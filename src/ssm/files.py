"""Folder-browser file operations, confined to the configured volumes.

Every path is walked one component at a time from the volume root with
``openat(O_NOFOLLOW | O_DIRECTORY)``. A symlink anywhere in the path is refused, so a
link can never lead outside its volume and there is no check-then-use race on the
path. Operations act on the final component itself (lstat semantics): deleting a
link removes the link, never its target.

Nothing is ever overwritten: renames use ``renameat2(RENAME_NOREPLACE)``. If the
filesystem or platform does not support that flag, a locked lstat-then-rename fallback
is used; its only remaining race is against another client (e.g. an SMB user) creating
the same name in the same instant.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import errno
import os
import secrets
import shutil
import stat
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

import anyio.to_thread

from ssm import validators as v

FORCE_RENAME_FALLBACK = False  # tests flip this to exercise the fallback path
FORCE_CROSS_DEVICE = False  # tests flip this to exercise copy-then-delete moves
COPY_TEMP_PREFIX = ".ssm-copy-"
MAX_QUERY_LEN = 100
RENAME_NOREPLACE = 1
_rename_lock = threading.Lock()
_last_mode = "unknown"


class FileOpError(Exception):
    """A refused or failed file operation; the message is safe to show the admin."""


@dataclass(frozen=True)
class Entry:
    name: str
    kind: str  # dir | file | link | other
    size: int
    mtime: float


def _load_renameat2() -> Callable[..., int] | None:
    if sys.platform != "linux":
        return None
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
        fn = libc.renameat2
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    return fn  # type: ignore[no-any-return, unused-ignore]


_renameat2 = _load_renameat2()


def last_rename_mode() -> str:
    return _last_mode


def rename_noreplace(src_dir: int, src: str, dst_dir: int, dst: str) -> None:
    """Rename without ever replacing an existing destination. Raises FileExistsError."""
    global _last_mode
    if _renameat2 is not None and not FORCE_RENAME_FALLBACK:
        rc = _renameat2(src_dir, os.fsencode(src), dst_dir, os.fsencode(dst), RENAME_NOREPLACE)
        if rc == 0:
            _last_mode = "native"
            return
        err = ctypes.get_errno()
        if err not in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
            raise OSError(err, os.strerror(err), dst)
    _last_mode = "fallback"
    with _rename_lock:
        try:
            os.lstat(dst, dir_fd=dst_dir)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(errno.EEXIST, "destination exists", dst)
        os.rename(src, dst, src_dir_fd=src_dir, dst_dir_fd=dst_dir)


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _copy_fd(src_fd: int, dst_fd: int) -> None:
    while True:
        chunk = os.read(src_fd, 1024 * 1024)
        if not chunk:
            return
        view = memoryview(chunk)
        while view:
            n = os.write(dst_fd, view)
            view = view[n:]


def _copy_file(src_dir: int, name: str, dst_dir: int, dst_name: str) -> None:
    """Copy one regular file (never a link) to a new file that must not exist yet."""
    src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=src_dir)
    try:
        st = os.fstat(src)
        if not stat.S_ISREG(st.st_mode):
            raise FileOpError(f"{name}: only regular files and folders can be copied")
        os.set_blocking(src, True)
        dst = os.open(
            dst_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o664,
            dir_fd=dst_dir,
        )
        try:
            _copy_fd(src, dst)
            os.fsync(dst)
            os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))
        finally:
            os.close(dst)
    finally:
        os.close(src)


def _copy_tree(src_dir: int, dst_dir: int) -> None:
    """Copy the contents of one open folder into another. Symlinks and special files
    are skipped, never followed."""
    with os.scandir(src_dir) as it:
        entries = list(it)
    for de in entries:
        st = de.stat(follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(de.name, 0o775, dir_fd=dst_dir)
            s = os.open(de.name, _DIR_FLAGS, dir_fd=src_dir)
            try:
                d = os.open(de.name, _DIR_FLAGS, dir_fd=dst_dir)
                try:
                    _copy_tree(s, d)
                finally:
                    os.close(d)
            finally:
                os.close(s)
        elif stat.S_ISREG(st.st_mode):
            _copy_file(src_dir, de.name, dst_dir, de.name)


def _suffixed(name: str, n: int) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        stem, dot, ext = name, "", ""
    tail = f" ({n}){dot}{ext}"
    budget = v.MAX_NAME_BYTES - len(tail.encode())
    stem = stem.encode()[:budget].decode("utf-8", "ignore")
    return stem + tail


def _entry(name: str, st: os.stat_result) -> Entry:
    if stat.S_ISLNK(st.st_mode):
        kind = "link"
    elif stat.S_ISDIR(st.st_mode):
        kind = "dir"
    elif stat.S_ISREG(st.st_mode):
        kind = "file"
    else:
        kind = "other"
    return Entry(name, kind, st.st_size, st.st_mtime)


class FileOps:
    def __init__(self, volumes: list[str], protected: Callable[[], list[str]]) -> None:
        self.volumes = [os.path.realpath(p) for p in volumes]
        self._protected = protected

    # --- path handling -----------------------------------------------------------------

    def split(self, path: str) -> tuple[str, list[str]]:
        """Return (volume root, components below it) for a lexical, normalised path."""
        if not isinstance(path, str) or not path.startswith("/"):
            raise FileOpError("path must be absolute")
        if v.has_control_chars(path):
            raise FileOpError("path contains control characters")
        if os.path.normpath(path) != path:
            raise FileOpError("path must be normalised")
        for root in self.volumes:
            if path == root:
                return root, []
            if path.startswith(root.rstrip("/") + "/"):
                parts = path[len(root.rstrip("/")) + 1 :].split("/")
                for p in parts:
                    try:
                        v.validate_filename(p)
                    except v.ValidationError as e:
                        raise FileOpError(str(e)) from e
                return root, parts
        raise FileOpError("path is not inside a configured volume")

    def _open_dir(self, root: str, parts: list[str]) -> int:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for p in parts:
                try:
                    nfd = os.open(p, _DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError as e:
                    raise FileOpError("folder not found") from e
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                        raise FileOpError("not a folder (symbolic links are not followed)") from e
                    raise FileOpError(f"cannot open folder: {e.strerror}") from e
                os.close(fd)
                fd = nfd
        except BaseException:
            os.close(fd)
            raise
        return fd

    def open_dir(self, path: str) -> int:
        root, parts = self.split(path)
        return self._open_dir(root, parts)

    def _parent(self, path: str) -> tuple[int, str, str]:
        """Open the parent folder; returns (parent fd, final name, volume root)."""
        root, parts = self.split(path)
        if not parts:
            raise FileOpError("this is a volume root; it cannot be changed")
        return self._open_dir(root, parts[:-1]), parts[-1], root

    # --- operations ----------------------------------------------------------------------

    def list_dir(self, path: str) -> list[Entry]:
        fd = self.open_dir(path)
        try:
            out = []
            with os.scandir(fd) as it:
                for de in it:
                    try:
                        st = de.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        kind = "link"
                    elif stat.S_ISDIR(st.st_mode):
                        kind = "dir"
                    elif stat.S_ISREG(st.st_mode):
                        kind = "file"
                    else:
                        kind = "other"
                    out.append(Entry(de.name, kind, st.st_size, st.st_mtime))
        finally:
            os.close(fd)
        out.sort(key=lambda e: (e.kind != "dir", e.name.lower()))
        return out

    def mkdir(self, parent: str, name: str) -> str:
        try:
            v.validate_filename(name)
        except v.ValidationError as e:
            raise FileOpError(str(e)) from e
        fd = self.open_dir(parent)
        try:
            os.mkdir(name, 0o775, dir_fd=fd)
        except FileExistsError as e:
            raise FileOpError("something with that name already exists") from e
        except OSError as e:
            raise FileOpError(f"cannot create folder: {e.strerror}") from e
        finally:
            os.close(fd)
        return parent.rstrip("/") + "/" + name

    def rename(self, path: str, new_name: str) -> str:
        try:
            v.validate_filename(new_name)
        except v.ValidationError as e:
            raise FileOpError(str(e)) from e
        self._check_not_protected(path, "rename")
        fd, old, _ = self._parent(path)
        try:
            if new_name == old:
                return path
            try:
                src_st = os.lstat(old, dir_fd=fd)
            except FileNotFoundError as e:
                raise FileOpError("not found") from e
            try:
                rename_noreplace(fd, old, fd, new_name)
            except FileExistsError as e:
                # Case-only rename on a case-insensitive filesystem (exFAT): the
                # "existing" destination is the source itself.
                try:
                    dst_st = os.lstat(new_name, dir_fd=fd)
                except FileNotFoundError:
                    raise FileOpError("something with that name already exists") from e
                if os.path.samestat(src_st, dst_st) and old.lower() == new_name.lower():
                    os.rename(old, new_name, src_dir_fd=fd, dst_dir_fd=fd)
                else:
                    raise FileOpError("something with that name already exists") from e
            except OSError as e:
                raise FileOpError(f"cannot rename: {e.strerror}") from e
        finally:
            os.close(fd)
        return os.path.dirname(path) + "/" + new_name

    def _check_not_protected(self, path: str, verb: str) -> None:
        for p in self._protected():
            if p == path or p.startswith(path.rstrip("/") + "/"):
                raise FileOpError(
                    f"cannot {verb}: this folder is (or contains) a shared folder; "
                    "remove the share first"
                )

    def delete(self, path: str, recursive: bool) -> None:
        self._check_not_protected(path, "delete")
        fd, name, _ = self._parent(path)
        try:
            try:
                st = os.lstat(name, dir_fd=fd)
            except FileNotFoundError as e:
                raise FileOpError("not found") from e
            try:
                if stat.S_ISDIR(st.st_mode):
                    if recursive:
                        shutil.rmtree(name, dir_fd=fd)
                    else:
                        os.rmdir(name, dir_fd=fd)
                else:
                    os.unlink(name, dir_fd=fd)
            except OSError as e:
                if e.errno == errno.ENOTEMPTY:
                    raise FileOpError("folder is not empty") from e
                raise FileOpError(f"cannot delete: {e.strerror}") from e
        finally:
            os.close(fd)

    # --- copy / move / search --------------------------------------------------------------

    def _check_not_into_itself(self, src: str, dest_dir: str) -> None:
        if dest_dir == src or dest_dir.startswith(src.rstrip("/") + "/"):
            raise FileOpError("a folder cannot be copied or moved into itself")

    def _place(self, dfd: int, tmp: str, name: str, suffix: bool) -> str:
        for i in range(1000 if suffix else 1):
            candidate = name if i == 0 else _suffixed(name, i)
            try:
                rename_noreplace(dfd, tmp, dfd, candidate)
            except FileExistsError:
                continue
            return candidate
        raise FileOpError(f"{name} already exists in the destination")

    def _copy_into(self, pfd: int, name: str, dfd: int, final: str, suffix: bool) -> str:
        """Copy pfd/name into dfd as a temp entry, then rename it into place."""
        st = os.lstat(name, dir_fd=pfd)
        if stat.S_ISLNK(st.st_mode):
            raise FileOpError(f"{name}: symbolic links are not copied")
        tmp = f"{COPY_TEMP_PREFIX}{secrets.token_hex(8)}"
        try:
            if stat.S_ISDIR(st.st_mode):
                os.mkdir(tmp, 0o775, dir_fd=dfd)
                s = os.open(name, _DIR_FLAGS, dir_fd=pfd)
                try:
                    d = os.open(tmp, _DIR_FLAGS, dir_fd=dfd)
                    try:
                        _copy_tree(s, d)
                    finally:
                        os.close(d)
                finally:
                    os.close(s)
            elif stat.S_ISREG(st.st_mode):
                _copy_file(pfd, name, dfd, tmp)
            else:
                raise FileOpError(f"{name}: only regular files and folders can be copied")
            placed = self._place(dfd, tmp, final, suffix)
            tmp = ""
            return placed
        except OSError as e:
            raise FileOpError(f"copy failed: {e.strerror}") from e
        finally:
            if tmp:
                self._remove_temp(dfd, tmp)

    @staticmethod
    def _remove_temp(dfd: int, tmp: str) -> None:
        try:
            st = os.lstat(tmp, dir_fd=dfd)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(tmp, dir_fd=dfd, ignore_errors=True)
        else:
            os.unlink(tmp, dir_fd=dfd)

    def copy(self, src: str, dest_dir: str) -> str:
        """Copy a file or folder into dest_dir; a name conflict gets "name (1)"."""
        self.split(dest_dir)
        self._check_not_into_itself(src, dest_dir)
        pfd, name, _ = self._parent(src)
        try:
            dfd = self.open_dir(dest_dir)
            try:
                placed = self._copy_into(pfd, name, dfd, name, suffix=True)
            finally:
                os.close(dfd)
        finally:
            os.close(pfd)
        return dest_dir.rstrip("/") + "/" + placed

    def move(self, src: str, dest_dir: str) -> str:
        """Move a file or folder into dest_dir. Never replaces anything; across
        filesystems the source is deleted only after a complete copy exists."""
        self.split(dest_dir)
        self._check_not_protected(src, "move")
        self._check_not_into_itself(src, dest_dir)
        if os.path.dirname(src) == dest_dir:
            raise FileOpError("it is already in this folder")
        pfd, name, _ = self._parent(src)
        try:
            dfd = self.open_dir(dest_dir)
            try:
                try:
                    os.lstat(name, dir_fd=pfd)
                except FileNotFoundError as e:
                    raise FileOpError("not found") from e
                same_dev = os.fstat(pfd).st_dev == os.fstat(dfd).st_dev
                if same_dev and not FORCE_CROSS_DEVICE:
                    try:
                        rename_noreplace(pfd, name, dfd, name)
                    except FileExistsError as e:
                        raise FileOpError(f"{name} already exists in the destination") from e
                    except OSError as e:
                        raise FileOpError(f"move failed: {e.strerror}") from e
                else:
                    try:
                        os.lstat(name, dir_fd=dfd)
                        raise FileOpError(f"{name} already exists in the destination")
                    except FileNotFoundError:
                        pass
                    self._copy_into(pfd, name, dfd, name, suffix=False)
                    st = os.lstat(name, dir_fd=pfd)
                    if stat.S_ISDIR(st.st_mode):
                        shutil.rmtree(name, dir_fd=pfd)
                    else:
                        os.unlink(name, dir_fd=pfd)
            finally:
                os.close(dfd)
        finally:
            os.close(pfd)
        return dest_dir.rstrip("/") + "/" + name

    def search(
        self,
        dir_path: str,
        query: str,
        show_hidden: bool,
        limit: int = 500,
        max_visited: int = 50_000,
        budget_s: float = 10.0,
    ) -> tuple[list[tuple[str, Entry]], bool]:
        """Case-insensitive name search below dir_path. Never follows symlinks."""
        if not isinstance(query, str) or not query or len(query) > MAX_QUERY_LEN:
            raise FileOpError(f"search text must be 1-{MAX_QUERY_LEN} characters")
        if v.has_control_chars(query):
            raise FileOpError("search text contains control characters")
        needle = query.casefold()
        fd = self.open_dir(dir_path)
        results: list[tuple[str, Entry]] = []
        visited = 0
        deadline = time.monotonic() + budget_s
        truncated = False
        try:
            for root, dirs, fnames, rfd in os.fwalk(".", dir_fd=fd, follow_symlinks=False):
                if not show_hidden:
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                dirs.sort()
                base = (
                    dir_path.rstrip("/") if root == "." else dir_path.rstrip("/") + "/" + root[2:]
                )
                for n in sorted(dirs + fnames):
                    visited += 1
                    if (not show_hidden and n.startswith(".")) or needle not in n.casefold():
                        continue
                    try:
                        st = os.lstat(n, dir_fd=rfd)
                    except OSError:
                        continue
                    results.append((base + "/" + n, _entry(n, st)))
                    if len(results) >= limit:
                        truncated = True
                        break
                if truncated or visited >= max_visited or time.monotonic() > deadline:
                    truncated = True
                    break
        finally:
            os.close(fd)
        return results, truncated

    def open_download(self, path: str) -> tuple[int, int, str]:
        """Open a regular file for reading. Returns (fd, size, name); caller closes fd."""
        pfd, name, _ = self._parent(path)
        try:
            try:
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=pfd
                )
            except FileNotFoundError as e:
                raise FileOpError("not found") from e
            except OSError as e:
                raise FileOpError("cannot open (symbolic links are not followed)") from e
        finally:
            os.close(pfd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise FileOpError("only regular files can be downloaded")
        os.set_blocking(fd, True)
        return fd, st.st_size, name

    async def upload(
        self, dir_path: str, raw_name: str, chunks: AsyncIterator[bytes], max_bytes: int
    ) -> str:
        try:
            name = v.sanitize_upload_filename(raw_name)
        except v.ValidationError as e:
            raise FileOpError(str(e)) from e
        dfd = self.open_dir(dir_path)
        tmp = f"{v.UPLOAD_TEMP_PREFIX}{secrets.token_hex(8)}.part"
        fd = -1
        done = False
        try:
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o664,
                dir_fd=dfd,
            )
            total = 0
            async for chunk in chunks:
                total += len(chunk)
                if total > max_bytes:
                    raise FileOpError("upload exceeds the size limit")
                view = memoryview(chunk)
                while view:
                    n = await anyio.to_thread.run_sync(os.write, fd, view)
                    view = view[n:]
            await anyio.to_thread.run_sync(os.fsync, fd)
            os.close(fd)
            fd = -1
            for i in range(1000):
                candidate = name if i == 0 else _suffixed(name, i)
                try:
                    rename_noreplace(dfd, tmp, dfd, candidate)
                except FileExistsError:
                    continue
                done = True
                return candidate
            raise FileOpError("too many files with that name")
        except ConnectionError:
            raise  # client went away; the temp file is removed below
        except OSError as e:
            raise FileOpError(f"upload failed: {e.strerror}") from e
        finally:
            if fd >= 0:
                os.close(fd)
            if not done:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp, dir_fd=dfd)
            os.close(dfd)
