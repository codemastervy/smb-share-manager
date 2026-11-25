"""WsgiDAV provider over the exposed shares.

URL layout: "/" lists the shares the user may use; "/<share>/<path>" maps into the
share's folder. Every operation walks the path from the share root one component at a
time with openat(O_NOFOLLOW | O_DIRECTORY) and acts on the final component with lstat
semantics, the same way ssm.files does for the admin folder browser. Symlinks, devices,
FIFOs, internal temp files and names that fail validation are invisible and unreachable.

Overwrite rule (WebDAV only):
- PUT may replace an existing regular file (read-write only): the body goes to a temp
  file in the same folder, which is then renamed over the old file atomically.
- COPY/MOVE replace something only with an explicit "Overwrite: T" (the guard turns a
  missing header into "F"), and then only a regular file by a regular file. A folder,
  share root or protected folder is never replaced, and nothing is copied or moved
  onto or into itself. A MOVE across filesystems deletes the source only after the
  complete copy is in place.

Authorisation is checked here as well as in the guard: every write needs "rw" on the
share it touches.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import shutil
import stat
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from wsgidav import util
from wsgidav.dav_error import (
    HTTP_BAD_REQUEST,
    HTTP_CONFLICT,
    HTTP_FORBIDDEN,
    HTTP_INSUFFICIENT_STORAGE,
    HTTP_METHOD_NOT_ALLOWED,
    HTTP_NOT_FOUND,
    HTTP_PRECONDITION_FAILED,
    HTTP_REQUEST_ENTITY_TOO_LARGE,
    DAVError,
)
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider
from wsgidav.lock_man.lock_storage import LockStorageDict
from wsgidav.prop_man.property_manager import PropertyManager

from ssm import audit
from ssm import validators as v
from ssm.dav.acl import AclSnapshot, DavShare
from ssm.files import _DIR_FLAGS, COPY_TEMP_PREFIX, _copy_file, _copy_tree, rename_noreplace

FORCE_CROSS_DEVICE = False  # tests flip this to exercise copy-then-delete moves
MAX_LOCKS_PER_USER = 200
MAX_LOCK_TIMEOUT = 3600
MAX_DEAD_PROPS = 20_000
TEMP_PREFIXES = (v.UPLOAD_TEMP_PREFIX, COPY_TEMP_PREFIX)
CTX_KEY = "ssm.dav.ctx"
_ROOT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class RequestCtx:
    user: str
    snap: AclSnapshot
    max_upload: int


class _Missing(Exception):
    pass


def split_path(path: str) -> list[str]:
    """Components of a provider path; refuses anything that is not a clean name."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise DAVError(HTTP_BAD_REQUEST)
    body = path[1:]
    if body.endswith("/"):
        body = body[:-1]
    if not body:
        return []
    parts = body.split("/")
    for p in parts:
        try:
            v.validate_filename(p)
        except v.ValidationError as e:
            raise DAVError(HTTP_BAD_REQUEST) from e
    return parts


def _walk(root: str, parts: list[str]) -> int:
    """Open root/parts... as a folder fd without following any symlink."""
    try:
        fd = os.open(root, _ROOT_FLAGS)
    except OSError as e:
        raise _Missing from e
    try:
        for p in parts:
            try:
                nfd = os.open(p, _DIR_FLAGS, dir_fd=fd)
            except OSError as e:
                raise _Missing from e
            os.close(fd)
            fd = nfd
    except BaseException:
        os.close(fd)
        raise
    return fd


def _lstat(name: str, dfd: int) -> os.stat_result | None:
    try:
        return os.lstat(name, dir_fd=dfd)
    except FileNotFoundError:
        return None


def _visible_name(name: str) -> bool:
    if name.startswith(TEMP_PREFIXES):
        return False
    try:
        v.validate_filename(name)
    except v.ValidationError:
        return False
    return True


def _remove_tree_or_file(name: str, dfd: int) -> None:
    st = _lstat(name, dfd)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(name, dir_fd=dfd)
    else:
        os.unlink(name, dir_fd=dfd)


def _oserror(e: OSError) -> DAVError:
    """Map an OSError without exposing paths or system messages."""
    if e.errno in (errno.ENOSPC, errno.EDQUOT):
        return DAVError(HTTP_INSUFFICIENT_STORAGE)
    if e.errno == errno.ENOENT:
        return DAVError(HTTP_CONFLICT)
    return DAVError(HTTP_FORBIDDEN)


class _Node:
    """What every share resource knows: the user's context, its share and location."""

    ctx: RequestCtx
    share: DavShare
    access: str
    rel: list[str]
    real: str

    def _init_node(self, ctx: RequestCtx, share: DavShare, access: str, rel: list[str]) -> None:
        self.ctx, self.share, self.access, self.rel = ctx, share, access, rel
        self.real = share.path if not rel else share.path.rstrip("/") + "/" + "/".join(rel)

    def _require_rw(self) -> None:
        if self.access != "rw":
            raise DAVError(HTTP_FORBIDDEN)

    def _protected(self) -> bool:
        """Share roots, and folders that are (or contain) any registry share."""
        if not self.rel:
            return True
        prefix = self.real.rstrip("/") + "/"
        return any(p == self.real or p.startswith(prefix) for p in self.ctx.snap.share_paths)

    def _parent_fd(self) -> tuple[int, str]:
        if not self.rel:
            raise DAVError(HTTP_FORBIDDEN)
        try:
            return _walk(self.share.path, self.rel[:-1]), self.rel[-1]
        except _Missing as e:
            raise DAVError(HTTP_CONFLICT) from e


class RootCollection(DAVCollection):  # type: ignore[misc]
    """'/': the shares this user may use. Read-only, not lockable."""

    def __init__(self, path: str, environ: dict[str, Any]) -> None:
        super().__init__(path, environ)
        self.ctx: RequestCtx = environ[CTX_KEY]

    def get_member_names(self) -> list[str]:
        return [s.name for s in self.ctx.snap.visible(self.ctx.user)]

    def get_member(self, name: str) -> Any:
        return self.provider.get_resource_inst(util.join_uri("/", name), self.environ)

    def get_display_name(self) -> str:
        return ""

    def prevent_locking(self) -> bool:
        return True

    def create_empty_resource(self, name: str) -> Any:
        raise DAVError(HTTP_FORBIDDEN)

    def create_collection(self, name: str) -> Any:
        raise DAVError(HTTP_FORBIDDEN)

    def delete(self) -> None:
        raise DAVError(HTTP_FORBIDDEN)

    def handle_delete(self) -> bool:
        raise DAVError(HTTP_FORBIDDEN)

    def handle_copy(self, dest_path: str, *, depth_infinity: bool) -> bool:
        raise DAVError(HTTP_FORBIDDEN)

    def handle_move(self, dest_path: str) -> bool:
        raise DAVError(HTTP_FORBIDDEN)

    def set_property_value(self, name: str, value: Any, dry_run: bool = False) -> None:
        raise DAVError(HTTP_FORBIDDEN)


class DirCollection(_Node, DAVCollection):  # type: ignore[misc]
    def __init__(
        self,
        path: str,
        environ: dict[str, Any],
        share: DavShare,
        access: str,
        rel: list[str],
        st: os.stat_result,
    ) -> None:
        DAVCollection.__init__(self, path, environ)
        self._init_node(environ[CTX_KEY], share, access, rel)
        self.st = st

    def _fd(self) -> int:
        try:
            return _walk(self.share.path, self.rel)
        except _Missing as e:
            raise DAVError(HTTP_NOT_FOUND) from e

    def get_member_names(self) -> list[str]:
        fd = self._fd()
        out: list[str] = []
        try:
            with os.scandir(fd) as it:
                for de in it:
                    if not _visible_name(de.name):
                        continue
                    try:
                        st = de.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode):
                        out.append(de.name)
        finally:
            os.close(fd)
        return sorted(out)

    def get_member(self, name: str) -> Any:
        return self.provider.get_resource_inst(util.join_uri(self.path, name), self.environ)

    def get_display_name(self) -> str:
        return self.share.name if not self.rel else self.rel[-1]

    def get_creation_date(self) -> float:
        return self.st.st_ctime

    def get_last_modified(self) -> float:
        return self.st.st_mtime

    def _vfs(self) -> os.statvfs_result | None:
        try:
            fd = self._fd()
        except DAVError:
            return None
        try:
            return os.fstatvfs(fd)
        except OSError:
            return None
        finally:
            os.close(fd)

    def get_used_bytes(self) -> int | None:
        s = self._vfs()
        return None if s is None else (s.f_blocks - s.f_bfree) * s.f_frsize

    def get_available_bytes(self) -> int | None:
        s = self._vfs()
        return None if s is None else s.f_bavail * s.f_frsize

    def prevent_locking(self) -> bool:
        return self.access != "rw"

    def _check_new_name(self, name: str) -> None:
        try:
            v.validate_filename(name)
        except v.ValidationError as e:
            raise DAVError(HTTP_BAD_REQUEST) from e
        if name.startswith(TEMP_PREFIXES):
            raise DAVError(HTTP_FORBIDDEN)

    def create_empty_resource(self, name: str) -> Any:
        self._require_rw()
        self._check_new_name(name)
        path = util.join_uri(self.path, name)
        if self.environ.get("REQUEST_METHOD") != "LOCK":
            # PUT: nothing is created until the body is complete (see FileResource).
            return FileResource(path, self.environ, self.share, self.access, [*self.rel, name])
        fd = self._fd()
        try:
            nfd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o664,
                dir_fd=fd,
            )
            os.close(nfd)
        except FileExistsError as e:
            raise DAVError(HTTP_METHOD_NOT_ALLOWED) from e
        except OSError as e:
            raise _oserror(e) from e
        finally:
            os.close(fd)
        audit.event("dav_create", user=self.ctx.user, share=self.share.name, path=path)
        return self.provider.get_resource_inst(path, self.environ)

    def create_collection(self, name: str) -> None:
        self._require_rw()
        self._check_new_name(name)
        fd = self._fd()
        try:
            os.mkdir(name, 0o775, dir_fd=fd)
        except FileExistsError as e:
            raise DAVError(HTTP_METHOD_NOT_ALLOWED) from e
        except OSError as e:
            raise _oserror(e) from e
        finally:
            os.close(fd)
        audit.event(
            "dav_mkcol",
            user=self.ctx.user,
            share=self.share.name,
            path=util.join_uri(self.path, name),
        )

    def handle_delete(self) -> bool:
        # Checked before WsgiDAV starts deleting members bottom-up, so nothing inside a
        # protected folder is removed either.
        self._require_rw()
        if self._protected():
            raise DAVError(HTTP_FORBIDDEN)
        return False

    def delete(self) -> None:
        self._require_rw()
        if self._protected():
            raise DAVError(HTTP_FORBIDDEN)
        pfd, name = self._parent_fd()
        try:
            st = _lstat(name, pfd)
            if st is None or not stat.S_ISDIR(st.st_mode):
                raise DAVError(HTTP_NOT_FOUND)
            os.rmdir(name, dir_fd=pfd)
        except OSError as e:
            # ENOTEMPTY: hidden entries (links, temp files) that WebDAV can't see.
            raise DAVError(HTTP_FORBIDDEN) from e
        finally:
            os.close(pfd)
        self.remove_all_properties(recursive=True)
        self.remove_all_locks(recursive=True)
        audit.event("dav_delete", user=self.ctx.user, share=self.share.name, path=self.path)

    def handle_copy(self, dest_path: str, *, depth_infinity: bool) -> bool:
        return transfer(self, dest_path, is_move=False, depth_infinity=depth_infinity)

    def handle_move(self, dest_path: str) -> bool:
        return transfer(self, dest_path, is_move=True, depth_infinity=True)

    def set_property_value(self, name: str, value: Any, dry_run: bool = False) -> None:
        self._require_rw()
        super().set_property_value(name, value, dry_run=dry_run)


class _UploadWriter:
    """File object handed to WsgiDAV's PUT loop: counts bytes and enforces the limit."""

    def __init__(self, fd: int, limit: int) -> None:
        self.fd = fd
        self.limit = limit
        self.total = 0

    def write(self, data: bytes) -> int:
        self.total += len(data)
        if self.total > self.limit:
            raise DAVError(HTTP_REQUEST_ENTITY_TOO_LARGE)
        view = memoryview(data)
        while view:
            n = os.write(self.fd, view)
            view = view[n:]
        return len(data)

    def close(self) -> None:
        pass  # closed by FileResource.end_write after fsync


class FileResource(_Node, DAVNonCollection):  # type: ignore[misc]
    def __init__(
        self,
        path: str,
        environ: dict[str, Any],
        share: DavShare,
        access: str,
        rel: list[str],
        st: os.stat_result | None = None,
    ) -> None:
        DAVNonCollection.__init__(self, path, environ)
        self._init_node(environ[CTX_KEY], share, access, rel)
        self.st = st
        self._pfd = -1
        self._tmp = ""
        self._writer: _UploadWriter | None = None

    def get_content_length(self) -> int:
        return self.st.st_size if self.st else 0

    def get_content_type(self) -> str:
        return "application/octet-stream"

    def get_creation_date(self) -> float | None:
        return self.st.st_ctime if self.st else None

    def get_last_modified(self) -> float | None:
        return self.st.st_mtime if self.st else None

    def get_etag(self) -> str | None:
        if self.st is None:
            return None
        return f"{self.st.st_ino:x}-{self.st.st_mtime_ns:x}-{self.st.st_size:x}"

    def support_etag(self) -> bool:
        return True

    def support_ranges(self) -> bool:
        return True

    def prevent_locking(self) -> bool:
        return self.access != "rw"

    def get_content(self) -> Any:
        pfd, name = self._parent_fd()
        try:
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=pfd
            )
        except OSError as e:
            raise DAVError(HTTP_NOT_FOUND) from e
        finally:
            os.close(pfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise DAVError(HTTP_NOT_FOUND)
            os.set_blocking(fd, True)
        except BaseException:
            os.close(fd)
            raise
        return os.fdopen(fd, "rb")

    def begin_write(self, *, content_type: str | None = None) -> _UploadWriter:
        self._require_rw()
        if self.rel[-1].startswith(TEMP_PREFIXES):
            raise DAVError(HTTP_FORBIDDEN)
        pfd, _ = self._parent_fd()
        tmp = f"{v.UPLOAD_TEMP_PREFIX}{secrets.token_hex(8)}.part"
        try:
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o664,
                dir_fd=pfd,
            )
        except OSError as e:
            os.close(pfd)
            raise _oserror(e) from e
        self._pfd, self._tmp = pfd, tmp
        self._writer = _UploadWriter(fd, self.ctx.max_upload)
        return self._writer

    def end_write(self, *, with_errors: bool) -> None:
        w, pfd, tmp, name = self._writer, self._pfd, self._tmp, self.rel[-1]
        if w is None:
            return
        self._writer, self._pfd, self._tmp = None, -1, ""
        placed = False
        replaced = False
        try:
            if with_errors:
                return
            os.fsync(w.fd)
            os.close(w.fd)
            w.fd = -1
            target = _lstat(name, pfd)
            if target is None:
                try:
                    rename_noreplace(pfd, tmp, pfd, name)
                    placed = True
                except FileExistsError:
                    target = _lstat(name, pfd)
            if not placed:
                if target is None or not stat.S_ISREG(target.st_mode):
                    raise DAVError(HTTP_CONFLICT)
                os.rename(tmp, name, src_dir_fd=pfd, dst_dir_fd=pfd)  # atomic replace
                placed = replaced = True
            self.st = _lstat(name, pfd)
        except OSError as e:
            raise _oserror(e) from e
        finally:
            if w.fd >= 0:
                os.close(w.fd)
            if not placed:
                with contextlib.suppress(OSError):
                    os.unlink(tmp, dir_fd=pfd)
            os.close(pfd)
        audit.event(
            "dav_put",
            user=self.ctx.user,
            share=self.share.name,
            path=self.path,
            size=w.total,
            replaced=replaced,
        )

    def delete(self) -> None:
        self._require_rw()
        pfd, name = self._parent_fd()
        try:
            st = _lstat(name, pfd)
            if st is None or not stat.S_ISREG(st.st_mode):
                raise DAVError(HTTP_NOT_FOUND)
            os.unlink(name, dir_fd=pfd)
        except OSError as e:
            raise _oserror(e) from e
        finally:
            os.close(pfd)
        self.remove_all_properties(recursive=True)
        self.remove_all_locks(recursive=True)
        audit.event("dav_delete", user=self.ctx.user, share=self.share.name, path=self.path)

    def handle_copy(self, dest_path: str, *, depth_infinity: bool) -> bool:
        return transfer(self, dest_path, is_move=False, depth_infinity=depth_infinity)

    def handle_move(self, dest_path: str) -> bool:
        return transfer(self, dest_path, is_move=True, depth_infinity=True)

    def set_property_value(self, name: str, value: Any, dry_run: bool = False) -> None:
        self._require_rw()
        super().set_property_value(name, value, dry_run=dry_run)


def transfer(src: Any, dest_path: str, *, is_move: bool, depth_infinity: bool) -> bool:
    """COPY or MOVE handled natively (WsgiDAV never deletes a destination itself)."""
    ctx: RequestCtx = src.ctx
    if is_move:
        src._require_rw()
    if not src.rel or (is_move and src._protected()):
        raise DAVError(HTTP_FORBIDDEN)
    dparts = split_path(dest_path)
    if len(dparts) < 2:
        raise DAVError(HTTP_FORBIDDEN)
    hit = ctx.snap.share_for(ctx.user, dparts[0])
    if hit is None:
        raise DAVError(HTTP_NOT_FOUND)
    dshare, daccess = hit
    if daccess != "rw":
        raise DAVError(HTTP_FORBIDDEN)
    drel = dparts[1:]
    dname = drel[-1]
    if dname.startswith(TEMP_PREFIXES):
        raise DAVError(HTTP_FORBIDDEN)
    dreal = dshare.path.rstrip("/") + "/" + "/".join(drel)
    if dreal == src.real or dreal.startswith(src.real.rstrip("/") + "/"):
        raise DAVError(HTTP_FORBIDDEN)
    overwrite = src.environ.get("HTTP_OVERWRITE", "F") == "T"

    pfd, sname = src._parent_fd()
    try:
        try:
            dfd = _walk(dshare.path, drel[:-1])
        except _Missing as e:
            raise DAVError(HTTP_CONFLICT) from e
        try:
            replaced = _transfer_fds(pfd, sname, dfd, dname, is_move, depth_infinity, overwrite)
        except OSError as e:
            raise _oserror(e) from e
        finally:
            os.close(dfd)
    finally:
        os.close(pfd)

    provider = src.provider
    pm = provider.prop_manager
    src_ref = src.get_ref_url()
    dest_ref = quote(provider.share_path + dest_path)
    if pm is not None:
        if replaced:
            pm.remove_properties(dest_ref)
        if is_move:
            pm.move_properties(src_ref, dest_ref, with_children=True)
        else:
            pm.copy_properties(src_ref, dest_ref)
    if is_move:
        src.remove_all_locks(recursive=True)
    audit.event(
        "dav_move" if is_move else "dav_copy",
        user=ctx.user,
        share=src.share.name,
        path=src.path,
        dest_share=dshare.name,
        dest=dest_path,
        replaced=replaced,
    )
    return True


def _transfer_fds(
    pfd: int, sname: str, dfd: int, dname: str, is_move: bool, deep: bool, overwrite: bool
) -> bool:
    """Returns True if an existing destination file was replaced."""
    sst = _lstat(sname, pfd)
    if sst is None:
        raise DAVError(HTTP_NOT_FOUND)
    is_dir = stat.S_ISDIR(sst.st_mode)
    if not is_dir and not stat.S_ISREG(sst.st_mode):
        raise DAVError(HTTP_FORBIDDEN)
    dst = _lstat(dname, dfd)
    if dst is not None:
        if not overwrite:
            raise DAVError(HTTP_PRECONDITION_FAILED)
        if is_dir or not stat.S_ISREG(dst.st_mode) or os.path.samestat(sst, dst):
            raise DAVError(HTTP_FORBIDDEN)  # only a file may replace a file

    same_dev = not FORCE_CROSS_DEVICE and os.fstat(pfd).st_dev == os.fstat(dfd).st_dev
    if is_move and same_dev:
        if dst is not None:
            os.rename(sname, dname, src_dir_fd=pfd, dst_dir_fd=dfd)
        else:
            try:
                rename_noreplace(pfd, sname, dfd, dname)
            except FileExistsError as e:
                raise DAVError(HTTP_PRECONDITION_FAILED) from e
        return dst is not None

    tmp = f"{COPY_TEMP_PREFIX}{secrets.token_hex(8)}"
    try:
        if is_dir:
            os.mkdir(tmp, 0o775, dir_fd=dfd)
            if deep:
                s = os.open(sname, _DIR_FLAGS, dir_fd=pfd)
                try:
                    d = os.open(tmp, _DIR_FLAGS, dir_fd=dfd)
                    try:
                        _copy_tree(s, d)
                    finally:
                        os.close(d)
                finally:
                    os.close(s)
        else:
            _copy_file(pfd, sname, dfd, tmp)
        if dst is not None:
            now = _lstat(dname, dfd)
            if now is None or not stat.S_ISREG(now.st_mode):
                raise DAVError(HTTP_CONFLICT)
            os.rename(tmp, dname, src_dir_fd=dfd, dst_dir_fd=dfd)
        else:
            try:
                rename_noreplace(dfd, tmp, dfd, dname)
            except FileExistsError as e:
                raise DAVError(HTTP_PRECONDITION_FAILED) from e
        tmp = ""
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                _remove_tree_or_file(tmp, dfd)
    if is_move:
        # The complete copy is in place; only now remove the source (if unchanged).
        cur = _lstat(sname, pfd)
        if cur is not None and os.path.samestat(cur, sst):
            _remove_tree_or_file(sname, pfd)
    return dst is not None


class ShareProvider(DAVProvider):  # type: ignore[misc]
    def get_resource_inst(self, path: str, environ: dict[str, Any]) -> Any:
        ctx: RequestCtx = environ[CTX_KEY]
        parts = split_path(path)
        if not parts:
            return RootCollection("/", environ)
        hit = ctx.snap.share_for(ctx.user, parts[0])
        if hit is None:
            return None
        share, access = hit
        rel = parts[1:]
        if any(p.startswith(TEMP_PREFIXES) for p in rel):
            return None
        try:
            if not rel:
                fd = _walk(share.path, [])
                try:
                    st = os.fstat(fd)
                finally:
                    os.close(fd)
            else:
                pfd = _walk(share.path, rel[:-1])
                try:
                    found = _lstat(rel[-1], pfd)
                finally:
                    os.close(pfd)
                if found is None:
                    return None
                st = found
        except (_Missing, OSError):
            return None
        if stat.S_ISDIR(st.st_mode):
            return DirCollection(path, environ, share, access, rel, st)
        if stat.S_ISREG(st.st_mode):
            return FileResource(path, environ, share, access, rel, st)
        return None  # symlinks, devices, FIFOs, sockets


class BoundedLockStorage(LockStorageDict):  # type: ignore[misc]
    """In-memory locks with a 1-hour timeout cap and a per-user count limit."""

    def _clamp(self, timeout: Any) -> float:
        try:
            t = float(timeout)
        except (TypeError, ValueError):
            t = MAX_LOCK_TIMEOUT
        return MAX_LOCK_TIMEOUT if t < 0 or t > MAX_LOCK_TIMEOUT else t

    def create(self, path: str, lock: dict[str, Any]) -> Any:
        lock["timeout"] = self._clamp(lock.get("timeout"))
        principal = lock.get("principal")
        self._lock.acquire_read()
        try:
            count = sum(
                1
                for k, val in self._dict.items()
                if not str(k).startswith("URL2TOKEN:")
                and isinstance(val, dict)
                and val.get("principal") == principal
            )
        finally:
            self._lock.release()
        if count >= MAX_LOCKS_PER_USER:
            raise DAVError(HTTP_INSUFFICIENT_STORAGE)
        return super().create(path, lock)

    def refresh(self, token: str, *, timeout: Any) -> Any:
        return super().refresh(token, timeout=self._clamp(timeout))

    def drop_principals(self, keep: set[str]) -> None:
        """Release every lock whose owner is no longer allowed in."""
        self._lock.acquire_read()
        try:
            doomed = [
                k
                for k, val in self._dict.items()
                if not str(k).startswith("URL2TOKEN:")
                and isinstance(val, dict)
                and val.get("principal") not in keep
            ]
        finally:
            self._lock.release()
        for token in doomed:
            self.delete(token)


class BoundedPropertyManager(PropertyManager):  # type: ignore[misc]
    """In-memory dead properties (Finder needs PROPPATCH to succeed), with a global cap."""

    def write_property(
        self,
        norm_url: str,
        name: str,
        property_value: Any,
        dry_run: bool = False,
        environ: Any = None,
    ) -> None:
        if not dry_run:
            total = sum(len(d) for d in self._dict.values()) if self._loaded else 0
            if total >= MAX_DEAD_PROPS:
                raise DAVError(HTTP_INSUFFICIENT_STORAGE)
        super().write_property(norm_url, name, property_value, dry_run=dry_run, environ=environ)
