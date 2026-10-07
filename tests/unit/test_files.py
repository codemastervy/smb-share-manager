"""Requirements 4 and 10: file operations never destroy a source, never follow links out,
never overwrite; uploads are streamed, size-limited, temp+rename, sanitised.

Runs on a tmpdir and, when SSM_TEST_EXFAT_DIR points at a mounted exFAT filesystem
(CI loop-mounts one), on exFAT as well.
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from ssm import files
from ssm.files import FileOpError, FileOps

ROOTS = ["tmp"]
if os.environ.get("SSM_TEST_EXFAT_DIR"):
    ROOTS.append("exfat")


@pytest.fixture(params=ROOTS)
def base(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    if request.param == "tmp":
        yield tmp_path
        return
    d = Path(os.environ["SSM_TEST_EXFAT_DIR"]) / f"t-{uuid.uuid4().hex[:8]}"
    d.mkdir()
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(params=["native", "fallback"])
def ops(request: pytest.FixtureRequest, base: Path, monkeypatch: pytest.MonkeyPatch) -> FileOps:
    if request.param == "fallback":
        monkeypatch.setattr(files, "FORCE_RENAME_FALLBACK", True)
    vol = base / "vol"
    (vol / "docs").mkdir(parents=True)
    (vol / "docs" / "a.txt").write_text("A")
    (vol / "docs" / "b.txt").write_text("B")
    (base / "outside").mkdir()
    (base / "outside" / "secret.txt").write_text("SECRET")
    return FileOps([str(vol)], protected=lambda: [str(vol / "shared")])


def vol_of(ops: FileOps) -> Path:
    return Path(ops.volumes[0])


def can_symlink(p: Path) -> bool:
    try:
        os.symlink("x", p / ".probe")
    except OSError:
        return False
    os.unlink(p / ".probe")
    return True


async def chunks(*parts: bytes):  # type: ignore[no-untyped-def]
    for p in parts:
        yield p


# --- containment -------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel", ["../outside", "docs/../../outside", "/etc", "relative", "docs/./a.txt", "docs//a.txt"]
)
def test_paths_outside_or_unnormalised_refused(ops: FileOps, rel: str) -> None:
    p = rel if rel.startswith("/") or rel == "relative" else f"{vol_of(ops)}/{rel}"
    with pytest.raises(FileOpError):
        ops.list_dir(p)


def test_prefix_sibling_refused(ops: FileOps) -> None:
    sib = Path(str(vol_of(ops)) + "2")
    sib.mkdir()
    with pytest.raises(FileOpError):
        ops.list_dir(str(sib))


def test_list_dir(ops: FileOps) -> None:
    entries = {e.name: e for e in ops.list_dir(str(vol_of(ops) / "docs"))}
    assert set(entries) == {"a.txt", "b.txt"}
    assert entries["a.txt"].kind == "file"
    assert entries["a.txt"].size == 1


def test_symlink_listed_not_followed(ops: FileOps, base: Path) -> None:
    v = vol_of(ops)
    if not can_symlink(v):
        pytest.skip("filesystem has no symlinks (e.g. exFAT)")
    os.symlink(base / "outside", v / "escape")
    os.symlink(base / "outside" / "secret.txt", v / "secret-link")
    os.symlink(v / "docs", v / "inner")
    kinds = {e.name: e.kind for e in ops.list_dir(str(v))}
    assert kinds["escape"] == "link" and kinds["inner"] == "link"
    for p in (v / "escape", v / "inner", v / "escape" / "secret.txt"):
        with pytest.raises(FileOpError):
            ops.list_dir(str(p))
    with pytest.raises(FileOpError):
        ops.open_download(str(v / "secret-link"))
    with pytest.raises(FileOpError):
        ops.open_download(str(v / "escape" / "secret.txt"))
    with pytest.raises(FileOpError):
        ops.mkdir(str(v / "escape"), "new")
    assert not (base / "outside" / "new").exists()


def test_delete_symlink_deletes_only_link(ops: FileOps, base: Path) -> None:
    v = vol_of(ops)
    if not can_symlink(v):
        pytest.skip("filesystem has no symlinks (e.g. exFAT)")
    os.symlink(base / "outside", v / "escape")
    ops.delete(str(v / "escape"), recursive=True)
    assert not os.path.lexists(v / "escape")
    assert (base / "outside" / "secret.txt").read_text() == "SECRET"


# --- mkdir / rename / delete --------------------------------------------------------


def test_mkdir(ops: FileOps) -> None:
    p = ops.mkdir(str(vol_of(ops) / "docs"), "New Folder")
    assert Path(p).is_dir()


def test_mkdir_existing_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.mkdir(str(vol_of(ops)), "docs")


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "x\ny", "x\x00"])
def test_mkdir_bad_names(ops: FileOps, bad: str) -> None:
    with pytest.raises(FileOpError):
        ops.mkdir(str(vol_of(ops)), bad)


def test_rename(ops: FileOps) -> None:
    v = vol_of(ops)
    new = ops.rename(str(v / "docs" / "a.txt"), "c.txt")
    assert Path(new).read_text() == "A"
    assert not (v / "docs" / "a.txt").exists()


def test_rename_never_overwrites(ops: FileOps) -> None:
    v = vol_of(ops)
    with pytest.raises(FileOpError):
        ops.rename(str(v / "docs" / "a.txt"), "b.txt")
    assert (v / "docs" / "a.txt").read_text() == "A"
    assert (v / "docs" / "b.txt").read_text() == "B"


def test_rename_dir_onto_existing_dir_refused(ops: FileOps) -> None:
    v = vol_of(ops)
    (v / "empty").mkdir()
    with pytest.raises(FileOpError):
        ops.rename(str(v / "docs"), "empty")
    assert (v / "docs" / "a.txt").exists()


def test_rename_case_only(ops: FileOps) -> None:
    # exFAT is case-insensitive: renaming a.txt -> A.txt must not be treated as a conflict
    # with itself, and must never lose the file.
    v = vol_of(ops)
    new = ops.rename(str(v / "docs" / "a.txt"), "A.txt")
    assert Path(new).read_text() == "A"


@pytest.mark.parametrize("bad", ["", "..", "x/y", "nl\n"])
def test_rename_bad_names(ops: FileOps, bad: str) -> None:
    with pytest.raises(FileOpError):
        ops.rename(str(vol_of(ops) / "docs" / "a.txt"), bad)


def test_rename_volume_root_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.rename(str(vol_of(ops)), "x")


def test_delete_file(ops: FileOps) -> None:
    v = vol_of(ops)
    ops.delete(str(v / "docs" / "a.txt"), recursive=False)
    assert not (v / "docs" / "a.txt").exists()


def test_delete_nonempty_dir_needs_recursive(ops: FileOps) -> None:
    v = vol_of(ops)
    with pytest.raises(FileOpError):
        ops.delete(str(v / "docs"), recursive=False)
    ops.delete(str(v / "docs"), recursive=True)
    assert not (v / "docs").exists()


def test_delete_volume_root_refused(ops: FileOps) -> None:
    v = vol_of(ops)
    with pytest.raises(FileOpError):
        ops.delete(str(v), recursive=True)
    assert (v / "docs" / "a.txt").exists()


def test_delete_shared_folder_or_parent_refused(ops: FileOps) -> None:
    v = vol_of(ops)
    (v / "shared" / "sub").mkdir(parents=True)
    with pytest.raises(FileOpError):
        ops.delete(str(v / "shared"), recursive=True)
    (v / "parent").mkdir()
    ops2 = FileOps([str(v)], protected=lambda: [str(v / "parent" / "inner")])
    (v / "parent" / "inner").mkdir()
    with pytest.raises(FileOpError):
        ops2.delete(str(v / "parent"), recursive=True)
    assert (v / "parent" / "inner").is_dir()


def test_delete_missing(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.delete(str(vol_of(ops) / "nope"), recursive=False)


# --- download ----------------------------------------------------------------------


def test_open_download(ops: FileOps) -> None:
    fd, size, name = ops.open_download(str(vol_of(ops) / "docs" / "a.txt"))
    try:
        assert os.read(fd, 10) == b"A"
        assert size == 1 and name == "a.txt"
    finally:
        os.close(fd)


def test_download_directory_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.open_download(str(vol_of(ops) / "docs"))


# --- upload (requirement 10) --------------------------------------------------------


@pytest.mark.anyio
async def test_upload_streams_and_renames(ops: FileOps) -> None:
    v = vol_of(ops)
    name = await ops.upload(str(v / "docs"), "new.bin", chunks(b"ab", b"cd"), max_bytes=10)
    assert name == "new.bin"
    assert (v / "docs" / "new.bin").read_bytes() == b"abcd"
    assert not [p for p in os.listdir(v / "docs") if p.startswith(".ssm-upload-")]


@pytest.mark.anyio
async def test_upload_never_overwrites_auto_suffix(ops: FileOps) -> None:
    v = vol_of(ops)
    n1 = await ops.upload(str(v / "docs"), "a.txt", chunks(b"new"), max_bytes=10)
    n2 = await ops.upload(str(v / "docs"), "a.txt", chunks(b"newer"), max_bytes=10)
    assert (n1, n2) == ("a (1).txt", "a (2).txt")
    assert (v / "docs" / "a.txt").read_text() == "A"
    assert (v / "docs" / "a (2).txt").read_text() == "newer"


@pytest.mark.anyio
async def test_upload_size_limit_leaves_nothing(ops: FileOps) -> None:
    v = vol_of(ops)
    before = sorted(os.listdir(v / "docs"))
    with pytest.raises(FileOpError, match="limit"):
        await ops.upload(str(v / "docs"), "big.bin", chunks(b"x" * 6, b"x" * 6), max_bytes=10)
    assert sorted(os.listdir(v / "docs")) == before


@pytest.mark.anyio
async def test_upload_client_abort_leaves_nothing(ops: FileOps) -> None:
    v = vol_of(ops)
    before = sorted(os.listdir(v / "docs"))

    async def broken():  # type: ignore[no-untyped-def]
        yield b"partial"
        raise ConnectionResetError

    with pytest.raises(ConnectionResetError):
        await ops.upload(str(v / "docs"), "x.bin", broken(), max_bytes=100)
    assert sorted(os.listdir(v / "docs")) == before


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("raw", "expected"),
    [("../../evil.sh", "evil.sh"), ("C:\\x\\y.txt", "y.txt"), ("ok\n.txt", "ok.txt")],
)
async def test_upload_sanitises_name(ops: FileOps, raw: str, expected: str) -> None:
    v = vol_of(ops)
    name = await ops.upload(str(v / "docs"), raw, chunks(b"x"), max_bytes=10)
    assert name == expected
    assert (v / "docs" / expected).exists()


@pytest.mark.anyio
async def test_upload_into_symlinked_dir_refused(ops: FileOps, base: Path) -> None:
    v = vol_of(ops)
    if not can_symlink(v):
        pytest.skip("filesystem has no symlinks (e.g. exFAT)")
    os.symlink(base / "outside", v / "escape")
    with pytest.raises(FileOpError):
        await ops.upload(str(v / "escape"), "x.txt", chunks(b"x"), max_bytes=10)
    assert not (base / "outside" / "x.txt").exists()


# --- rename primitive ---------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 is Linux-only")
def test_renameat2_available_or_reported(base: Path) -> None:
    # Records which path the filesystem takes; both are acceptable, neither may overwrite.
    d = base / "r"
    d.mkdir()
    (d / "x").write_text("x")
    (d / "y").write_text("y")
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            files.rename_noreplace(fd, "x", fd, "y")
        files.rename_noreplace(fd, "x", fd, "z")
    finally:
        os.close(fd)
    assert (d / "y").read_text() == "y" and (d / "z").read_text() == "x"
    print("renameat2 native:", files.last_rename_mode())


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
