"""Requirement 4 for the copy/move/search operations kept from nas-dashboard: never
overwrite, never destroy a source, never follow a symlink, stay inside the volumes.
Runs on tmp and (in CI) on a loop-mounted exFAT filesystem."""

from __future__ import annotations

import os
import shutil
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
    d = Path(os.environ["SSM_TEST_EXFAT_DIR"]) / f"c-{uuid.uuid4().hex[:8]}"
    d.mkdir()
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(params=["native", "fallback"])
def ops(request: pytest.FixtureRequest, base: Path, monkeypatch: pytest.MonkeyPatch) -> FileOps:
    if request.param == "fallback":
        monkeypatch.setattr(files, "FORCE_RENAME_FALLBACK", True)
    v1 = base / "vol1"
    v2 = base / "vol2"
    (v1 / "docs" / "sub").mkdir(parents=True)
    (v1 / "docs" / "a.txt").write_text("A")
    (v1 / "docs" / "sub" / "deep.txt").write_text("DEEP")
    (v1 / "dest").mkdir()
    v2.mkdir()
    (base / "outside").mkdir()
    (base / "outside" / "secret.txt").write_text("SECRET")
    return FileOps([str(v1), str(v2)], protected=lambda: [str(v1 / "shared")])


def v1(ops: FileOps) -> Path:
    return Path(ops.volumes[0])


def v2(ops: FileOps) -> Path:
    return Path(ops.volumes[1])


def can_symlink(p: Path) -> bool:
    try:
        os.symlink("x", p / ".probe")
    except OSError:
        return False
    os.unlink(p / ".probe")
    return True


def tree(p: Path) -> dict[str, str]:
    out = {}
    for root, _dirs, fnames in os.walk(p):
        for f in fnames:
            fp = Path(root) / f
            out[str(fp.relative_to(p))] = fp.read_text()
    return out


# --- copy ---------------------------------------------------------------------------------


def test_copy_file(ops: FileOps) -> None:
    out = ops.copy(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "dest"))
    assert Path(out).read_text() == "A"
    assert (v1(ops) / "docs" / "a.txt").read_text() == "A"


def test_copy_never_overwrites_auto_suffix(ops: FileOps) -> None:
    (v1(ops) / "dest" / "a.txt").write_text("EXISTING")
    out = ops.copy(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "dest"))
    assert Path(out).name == "a (1).txt"
    assert (v1(ops) / "dest" / "a.txt").read_text() == "EXISTING"


def test_copy_into_same_folder_duplicates(ops: FileOps) -> None:
    out = ops.copy(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "docs"))
    assert Path(out).name == "a (1).txt"


def test_copy_directory_tree(ops: FileOps) -> None:
    out = ops.copy(str(v1(ops) / "docs"), str(v2(ops)))
    assert tree(Path(out)) == tree(v1(ops) / "docs")
    assert tree(v1(ops) / "docs") == {"a.txt": "A", "sub/deep.txt": "DEEP"}


def test_copy_dir_into_itself_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.copy(str(v1(ops) / "docs"), str(v1(ops) / "docs" / "sub"))
    with pytest.raises(FileOpError):
        ops.copy(str(v1(ops) / "docs"), str(v1(ops) / "docs"))


def test_copy_leaves_no_temp_on_failure(ops: FileOps, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "_copy_fd", boom)
    with pytest.raises(FileOpError):
        ops.copy(str(v1(ops) / "docs"), str(v2(ops)))
    assert list(v2(ops).iterdir()) == []


def test_copy_symlinks_not_followed(ops: FileOps, base: Path) -> None:
    v = v1(ops)
    if not can_symlink(v):
        pytest.skip("filesystem has no symlinks (e.g. exFAT)")
    os.symlink(base / "outside", v / "docs" / "escape")
    os.symlink(base / "outside" / "secret.txt", v / "docs" / "secret-link")
    with pytest.raises(FileOpError):
        ops.copy(str(v / "docs" / "secret-link"), str(v / "dest"))
    out = Path(ops.copy(str(v / "docs"), str(v / "dest")))
    copied = tree(out)
    assert "SECRET" not in copied.values()
    assert not (out / "escape").exists() or (out / "escape").is_symlink() is False


def test_copy_outside_volumes_refused(ops: FileOps, base: Path) -> None:
    with pytest.raises(FileOpError):
        ops.copy(str(base / "outside" / "secret.txt"), str(v1(ops) / "dest"))
    with pytest.raises(FileOpError):
        ops.copy(str(v1(ops) / "docs" / "a.txt"), str(base / "outside"))


def test_copy_volume_root_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.copy(str(v1(ops)), str(v2(ops)))


# --- move ---------------------------------------------------------------------------------


def test_move_same_volume(ops: FileOps) -> None:
    out = ops.move(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "dest"))
    assert Path(out).read_text() == "A"
    assert not (v1(ops) / "docs" / "a.txt").exists()


def test_move_conflict_refused_source_kept(ops: FileOps) -> None:
    (v1(ops) / "dest" / "a.txt").write_text("EXISTING")
    with pytest.raises(FileOpError, match="exists"):
        ops.move(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "dest"))
    assert (v1(ops) / "docs" / "a.txt").read_text() == "A"
    assert (v1(ops) / "dest" / "a.txt").read_text() == "EXISTING"


def test_move_dir_into_itself_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.move(str(v1(ops) / "docs"), str(v1(ops) / "docs" / "sub"))
    assert (v1(ops) / "docs" / "sub" / "deep.txt").exists()


def test_move_to_same_folder_is_noop_error(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.move(str(v1(ops) / "docs" / "a.txt"), str(v1(ops) / "docs"))
    assert (v1(ops) / "docs" / "a.txt").exists()


def test_move_protected_refused(ops: FileOps) -> None:
    (v1(ops) / "shared").mkdir()
    with pytest.raises(FileOpError):
        ops.move(str(v1(ops) / "shared"), str(v1(ops) / "dest"))
    assert (v1(ops) / "shared").is_dir()


def test_move_volume_root_refused(ops: FileOps) -> None:
    with pytest.raises(FileOpError):
        ops.move(str(v1(ops)), str(v2(ops)))


def test_cross_device_move_copies_then_deletes(
    ops: FileOps, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(files, "FORCE_CROSS_DEVICE", True)
    out = ops.move(str(v1(ops) / "docs"), str(v2(ops)))
    assert tree(Path(out)) == {"a.txt": "A", "sub/deep.txt": "DEEP"}
    assert not (v1(ops) / "docs").exists()


def test_cross_device_move_failure_keeps_source(
    ops: FileOps, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(files, "FORCE_CROSS_DEVICE", True)

    def boom(*a: object, **k: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "_copy_fd", boom)
    with pytest.raises(FileOpError):
        ops.move(str(v1(ops) / "docs"), str(v2(ops)))
    assert tree(v1(ops) / "docs") == {"a.txt": "A", "sub/deep.txt": "DEEP"}
    assert list(v2(ops).iterdir()) == []


# --- search -------------------------------------------------------------------------------


def test_search_finds_recursively(ops: FileOps) -> None:
    res, truncated = ops.search(str(v1(ops)), "deep", show_hidden=False)
    assert [str(p) for p, _ in res] == [str(v1(ops) / "docs" / "sub" / "deep.txt")]
    assert truncated is False


def test_search_case_insensitive_and_hidden(ops: FileOps) -> None:
    (v1(ops) / "docs" / ".Hidden-Deep").write_text("x")
    res, _ = ops.search(str(v1(ops)), "DEEP", show_hidden=False)
    assert len(res) == 1
    res, _ = ops.search(str(v1(ops)), "DEEP", show_hidden=True)
    assert len(res) == 2


def test_search_does_not_follow_symlinks(ops: FileOps, base: Path) -> None:
    v = v1(ops)
    if not can_symlink(v):
        pytest.skip("filesystem has no symlinks (e.g. exFAT)")
    os.symlink(base / "outside", v / "escape")
    res, _ = ops.search(str(v), "secret", show_hidden=True)
    assert res == []


def test_search_limit(ops: FileOps) -> None:
    for i in range(30):
        (v1(ops) / "dest" / f"match-{i}.txt").write_text("x")
    res, truncated = ops.search(str(v1(ops)), "match", show_hidden=False, limit=10)
    assert len(res) == 10 and truncated is True


@pytest.mark.parametrize("q", ["", "x" * 101, "a\nb", "\x00"])
def test_search_bad_query(ops: FileOps, q: str) -> None:
    with pytest.raises(FileOpError):
        ops.search(str(v1(ops)), q, show_hidden=False)
