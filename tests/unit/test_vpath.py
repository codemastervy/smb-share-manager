"""Virtual paths shown in the UI ("/files/Photos") map to real volume paths and back."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssm.vpath import VolumeMap, VPathError


@pytest.fixture
def vm(tmp_path: Path) -> VolumeMap:
    (tmp_path / "mnt" / "files").mkdir(parents=True)
    (tmp_path / "srv" / "media").mkdir(parents=True)
    return VolumeMap([str(tmp_path / "mnt" / "files"), str(tmp_path / "srv" / "media")])


def test_names(vm: VolumeMap) -> None:
    assert [v.name for v in vm.volumes] == ["files", "media"]


def test_roundtrip(vm: VolumeMap, tmp_path: Path) -> None:
    real = vm.to_real("/files/Photos/2024")
    assert real == str(tmp_path / "mnt" / "files" / "Photos" / "2024")
    assert vm.to_virtual(real) == "/files/Photos/2024"
    assert vm.to_real("/media") == str(tmp_path / "srv" / "media")
    assert vm.to_virtual(str(tmp_path / "srv" / "media")) == "/media"


@pytest.mark.parametrize(
    "bad",
    ["", "/", "files", "/nope", "/files/../media", "/files/./x", "/files//x", "/files/x/",
     "/files/a\nb", "/files/\x00", "/../etc/passwd"],
)
def test_bad_virtual_paths(vm: VolumeMap, bad: str) -> None:
    with pytest.raises(VPathError):
        vm.to_real(bad)


def test_to_virtual_outside(vm: VolumeMap, tmp_path: Path) -> None:
    with pytest.raises(VPathError):
        vm.to_virtual(str(tmp_path / "mnt"))
    with pytest.raises(VPathError):
        vm.to_virtual(str(tmp_path / "mnt" / "files2"))


def test_duplicate_names_refused(tmp_path: Path) -> None:
    (tmp_path / "a" / "files").mkdir(parents=True)
    (tmp_path / "b" / "files").mkdir(parents=True)
    with pytest.raises(VPathError):
        VolumeMap([str(tmp_path / "a" / "files"), str(tmp_path / "b" / "files")])
