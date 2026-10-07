"""Requirement 2 (no config injection) and 7 (usernames/passwords): validator unit tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ssm import validators as v
from ssm.models import ShareSpec

CONTROL_SAMPLES = ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85", "\u2028", "\u2029", "\x1f"]


# --- control characters -------------------------------------------------------------


@pytest.mark.parametrize("ch", CONTROL_SAMPLES)
def test_control_chars_rejected_everywhere(ch: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_name(f"Files{ch}x")
    with pytest.raises(v.ValidationError):
        v.validate_username(f"alice{ch}")
    with pytest.raises(v.ValidationError):
        v.validate_comment(f"hello{ch}[global]")
    with pytest.raises(v.ValidationError):
        v.validate_filename(f"a{ch}b.txt")
    with pytest.raises(v.ValidationError):
        v.validate_password(f"longenough{ch}password")


def test_has_control_chars_boundaries() -> None:
    assert v.has_control_chars("\x1f")
    assert v.has_control_chars("\x7f")
    assert not v.has_control_chars(" ")
    assert not v.has_control_chars("~")
    assert not v.has_control_chars("é")


# --- share names --------------------------------------------------------------------


@pytest.mark.parametrize("name", ["Files", "Isherveer", "a", "My Share", "x.y_z-1", "A" * 64])
def test_valid_share_names(name: str) -> None:
    assert v.validate_share_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        " Files",
        "Files ",
        "-dash",
        ".dot",
        "A" * 65,
        "a[b",
        "a]b",
        "a%b",
        "a;b",
        "a#b",
        "a/b",
        "a\\b",
        "a=b",
        "Ｆiles",  # fullwidth F
        "Filеs",  # cyrillic e
        "Files\u00a0",
        "ﬁles",  # ligature
    ],
)
def test_invalid_share_names(name: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_name(name)


@pytest.mark.parametrize("name", ["global", "GLOBAL", "Homes", "printers", "print$", "IPC$", "globals"])
def test_reserved_share_names(name: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_name(name)


# --- usernames ----------------------------------------------------------------------


@pytest.mark.parametrize("name", ["alice", "_svc", "jagdev", "a1-b_c", "a" * 32])
def test_valid_usernames(name: str) -> None:
    assert v.validate_username(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "Alice",
        "1alice",
        "-alice",
        "--help",
        "a" * 33,
        "al ice",
        "alice$",
        "al.ice",
        "álice",
        "alicе",  # cyrillic e
        "root",
        "nobody",
        "smbusers",
    ],
)
def test_invalid_usernames(name: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_username(name)


# --- passwords ----------------------------------------------------------------------


def test_password_min_length() -> None:
    with pytest.raises(v.ValidationError):
        v.validate_password("123456789")
    assert v.validate_password("1234567890") == "1234567890"


def test_password_max_length() -> None:
    with pytest.raises(v.ValidationError):
        v.validate_password("x" * 257)


def test_password_error_never_contains_password() -> None:
    secret = "abc\ndefghijklmn"
    with pytest.raises(v.ValidationError) as ei:
        v.validate_password(secret)
    assert "abc" not in str(ei.value)


# --- comments -----------------------------------------------------------------------


@pytest.mark.parametrize("c", ["", "Family photos", "Jagdev's files (2024)", "Ünïcödé ok", "a[b]c"])
def test_valid_comments(c: str) -> None:
    assert v.validate_comment(c) == c


@pytest.mark.parametrize("c", ["x" * 257, "50%", "%U", "trailing\\", "a\\b", " lead", "trail "])
def test_invalid_comments(c: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_comment(c)


# --- filenames ----------------------------------------------------------------------


@pytest.mark.parametrize("n", ["a.txt", ".hidden", "with space.pdf", "ünï.jpg", "a" * 255])
def test_valid_filenames(n: str) -> None:
    assert v.validate_filename(n) == n


@pytest.mark.parametrize("n", ["", ".", "..", "a/b", "/abs", "a\x00b", "é" * 128])
def test_invalid_filenames(n: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_filename(n)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\evil.html", "evil.html"),
        ("  spaced  .txt ", "spaced  .txt"),
        ("tab\there.txt", "tabhere.txt"),
        ("new\nline.txt", "newline.txt"),
        (".bashrc", ".bashrc"),
    ],
)
def test_sanitize_upload_filename(raw: str, expected: str) -> None:
    assert v.sanitize_upload_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "..", ".", "/", "\x00\x01", "a/..", ".ssm-upload-x.part"])
def test_sanitize_upload_filename_rejects(raw: str) -> None:
    with pytest.raises(v.ValidationError):
        v.sanitize_upload_filename(raw)


def test_sanitize_upload_filename_truncates_keeping_extension() -> None:
    out = v.sanitize_upload_filename("é" * 300 + ".jpeg")
    assert out.endswith(".jpeg")
    assert len(out.encode()) <= 255


# --- volumes and share paths --------------------------------------------------------


@pytest.fixture
def vol(tmp_path: Path) -> Path:
    root = tmp_path / "files"
    (root / "Photos" / "2024").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    return root


@pytest.mark.parametrize(
    "bad", ["/", "/proc", "/sys", "/dev", "/etc", "/data", "/run", "/usr", "/proc/1", "relative"]
)
def test_volume_denylist(bad: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_volumes([bad])


def test_volume_must_exist(tmp_path: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_volumes([str(tmp_path / "missing")])


def test_volume_ok(vol: Path) -> None:
    assert v.validate_volumes([str(vol)]) == [os.path.realpath(vol)]


def test_overlapping_volumes_rejected(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_volumes([str(vol), str(vol / "Photos")])


def test_share_path_inside_volume(vol: Path) -> None:
    p = v.validate_share_path(str(vol / "Photos"), [str(vol)])
    assert p == os.path.realpath(vol / "Photos")


def test_share_path_volume_root_allowed(vol: Path) -> None:
    assert v.validate_share_path(str(vol), [str(vol)]) == os.path.realpath(vol)


def test_share_path_outside_volume(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol.parent / "outside"), [str(vol)])


def test_share_path_dotdot_escape(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol / "Photos" / ".." / ".." / "outside"), [str(vol)])


def test_share_path_prefix_trick(vol: Path) -> None:
    sibling = vol.parent / "files2"
    sibling.mkdir()
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(sibling), [str(vol)])


def test_share_path_symlink_escape(vol: Path) -> None:
    (vol / "link").symlink_to(vol.parent / "outside")
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol / "link"), [str(vol)])


def test_share_path_must_be_existing_directory(vol: Path) -> None:
    (vol / "file.txt").write_text("x")
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol / "file.txt"), [str(vol)])
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol / "nope"), [str(vol)])


@pytest.mark.parametrize("bad", ["100%", "a\nb", " lead", "trail ", "back\\slash", "semi;colon"])
def test_share_path_bad_chars(vol: Path, bad: str) -> None:
    d = vol / bad.replace("\n", "_")
    d.mkdir(exist_ok=True)
    with pytest.raises(v.ValidationError):
        v.validate_share_path(str(vol / bad), [str(vol)])


def test_share_path_relative_rejected(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share_path("Photos", [str(vol)])


# --- whole share spec (requirement 3) ------------------------------------------------


def _spec(vol: Path, **kw: object) -> ShareSpec:
    base: dict[str, object] = {
        "name": "Photos",
        "path": str(vol / "Photos"),
        "comment": "",
        "members": {"alice": "rw"},
        "all_users": None,
    }
    base.update(kw)
    return ShareSpec(**base)  # type: ignore[arg-type]


def test_share_spec_ok(vol: Path) -> None:
    s = v.validate_share(_spec(vol), [str(vol)], {"alice"})
    assert s.members == {"alice": "rw"}


def test_share_spec_zero_members_refused(vol: Path) -> None:
    with pytest.raises(v.ValidationError, match="member"):
        v.validate_share(_spec(vol, members={}), [str(vol)], {"alice"})


def test_share_spec_all_users_without_members_ok(vol: Path) -> None:
    s = v.validate_share(_spec(vol, members={}, all_users="ro"), [str(vol)], set())
    assert s.all_users == "ro"


def test_share_spec_unknown_member(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share(_spec(vol, members={"bob": "ro"}), [str(vol)], {"alice"})


def test_share_spec_bad_access(vol: Path) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_share(_spec(vol, members={"alice": "admin"}), [str(vol)], {"alice"})
    with pytest.raises(v.ValidationError):
        v.validate_share(_spec(vol, members={}, all_users="yes"), [str(vol)], set())
