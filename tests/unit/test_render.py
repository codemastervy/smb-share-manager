"""Requirements 2, 3 and 8: the smb.conf renderer refuses bad input and never escapes it."""

from __future__ import annotations

import re

import pytest

from ssm import render
from ssm.models import ShareSpec


def share(**kw: object) -> ShareSpec:
    base: dict[str, object] = {
        "name": "Photos",
        "path": "/mnt/files/Photos",
        "comment": "Family photos",
        "members": {"alice": "rw", "bob": "ro"},
        "all_users": None,
        "no_unix_perms": False,
    }
    base.update(kw)
    return ShareSpec(**base)  # type: ignore[arg-type]


def sections(text: str) -> list[str]:
    return re.findall(r"^\[([^\]]*)\]\s*$", text, flags=re.M)


def params(text: str, section: str) -> dict[str, str]:
    out: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^\[([^\]]*)\]\s*$", line)
        if m:
            current = m.group(1)
            continue
        if current == section and "=" in line and not line.lstrip().startswith(("#", ";")):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_basic_share() -> None:
    text = render.render_shares([share()])
    assert sections(text) == ["Photos"]
    p = params(text, "Photos")
    assert p["path"] == "/mnt/files/Photos"
    assert p["comment"] == "Family photos"
    assert p["valid users"] == "alice bob"
    assert p["write list"] == "alice"
    assert p["read only"] == "yes"
    assert p["guest ok"] == "no"
    assert p["force group"] == "smbusers"
    assert "available" not in p


def test_ro_only_share_has_empty_write_list_param_absent() -> None:
    p = params(render.render_shares([share(members={"bob": "ro"})]), "Photos")
    assert p["valid users"] == "bob"
    assert "write list" not in p
    assert p["read only"] == "yes"


def test_all_users_ro() -> None:
    p = params(render.render_shares([share(members={"alice": "rw"}, all_users="ro")]), "Photos")
    assert p["valid users"] == "@smbusers alice"
    assert p["write list"] == "alice"


def test_all_users_rw() -> None:
    p = params(render.render_shares([share(members={}, all_users="rw")]), "Photos")
    assert p["valid users"] == "@smbusers"
    assert p["write list"] == "@smbusers"


def test_zero_members_rendered_unavailable() -> None:
    # Defense in depth for requirement 3: even if validation were bypassed, the share is off.
    p = params(render.render_shares([share(members={}, all_users=None)]), "Photos")
    assert p["available"] == "no"
    assert p["valid users"] == "nobody"
    assert "write list" not in p


def test_no_unix_perms_share_avoids_xattrs() -> None:
    p = params(render.render_shares([share(no_unix_perms=True)]), "Photos")
    assert "streams_xattr" not in p["vfs objects"]
    assert "fruit" in p["vfs objects"]
    assert p["ea support"] == "no"


def test_unix_share_uses_streams_xattr() -> None:
    p = params(render.render_shares([share()]), "Photos")
    assert p["vfs objects"] == "fruit streams_xattr"


def test_output_is_deterministic_and_sorted() -> None:
    a = share(name="b-share", path="/mnt/files/b")
    b = share(name="A share", path="/mnt/files/a")
    assert render.render_shares([a, b]) == render.render_shares([b, a])
    assert sections(render.render_shares([a, b])) == ["A share", "b-share"]


def test_empty_list_renders_header_only() -> None:
    text = render.render_shares([])
    assert sections(text) == []
    assert text.startswith("#")


def test_duplicate_names_case_insensitive_refused() -> None:
    with pytest.raises(render.RenderError):
        render.render_shares([share(name="Files"), share(name="files")])


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "Photos]\n[global"),
        ("name", "global"),
        ("name", "IPC$"),
        ("name", "x%U"),
        ("comment", "ok\n[evil]\npath = /"),
        ("comment", "100% done"),
        ("comment", "trailing\\"),
        ("comment", "line\u2028sep"),
        ("comment", "nel\x85x"),
        ("path", "/mnt/files/x\n[evil]"),
        ("path", "relative/path"),
        ("path", "/mnt/files/%U"),
        ("path", "/mnt/files/a;b"),
        ("path", "/mnt/files/a#b"),
        ("path", "/mnt/files/trail "),
        ("path", "/mnt/files/x\\"),
        ("members", {"alice\n[evil]": "rw"}),
        ("members", {"Alice": "rw"}),
        ("members", {"alice": "rw\nadmin users = alice"}),
        ("members", {"alice": "admin"}),
        ("all_users", "yes"),
    ],
)
def test_renderer_refuses_bad_input(field: str, value: object) -> None:
    with pytest.raises(render.RenderError):
        render.render_shares([share(**{field: value})])


def test_lookalike_brackets_in_comment_cannot_open_section() -> None:
    text = render.render_shares([share(comment="［global］ ＃ ；")])
    assert sections(text) == ["Photos"]


# --- globals --------------------------------------------------------------------------


def test_globals_default() -> None:
    text = render.render_globals(hosts_allow=[], server_name="NAS", enable_nmbd=False)
    assert "hosts allow" not in text
    assert "netbios name = NAS" in text
    assert "disable netbios = yes" in text


def test_globals_hosts_allow_includes_loopback() -> None:
    text = render.render_globals(
        hosts_allow=["192.168.68.0/24", "100.64.0.0/10"], server_name="NAS", enable_nmbd=True
    )
    line = next(ln for ln in text.splitlines() if "hosts allow" in ln)
    assert "192.168.68.0/24" in line and "100.64.0.0/10" in line and "127.0.0.1" in line
    assert "hosts deny = ALL" in text or "hosts deny = 0.0.0.0/0" in text
    assert "disable netbios = no" in text


@pytest.mark.parametrize(
    "bad", ["192.168.1.0/24\n[evil]", "example.com", "1.2.3.4 5.6.7.8", "%", "300.1.1.1", ""]
)
def test_globals_bad_hosts_refused(bad: str) -> None:
    with pytest.raises(render.RenderError):
        render.render_globals(hosts_allow=[bad], server_name="NAS", enable_nmbd=False)


@pytest.mark.parametrize("bad", ["", "a" * 16, "NAS\n", "N AS", "-x", "x%"])
def test_globals_bad_server_name_refused(bad: str) -> None:
    with pytest.raises(render.RenderError):
        render.render_globals(hosts_allow=[], server_name=bad, enable_nmbd=False)


def test_parse_testparm_sections() -> None:
    sample = "# Global parameters\n[global]\n\tworkgroup = WORKGROUP\n\n[Photos]\n\tpath = /x\n"
    assert render.parse_sections(sample) == {
        "global": {"workgroup": "WORKGROUP"},
        "Photos": {"path": "/x"},
    }
