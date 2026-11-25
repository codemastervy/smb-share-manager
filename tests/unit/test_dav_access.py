"""WebDAV authorisation and path safety: who sees which share, read-only enforcement,
zero-member and unexposed shares, traversal, symlinks, control characters, the
/mnt/timenest stand-in, admin routes, response headers and PROPFIND depth."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.unit.dav_harness import LOCK_BODY, PROPFIND_BODY, Dav, dest


@pytest.fixture
def dav(tmp_path: Path) -> Dav:
    return Dav(tmp_path)


def names(r: object) -> set[str]:
    import re

    text = r.text  # type: ignore[attr-defined]
    hrefs = re.findall(r"<(?:\w+:)?href>([^<]*)</(?:\w+:)?href>", text)
    return {h.rstrip("/").rsplit("/", 1)[-1] for h in hrefs if h.strip("/")}


def ls(dav: Dav, path: str = "/", user: str = "alice") -> object:
    return dav.req("PROPFIND", path, user=user, body=PROPFIND_BODY, headers={"Depth": "1"})


# --- which shares a user sees ------------------------------------------------------------


def test_root_lists_only_member_and_all_users_shares(dav: Dav) -> None:
    r = ls(dav)
    assert r.status == 207  # type: ignore[attr-defined]
    assert names(r) == {"Docs", "Photos", "Common"}
    assert names(ls(dav, user="dave")) == {"Secret", "Common"}
    assert names(ls(dav, user="erin")) == {"Common"}


def test_non_member_gets_404_not_403(dav: Dav) -> None:
    for path in ("/Secret", "/Secret/", "/Secret/plans.txt"):
        assert dav.req("GET", path).status == 404
        assert dav.req("PROPFIND", path, headers={"Depth": "0"}).status == 404
    assert dav.req("PUT", "/Secret/x.txt", body=b"x").status in (403, 404)
    assert not (dav.vol / "Secret" / "x.txt").exists()


def test_unknown_share_looks_the_same_as_foreign_share(dav: Dav) -> None:
    a = dav.req("GET", "/Secret/plans.txt")
    b = dav.req("GET", "/Nope/plans.txt")
    assert (a.status, a.body) == (b.status, b.body)


def test_zero_member_share_unreachable_for_everyone(dav: Dav) -> None:
    for user in ("alice", "bob", "dave", "erin"):
        assert "Empty" not in names(ls(dav, user=user))
        assert dav.req("PROPFIND", "/Empty", user=user, headers={"Depth": "0"}).status == 404


def test_unexposed_share_unreachable_even_for_members(dav: Dav) -> None:
    assert dav.req("GET", "/Hidden/h.txt").status == 404
    assert "Hidden" not in names(ls(dav))


def test_share_not_mounted_is_not_served(dav: Dav) -> None:
    dav.mounted.discard(dav.share("Docs")["path"])
    dav.acl["format"] = 1  # rewrite to force a reload
    dav.write_acl()
    assert dav.req("GET", "/Docs/readme.txt").status == 404


def test_whole_volume_share_never_served(tmp_path: Path) -> None:
    d = Dav(tmp_path, exposed_shares=["Docs", "Whole"])
    d.mounted.add(str(d.vol))
    d.write_acl()
    assert d.req("GET", "/Whole/top-level.txt").status == 404
    assert names(ls(d)) == {"Docs"}


def test_all_users_ro_plus_member_rw_gives_rw(dav: Dav) -> None:
    common = dav.share("Common")
    common["members"] = {"erin": "rw"}
    dav.write_acl()
    assert dav.req("PUT", "/Common/e.txt", user="erin", body=b"e").status == 201
    assert dav.req("PUT", "/Common/a.txt", user="alice", body=b"a").status == 403


# --- read-only members ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "headers", "body"),
    [
        ("PUT", "/Photos/new.jpg", {}, b"x"),
        ("PUT", "/Photos/cat.jpg", {}, b"overwrite"),
        ("MKCOL", "/Photos/dir", {}, b""),
        ("DELETE", "/Photos/cat.jpg", {}, b""),
        ("MOVE", "/Photos/cat.jpg", {"Destination": dest("/Photos/dog.jpg")}, b""),
        ("COPY", "/Photos/cat.jpg", {"Destination": dest("/Photos/copy.jpg")}, b""),
        ("COPY", "/Docs/readme.txt", {"Destination": dest("/Photos/readme.txt")}, b""),
        ("MOVE", "/Docs/readme.txt", {"Destination": dest("/Photos/readme.txt")}, b""),
        ("LOCK", "/Photos/cat.jpg", {"Timeout": "Second-60"}, LOCK_BODY),
        ("LOCK", "/Photos/locknull.jpg", {"Timeout": "Second-60"}, LOCK_BODY),
        (
            "PROPPATCH",
            "/Photos/cat.jpg",
            {"Content-Type": "application/xml"},
            b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:z">'
            b"<D:set><D:prop><Z:x>1</Z:x></D:prop></D:set></D:propertyupdate>",
        ),
    ],
)
def test_read_only_member_cannot_write(
    dav: Dav, method: str, path: str, headers: dict[str, str], body: bytes
) -> None:
    before = sorted(p.name for p in (dav.vol / "Photos").iterdir())
    content = (dav.vol / "Photos" / "cat.jpg").read_bytes()
    r = dav.req(method, path, body=body, headers=headers)
    assert r.status == 403, (method, path, r.status, r.text)
    assert sorted(p.name for p in (dav.vol / "Photos").iterdir()) == before
    assert (dav.vol / "Photos" / "cat.jpg").read_bytes() == content
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_read_only_member_can_read(dav: Dav) -> None:
    r = dav.req("GET", "/Photos/cat.jpg")
    assert r.status == 200
    assert r.body == (dav.vol / "Photos" / "cat.jpg").read_bytes()


def test_root_and_share_roots_are_immutable(dav: Dav) -> None:
    assert dav.req("DELETE", "/Docs").status == 403
    assert dav.req("DELETE", "/").status == 403
    assert dav.req("MKCOL", "/NewShare").status == 403
    assert dav.req("PUT", "/root.txt", body=b"x").status in (403, 405, 409)
    r = dav.req("MOVE", "/Docs", headers={"Destination": dest("/Photos/Docs")})
    assert r.status == 403
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_folder_containing_another_share_is_protected(dav: Dav) -> None:
    # A share nested inside an exposed share: its folder can't be deleted or moved away.
    (dav.vol / "Docs" / "Kids").mkdir()
    dav.acl["shares"].append(
        {
            "name": "Kids",
            "path": str(dav.vol / "Docs" / "Kids"),
            "all_users": None,
            "members": {"bob": "rw"},
        }
    )
    dav.write_acl()
    assert dav.req("DELETE", "/Docs/Kids").status == 403
    r = dav.req("MOVE", "/Docs/Kids", headers={"Destination": dest("/Docs/Kids2")})
    assert r.status == 403
    assert (dav.vol / "Docs" / "Kids").is_dir()


# --- path safety -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "/Docs/../Secret/plans.txt",
        "/Docs/%2e%2e/Secret/plans.txt",
        "/Docs/..%2fSecret/plans.txt",
        "/Docs/%2e%2e%2fSecret%2fplans.txt",
        "/Docs/./readme.txt",
        "/Docs//readme.txt",
        "/../vol/Secret/plans.txt",
        "/Docs/..",
        "/Docs/%2e%2e",
        "/Docs/..\\..\\Secret",
    ],
)
def test_traversal_refused(dav: Dav, raw: str) -> None:
    r = dav.req("GET", raw, raw_path=True)
    assert r.status in (400, 403, 404), (raw, r.status)
    assert b"secret plans" not in r.body


def test_double_encoding_is_a_literal_name(dav: Dav) -> None:
    r = dav.req("GET", "/Docs/%252e%252e/Secret/plans.txt", raw_path=True)
    assert r.status == 404
    assert b"secret plans" not in r.body


@pytest.mark.parametrize(
    "name",
    ["a\x00b", "a\nb", "a\rb", "tab\there", "del\x7f", "c1\x85", "ls sep", "\x1b[31m"],
)
def test_control_characters_refused(dav: Dav, name: str) -> None:
    for method, body in (("PUT", b"x"), ("MKCOL", b""), ("GET", b"")):
        r = dav.req(method, f"/Docs/{name}", body=body)
        assert r.status == 400, (method, repr(name), r.status)
    assert sorted(p.name for p in (dav.vol / "Docs").iterdir()) == ["readme.txt"]


def test_control_characters_in_destination_refused(dav: Dav) -> None:
    r = dav.req("COPY", "/Docs/readme.txt", headers={"Destination": dest("/Docs/a\nb")})
    assert r.status == 400


def test_invalid_utf8_path_refused(dav: Dav) -> None:
    assert dav.req("GET", "/Docs/%ff%fe", raw_path=True).status == 400


def test_overlong_name_refused(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/" + "a" * 300, body=b"x").status == 400


def test_internal_temp_names_refused(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/.ssm-upload-abc.part", body=b"x").status in (400, 403)
    assert dav.req("MKCOL", "/Docs/.ssm-copy-1").status in (400, 403)


def _symlinks(dav: Dav) -> None:
    os.symlink(dav.vol / "Secret", dav.vol / "Docs" / "to-secret")
    os.symlink(dav.vol / "Secret" / "plans.txt", dav.vol / "Docs" / "plans-link.txt")
    os.symlink(dav.outside, dav.vol / "Docs" / "to-timenest")
    os.symlink("/etc/passwd", dav.vol / "Docs" / "passwd")


def test_symlinks_are_not_listed_or_followed(dav: Dav) -> None:
    _symlinks(dav)
    assert names(ls(dav, "/Docs")) == {"Docs", "readme.txt"}
    for p in (
        "/Docs/to-secret/plans.txt",
        "/Docs/plans-link.txt",
        "/Docs/to-timenest/backup.txt",
        "/Docs/passwd",
        "/Docs/to-secret",
    ):
        r = dav.req("GET", p)
        assert r.status in (403, 404), (p, r.status)
        assert b"secret plans" not in r.body and b"time machine" not in r.body
        assert b"root:" not in r.body


def test_writes_through_symlinks_refused(dav: Dav) -> None:
    _symlinks(dav)
    assert dav.req("PUT", "/Docs/to-secret/evil.txt", body=b"x").status in (403, 404, 409)
    assert dav.req("PUT", "/Docs/plans-link.txt", body=b"x").status in (403, 404, 409)
    assert dav.req("MKCOL", "/Docs/to-timenest/x").status in (403, 404, 409)
    assert dav.req("DELETE", "/Docs/to-secret").status in (403, 404)
    r = dav.req("COPY", "/Docs/plans-link.txt", headers={"Destination": dest("/Docs/c.txt")})
    assert r.status in (403, 404)
    r = dav.req("MOVE", "/Docs/readme.txt", headers={"Destination": dest("/Docs/to-secret/r")})
    assert r.status in (403, 404, 409)
    assert (dav.vol / "Secret" / "plans.txt").read_bytes() == b"secret plans"
    assert not (dav.vol / "Secret" / "evil.txt").exists()
    assert os.path.islink(dav.vol / "Docs" / "to-secret")
    assert sorted(p.name for p in dav.outside.iterdir()) == ["backup.txt"]


def test_symlink_swapped_in_as_parent_is_not_followed(dav: Dav) -> None:
    (dav.vol / "Docs" / "sub").mkdir()
    assert dav.req("PUT", "/Docs/sub/a.txt", body=b"1").status == 201
    # Replace the folder with a link to the outside between requests.
    for p in (dav.vol / "Docs" / "sub").iterdir():
        p.unlink()
    (dav.vol / "Docs" / "sub").rmdir()
    os.symlink(dav.outside, dav.vol / "Docs" / "sub")
    assert dav.req("PUT", "/Docs/sub/b.txt", body=b"2").status in (403, 404, 409)
    assert dav.req("GET", "/Docs/sub/backup.txt").status in (403, 404)
    assert sorted(p.name for p in dav.outside.iterdir()) == ["backup.txt"]


def test_timenest_unreachable_by_any_url_or_destination(dav: Dav) -> None:
    for p in ("/timenest/backup.txt", "/../timenest/backup.txt", f"/{dav.outside}/backup.txt"):
        r = dav.req("GET", p, raw_path=True)
        assert r.status in (400, 403, 404)
        assert b"time machine" not in r.body
    for target in ("/timenest/x.txt", "/../timenest/x.txt", str(dav.outside) + "/x.txt"):
        r = dav.req(
            "COPY", "/Docs/readme.txt", headers={"Destination": f"https://dav.example.org{target}"}
        )
        assert r.status in (400, 403, 404, 409, 502)
    assert sorted(p.name for p in dav.outside.iterdir()) == ["backup.txt"]


def test_destination_on_another_host_refused(dav: Dav) -> None:
    r = dav.req(
        "COPY", "/Docs/readme.txt", headers={"Destination": "https://evil.example.com/Docs/x.txt"}
    )
    assert r.status in (400, 403, 502)
    assert not (dav.vol / "Docs" / "x.txt").exists()


def test_destination_into_foreign_share_refused(dav: Dav) -> None:
    r = dav.req("COPY", "/Docs/readme.txt", headers={"Destination": dest("/Secret/r.txt")})
    assert r.status in (403, 404)
    assert not (dav.vol / "Secret" / "r.txt").exists()


# --- headers and admin routes ------------------------------------------------------------------


def test_download_headers(dav: Dav) -> None:
    (dav.vol / "Docs" / "evil.html").write_bytes(b"<script>alert(1)</script>")
    (dav.vol / "Docs" / "evil.svg").write_bytes(b"<svg onload=alert(1)>")
    for name in ("evil.html", "evil.svg", "readme.txt"):
        r = dav.req("GET", f"/Docs/{name}")
        assert r.status == 200
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.headers["x-content-type-options"] == "nosniff"
        csp = r.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "sandbox" in csp
        assert r.headers["content-disposition"].startswith("attachment")


def test_no_server_banner_or_version(dav: Dav) -> None:
    for r in (
        dav.req("OPTIONS", "/"),
        dav.req("GET", "/Docs/readme.txt"),
        dav.req("GET", "/nope"),
        dav.req("OPTIONS", "/", user=None),
    ):
        for k, val in r.header_list:
            assert "wsgidav" not in val.lower() and "cheroot" not in val.lower(), (k, val)
            assert "python" not in val.lower()
        assert b"WsgiDAV" not in r.body and b"wsgidav" not in r.body
        if "server" in r.headers:
            assert not any(ch.isdigit() for ch in r.headers["server"])


def test_never_html(dav: Dav) -> None:
    probes = [
        dav.req("GET", "/"),
        dav.req("GET", "/Docs"),
        dav.req("GET", "/Docs/"),
        dav.req("GET", "/nope"),
        dav.req("GET", "/", user=None),
        dav.req("DELETE", "/Docs"),
        dav.req("PROPFIND", "/", headers={"Depth": "infinity"}),
        dav.req("BREW", "/"),
        dav.req("GET", "/Docs/readme.txt?davmount"),
    ]
    for r in probes:
        assert not r.headers.get("content-type", "").startswith("text/html"), r.status
        assert b"<html" not in r.body.lower()


def test_get_on_collection_is_405_plain(dav: Dav) -> None:
    for p in ("/", "/Docs", "/Docs/"):
        r = dav.req("GET", p)
        assert r.status == 405
        assert r.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize(
    "path",
    [
        "/api/users",
        "/api/auth/status",
        "/login",
        "/healthz",
        "/static/index.js",
        "/assets/index.js",
        "/api/files/list?path=/files",
        "/",
    ],
)
def test_admin_routes_not_served(dav: Dav, path: str) -> None:
    anon = dav.req("GET", path, user=None)
    assert anon.status == 401
    authed = dav.req("GET", path)
    assert authed.status in (404, 405)
    for r in (anon, authed):
        assert b"csrf" not in r.body.lower() and b"<div id=root" not in r.body
        assert "set-cookie" not in r.headers


def test_unknown_methods_refused(dav: Dav) -> None:
    for m in ("POST", "TRACE", "CONNECT", "PATCH", "SEARCH", "BREW"):
        assert dav.req(m, "/Docs/readme.txt").status in (405, 501)


# --- PROPFIND depth ------------------------------------------------------------------------------


def test_propfind_infinity_refused(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/Docs", body=PROPFIND_BODY, headers={"Depth": "infinity"})
    assert r.status == 403
    assert b"propfind-finite-depth" in r.body


def test_propfind_without_depth_refused(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/Docs", body=PROPFIND_BODY)
    assert r.status == 403


def test_propfind_depth_0_and_1(dav: Dav) -> None:
    assert dav.req("PROPFIND", "/Docs", body=PROPFIND_BODY, headers={"Depth": "0"}).status == 207
    r = dav.req("PROPFIND", "/Docs", body=PROPFIND_BODY, headers={"Depth": "1"})
    assert r.status == 207
    assert "readme.txt" in names(r)


def test_xml_entity_expansion_refused(dav: Dav) -> None:
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa">'
        b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        b'<D:propfind xmlns:D="DAV:"><D:prop><D:x>&b;</D:x></D:prop></D:propfind>'
    )
    r = dav.req("PROPFIND", "/Docs", body=bomb, headers={"Depth": "0"})
    assert r.status in (400, 403, 415)


def test_external_entity_refused(dav: Dav) -> None:
    xxe = (
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b'<D:propfind xmlns:D="DAV:"><D:prop><D:x>&x;</D:x></D:prop></D:propfind>'
    )
    r = dav.req("PROPFIND", "/Docs", body=xxe, headers={"Depth": "0"})
    assert r.status in (400, 403, 415)
    assert b"root:" not in r.body


def test_hidden_entries_not_listed(dav: Dav) -> None:
    (dav.vol / "Docs" / ".ssm-upload-123.part").write_bytes(b"partial")
    (dav.vol / "Docs" / ".ssm-copy-123").mkdir()
    os.mkfifo(dav.vol / "Docs" / "fifo")
    assert names(ls(dav, "/Docs")) == {"Docs", "readme.txt"}
    assert dav.req("GET", "/Docs/.ssm-upload-123.part").status in (400, 403, 404)
    assert dav.req("GET", "/Docs/fifo").status in (403, 404)
