"""Files portal: who may ask (trusted proxy, HTTPS, one identity header, linked e-mail,
remote access), setup mode until the spoof test passed, CSRF, and the same share
authorisation and file rules as WebDAV."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from ssm.dav.acl import AclStore
from ssm.portal.app import build_asgi
from ssm.portal.main import portal_checks
from ssm.portal.settings import PortalSettings, load_portal_settings
from ssm.settings import ConfigError

HOST = "files.example.org"
ORIGIN = f"https://{HOST}"
PROXY = "172.20.0.5"
SECRET = "s3cret-" + "x" * 40


class Portal:
    def __init__(self, tmp: Path, verified: bool = True, **over: Any) -> None:
        tmp = Path(os.path.realpath(tmp))
        self.vol = tmp / "files"
        for d in ("Family/Photos", "Private", "Media", "Nested/Inner"):
            (self.vol / d).mkdir(parents=True)
        (self.vol / "Family" / "list.txt").write_bytes(b"milk\n")
        (self.vol / "Media" / "song.mp3").write_bytes(b"ID3")
        self.bridge = tmp / "bridge"
        self.bridge.mkdir()
        self.users: dict[str, dict[str, Any]] = {
            "alice": {"cred": 1, "remote": True, "email": "alice@example.org"},
            "bob": {"cred": 1, "remote": True, "email": "bob@example.org"},
            "carol": {"cred": 1, "remote": False, "email": "carol@example.org"},
            "dave": {"cred": 1, "remote": True, "email": ""},
        }
        v = str(self.vol)
        self.shares: list[dict[str, Any]] = [
            {
                "name": "Family",
                "path": f"{v}/Family",
                "all_users": None,
                "members": {"alice": "rw", "bob": "ro", "carol": "rw"},
            },
            {
                "name": "Private",
                "path": f"{v}/Private",
                "all_users": None,
                "members": {"bob": "rw"},
            },
            {"name": "Media", "path": f"{v}/Media", "all_users": "ro", "members": {}},
            {
                "name": "Nested",
                "path": f"{v}/Nested",
                "all_users": None,
                "members": {"alice": "rw"},
            },
            {
                "name": "Inner",
                "path": f"{v}/Nested/Inner",
                "all_users": None,
                "members": {"alice": "rw"},
            },
            {"name": "Whole", "path": v, "all_users": "rw", "members": {}},
        ]
        self.write()
        self.settings = PortalSettings(
            hosts=[HOST],
            exposed_shares=["Family", "Private", "Media", "Nested", "Inner", "Whole"],
            volumes=[v],
            trusted_proxies=["172.16.0.0/12"],
            proxy_secret=SECRET,
            header_verified=verified,
            max_upload_bytes=1024,
            bridge_dir=str(self.bridge),
            frontend_dir=str(tmp / "frontend"),
            **over,
        )
        self.store = AclStore(
            str(self.bridge / "acl.json"),
            self.settings.exposed_shares,
            [v],
            is_mountpoint=lambda p: True,
        )
        self.peer = PROXY
        inner = build_asgi(self.settings, self.store)

        async def with_peer(scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                scope["client"] = (self.peer, 40000)
            await inner(scope, receive, send)

        self.client = TestClient(with_peer, base_url=ORIGIN)

    def write(self) -> None:
        data = {"format": 1, "volumes": [str(self.vol)], "users": self.users, "shares": self.shares}
        tmp = self.bridge / "acl.tmp"
        tmp.write_text(json.dumps(data))
        os.replace(tmp, self.bridge / "acl.json")

    def headers(
        self, email: str | None = "alice@example.org", change: bool = False, **extra: str
    ) -> dict[str, str]:
        h = {"x-forwarded-proto": "https", "x-portal-proxy-secret": SECRET}
        if email is not None:
            h["remote-email"] = email
        if change:
            h["x-ssm-portal"] = "1"
            h["origin"] = ORIGIN
        h.update(extra)
        return h

    def get(self, url: str, email: str | None = "alice@example.org", **kw: Any) -> Any:
        return self.client.get(url, headers=self.headers(email, **kw))

    def post(self, url: str, body: Any, email: str = "alice@example.org", **kw: Any) -> Any:
        h = self.headers(email, change=True)
        h.update(kw.pop("headers", {}))
        return self.client.post(url, json=body, headers=h, **kw)

    def upload(self, path: str, name: str, data: bytes, email: str = "alice@example.org") -> Any:
        return self.client.put(
            "/api/portal/upload",
            params={"path": path, "name": name},
            content=data,
            headers=self.headers(email, change=True),
        )


@pytest.fixture
def p(tmp_path: Path) -> Portal:
    return Portal(tmp_path)


# --- who may ask --------------------------------------------------------------------------


def test_me_lists_only_visible_exposed_shares(p: Portal) -> None:
    r = p.get("/api/portal/me")
    assert r.status_code == 200, r.text
    names = {s["name"]: s["access"] for s in r.json()["shares"]}
    # Whole covers a volume and is never served; Private belongs to bob.
    assert names == {"Family": "rw", "Inner": "rw", "Media": "ro", "Nested": "rw"}
    assert r.json()["user"] == "alice"


def test_untrusted_peer_refused_before_anything(p: Portal) -> None:
    p.peer = "203.0.113.9"
    for url in ("/api/portal/me", "/", "/api/portal/probe", "/assets/x.js"):
        r = p.get(url)
        assert r.status_code == 403 and r.text == "Forbidden\n"


@pytest.mark.parametrize(
    "secret",
    [None, "", "wrong-" + "x" * 40, SECRET + "x", SECRET.upper()],
)
def test_proxy_secret_required(p: Portal, secret: str | None) -> None:
    # A container inside the trusted network that doesn't know the secret can't pose as
    # the proxy, and so can't forge the identity header.
    h = {"x-forwarded-proto": "https", "remote-email": "alice@example.org"}
    if secret is not None:
        h["x-portal-proxy-secret"] = secret
    r = p.client.get("/api/portal/me", headers=h)
    assert r.status_code == 403 and r.text == "Forbidden\n"


def test_proxy_secret_twice_refused(p: Portal) -> None:
    h = [
        ("x-forwarded-proto", "https"),
        ("x-portal-proxy-secret", SECRET),
        ("x-portal-proxy-secret", SECRET),
        ("remote-email", "alice@example.org"),
    ]
    assert p.client.get("/api/portal/me", headers=h).status_code == 403


def test_healthz_needs_no_identity(p: Portal) -> None:
    p.peer = "127.0.0.1"
    r = p.client.get("/healthz", headers={"host": "127.0.0.1:8096"})
    assert r.status_code == 200 and r.text == "ok"


def test_https_required(p: Portal) -> None:
    for proto in (None, "http", "https, http"):
        h = {"remote-email": "alice@example.org", "x-portal-proxy-secret": SECRET}
        if proto:
            h["x-forwarded-proto"] = proto
        r = p.client.get("/api/portal/me", headers=h)
        assert r.status_code == 403 and "HTTPS" in r.text


def test_unknown_host_refused(p: Portal) -> None:
    r = p.client.get("/api/portal/me", headers={**p.headers(), "host": "evil.example"})
    assert r.status_code == 400


def test_missing_identity_is_401(p: Portal) -> None:
    assert p.get("/api/portal/me", email=None).status_code == 401


def test_two_identity_headers_refused(p: Portal) -> None:
    # A proxy that appends instead of replacing passes the forged copy along too.
    h = [
        ("x-forwarded-proto", "https"),
        ("x-portal-proxy-secret", SECRET),
        ("remote-email", "bob@example.org"),
        ("remote-email", "alice@example.org"),
    ]
    r = p.client.get("/api/portal/me", headers=h)
    assert r.status_code == 400


def test_comma_joined_identity_refused(p: Portal) -> None:
    r = p.get("/api/portal/me", email="bob@example.org, alice@example.org")
    assert r.status_code == 400


def test_invalid_identity_refused(p: Portal) -> None:
    for bad in ("", "alice", "alice@", "<script>@x.org", "a@b"):
        assert p.get("/api/portal/me", email=bad).status_code in (401, 403), bad


def test_identity_case_insensitive(p: Portal) -> None:
    assert p.get("/api/portal/me", email="Alice@Example.ORG").json()["user"] == "alice"


def test_unlinked_email_refused(p: Portal) -> None:
    r = p.get("/api/portal/me", email="stranger@example.org")
    assert r.status_code == 403 and "not linked" in r.json()["detail"]


def test_remote_access_off_refused(p: Portal) -> None:
    r = p.get("/api/portal/me", email="carol@example.org")
    assert r.status_code == 403 and "Remote access" in r.json()["detail"]


def test_email_claimed_twice_maps_to_nobody(p: Portal) -> None:
    p.users["dave"]["email"] = "alice@example.org"
    p.write()
    assert p.get("/api/portal/me").status_code == 403


def test_registry_changes_apply_next_request(p: Portal) -> None:
    assert p.get("/api/portal/list?path=/Family").status_code == 200
    p.shares[0]["members"].pop("alice")
    p.write()
    assert p.get("/api/portal/list?path=/Family").status_code == 404
    p.users["alice"]["remote"] = False
    p.write()
    assert p.get("/api/portal/me").status_code == 403
    p.users.pop("alice")
    p.write()
    assert p.get("/api/portal/me").status_code == 403


def test_missing_snapshot_fails_closed(p: Portal) -> None:
    os.unlink(p.bridge / "acl.json")
    assert p.get("/api/portal/me").status_code == 503


# --- setup mode ---------------------------------------------------------------------------


def test_setup_mode_serves_no_files(tmp_path: Path) -> None:
    p = Portal(tmp_path, verified=False)
    assert p.get("/api/portal/me").status_code == 503
    assert p.get("/api/portal/list?path=/Family").status_code == 503
    assert p.get("/api/portal/download?path=/Family/list.txt").status_code == 503
    assert p.upload("/Family", "x.txt", b"x").status_code == 503
    assert p.get("/").status_code == 503
    assert not (p.vol / "Family" / "x.txt").exists()


def test_probe_reports_every_identity_value(tmp_path: Path) -> None:
    p = Portal(tmp_path, verified=False)
    h = [
        ("x-forwarded-proto", "https"),
        ("x-portal-proxy-secret", SECRET),
        ("remote-email", "spoof@example.invalid"),
        ("remote-email", "alice@example.org"),
    ]
    r = p.client.get("/api/portal/probe", headers=h)
    assert r.status_code == 200
    assert r.json()["values"] == ["spoof@example.invalid", "alice@example.org"]


def test_probe_gone_once_verified(p: Portal) -> None:
    assert p.get("/api/portal/probe").status_code == 404


# --- CSRF ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "drop",
    [
        {"x-ssm-portal": ""},
        {"origin": "https://evil.example"},
        {"origin": "null"},
        {"origin": f"http://{HOST}"},
    ],
)
def test_changes_need_csrf_header_and_origin(p: Portal, drop: dict[str, str]) -> None:
    r = p.post("/api/portal/mkdir", {"path": "/Family", "name": "New"}, headers=drop)
    assert r.status_code == 403
    assert not (p.vol / "Family" / "New").exists()


def test_get_cannot_change_anything(p: Portal) -> None:
    assert p.get("/api/portal/delete?path=/Family/list.txt").status_code in (404, 405)
    assert (p.vol / "Family" / "list.txt").exists()


# --- browsing and authorisation --------------------------------------------------------------


def test_list_share(p: Portal) -> None:
    (p.vol / "Family" / ".ssm-upload-abc.part").write_bytes(b"")
    os.symlink("/etc", p.vol / "Family" / "escape")
    r = p.get("/api/portal/list?path=/Family")
    assert r.status_code == 200
    body = r.json()
    assert body["access"] == "rw" and body["path"] == "/Family"
    assert [e["name"] for e in body["entries"]] == ["Photos", "list.txt"]


def test_share_names_case_insensitive(p: Portal) -> None:
    r = p.get("/api/portal/list?path=/family")
    assert r.status_code == 200 and r.json()["path"] == "/Family"


def test_other_users_share_is_404(p: Portal) -> None:
    assert p.get("/api/portal/list?path=/Private").status_code == 404
    assert p.get("/api/portal/list?path=/Private", email="bob@example.org").status_code == 200


def test_whole_volume_share_never_served(p: Portal) -> None:
    assert p.get("/api/portal/list?path=/Whole").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/Family/../Private",
        "/Family/./x",
        "Family",
        "/",
        "",
        "/Family/",
        "//Family",
        "/Family/\x00",
        "/Family/a\nb",
        "/../etc",
    ],
)
def test_bad_paths_refused(p: Portal, path: str) -> None:
    r = p.client.get("/api/portal/list", params={"path": path}, headers=p.headers())
    assert r.status_code in (400, 404, 422)


def test_symlink_not_followed(p: Portal) -> None:
    os.symlink(p.vol / "Private", p.vol / "Family" / "link")
    (p.vol / "Private" / "secret.txt").write_text("s")
    assert p.get("/api/portal/list?path=/Family/link").status_code == 400
    assert p.get("/api/portal/download?path=/Family/link/secret.txt").status_code == 400


def test_download_headers(p: Portal) -> None:
    (p.vol / "Family" / "page.html").write_text("<script>alert(1)</script>")
    r = p.get("/api/portal/download?path=/Family/page.html")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"].startswith("attachment;")
    assert "sandbox" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_download_folder_refused(p: Portal) -> None:
    assert p.get("/api/portal/download?path=/Family/Photos").status_code == 400


# --- changes ------------------------------------------------------------------------------


def test_upload_never_overwrites(p: Portal) -> None:
    r = p.upload("/Family", "list.txt", b"eggs\n")
    assert r.status_code == 201 and r.json()["name"] == "list (1).txt"
    assert (p.vol / "Family" / "list.txt").read_bytes() == b"milk\n"


def test_upload_limit(p: Portal) -> None:
    assert p.upload("/Family", "big.bin", b"x" * 1025).status_code == 413
    assert sorted(x.name for x in (p.vol / "Family").iterdir()) == ["Photos", "list.txt"]


def test_upload_bad_name(p: Portal) -> None:
    assert p.upload("/Family", "../escape.txt", b"x").status_code in (201, 400)
    assert not (p.vol / "escape.txt").exists()


def test_mkdir_rename_delete(p: Portal) -> None:
    assert p.post("/api/portal/mkdir", {"path": "/Family", "name": "Trip"}).status_code == 201
    r = p.post("/api/portal/rename", {"path": "/Family/Trip", "name": "Trip 2026"})
    assert r.status_code == 200
    assert (p.vol / "Family" / "Trip 2026").is_dir()
    (p.vol / "Family" / "Trip 2026" / "a.jpg").write_bytes(b"x")
    assert p.post("/api/portal/delete", {"path": "/Family/Trip 2026"}).status_code == 200
    assert not (p.vol / "Family" / "Trip 2026").exists()


def test_rename_never_overwrites(p: Portal) -> None:
    (p.vol / "Family" / "b.txt").write_text("b")
    r = p.post("/api/portal/rename", {"path": "/Family/b.txt", "name": "list.txt"})
    assert r.status_code == 400
    assert (p.vol / "Family" / "list.txt").read_bytes() == b"milk\n"


def test_rename_cannot_move_out(p: Portal) -> None:
    r = p.post("/api/portal/rename", {"path": "/Family/list.txt", "name": "../x.txt"})
    assert r.status_code == 400


@pytest.mark.parametrize(
    "call",
    [
        lambda p: p.upload("/Family", "x.txt", b"x", email="bob@example.org"),
        lambda p: p.post(
            "/api/portal/mkdir", {"path": "/Family", "name": "X"}, email="bob@example.org"
        ),
        lambda p: p.post(
            "/api/portal/rename",
            {"path": "/Family/list.txt", "name": "y.txt"},
            email="bob@example.org",
        ),
        lambda p: p.post(
            "/api/portal/delete", {"path": "/Family/list.txt"}, email="bob@example.org"
        ),
        lambda p: p.upload("/Media", "x.txt", b"x"),
    ],
)
def test_read_only_cannot_change(p: Portal, call: Callable[[Portal], Any]) -> None:
    before = sorted(str(x) for x in p.vol.rglob("*"))
    assert call(p).status_code == 403
    assert sorted(str(x) for x in p.vol.rglob("*")) == before


def test_share_root_cannot_be_deleted_or_renamed(p: Portal) -> None:
    assert p.post("/api/portal/delete", {"path": "/Family"}).status_code == 400
    assert p.post("/api/portal/rename", {"path": "/Family", "name": "X"}).status_code == 400
    assert (p.vol / "Family").is_dir()


def test_folder_holding_another_share_is_protected(p: Portal) -> None:
    r = p.post("/api/portal/delete", {"path": "/Nested/Inner"})
    assert r.status_code == 400
    assert (p.vol / "Nested" / "Inner").is_dir()


def test_json_body_limit(p: Portal) -> None:
    r = p.post("/api/portal/mkdir", {"path": "/Family", "name": "x" * 70_000})
    assert r.status_code == 413


def test_unknown_api_404(p: Portal) -> None:
    for url in ("/api/users", "/api/auth/status", "/api/files/list"):
        assert p.get(url).status_code == 404


def test_security_headers(p: Portal) -> None:
    r = p.get("/api/portal/me")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "server" not in r.headers


# --- settings and startup -------------------------------------------------------------------


BASE = {
    "PORTAL_HOSTS": HOST,
    "PORTAL_TRUSTED_PROXIES": "172.16.0.0/12",
    "VOLUMES": "/mnt/files",
    "PORTAL_PROXY_SECRET": SECRET,
}


def test_settings_defaults() -> None:
    s = load_portal_settings({**BASE, "DAV_EXPOSED_SHARES": "Family"})
    assert s.exposed_shares == ["Family"] and not s.header_verified
    assert s.identity_header == "remote-email"
    assert SECRET not in repr(s)


@pytest.mark.parametrize(
    "env",
    [
        {"PORTAL_HOSTS": ""},
        {"PORTAL_HOSTS": "https://files.example.org"},
        {"PORTAL_TRUSTED_PROXIES": ""},
        {"PORTAL_TRUSTED_PROXIES": "0.0.0.0/0"},
        {"PORTAL_TRUSTED_PROXIES": "not-an-ip"},
        {"PORTAL_IDENTITY_HEADER": "remote email"},
        {"PORTAL_HEADER_VERIFIED": "yes"},
        {"PORTAL_EXPOSED_SHARES": "bad/name"},
        {"PORTAL_PROXY_SECRET": ""},
        {"PORTAL_PROXY_SECRET": "short"},
        {"PORTAL_PROXY_SECRET": "x" * 31},
        {"PORTAL_PROXY_SECRET": "has space " + "x" * 40},
    ],
)
def test_settings_refused(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        load_portal_settings({**BASE, **env})


def test_portal_refuses_dav_uid(p: Portal) -> None:
    from ssm.dav.main import StartupError

    with pytest.raises(StartupError, match="DAV_UID"):
        portal_checks(p.settings, p.store, uid=p.settings.dav_uid)
