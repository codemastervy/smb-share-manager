"""Requirement 6: authentication, sessions, CSRF, Origin/Host checks, login throttle."""

from __future__ import annotations

import itertools
import json
import sqlite3
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from ssm import auth
from ssm.settings import ConfigError, Settings, load_settings
from tests.conftest import ORIGIN, PASSWORD, Env, call, login, make_settings, prelogin

# --- startup -------------------------------------------------------------------------


def test_refuses_to_start_without_password(env: Env) -> None:
    s = make_settings(env.tmp, env.volume, admin_password=None, admin_password_hash=None)
    with pytest.raises(ConfigError):
        env.make_client(s)


def test_load_settings_requires_password(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ADMIN_PASSWORD"):
        load_settings({"VOLUMES": str(tmp_path)})


def test_load_settings_rejects_short_password(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings({"ADMIN_PASSWORD": "short", "VOLUMES": str(tmp_path)})


def test_load_settings_rejects_non_argon2id_hash(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings({"ADMIN_PASSWORD_HASH": "$2b$12$abcdefghijkl", "VOLUMES": str(tmp_path)})


def test_load_settings_parses_env(tmp_path: Path) -> None:
    s = load_settings(
        {
            "ADMIN_PASSWORD": PASSWORD,
            "VOLUMES": str(tmp_path),
            "TRUSTED_PROXIES": "10.0.0.1, 10.1.0.0/16",
            "ALLOWED_HOSTS": "nuc, nuc.example.ts.net",
            "MAX_UPLOAD_MB": "5",
        }
    )
    assert s.trusted_proxies == ["10.0.0.1", "10.1.0.0/16"]
    assert s.allowed_hosts == ["nuc", "nuc.example.ts.net"]
    assert s.max_upload_bytes == 5 * 1024 * 1024


def test_hash_login(env: Env) -> None:
    h = PasswordHasher().hash("hash password 123")
    s = make_settings(env.tmp, env.volume, admin_password=None, admin_password_hash=h)
    login(env.make_client(s), "hash password 123")


# --- unauthenticated surface ---------------------------------------------------------

PUBLIC = {"/healthz", "/api/auth/status", "/api/auth/login"}


def test_no_unauthenticated_api_routes_except_allowlist(env: Env) -> None:
    c = env.make_client()
    pre = prelogin(c)
    checked = 0
    for route in c.app.routes:  # type: ignore[attr-defined]
        path = getattr(route, "path", "")
        if path in PUBLIC or not path.startswith("/api"):
            continue
        url = path.replace("{share_id}", "x").replace("{username}", "x")
        for method in sorted(getattr(route, "methods", None) or {"GET"}):
            if method == "HEAD":
                continue
            r = c.request(method, url, headers={"Origin": ORIGIN, "X-CSRF-Token": pre})
            assert r.status_code == 401, (method, url, r.status_code)
            checked += 1
    assert checked > 20


def test_non_api_routes_serve_only_the_static_app(env: Env) -> None:
    c = env.make_client()
    for url in ("/", "/files/files/x", "/shares", "/anything"):
        r = c.get(url)
        assert r.status_code == 200
        assert r.text.startswith("<!doctype html>")
        assert r.headers["cache-control"] == "no-store"
    assert c.get("/assets/index-abc.js").status_code == 200
    assert c.post("/", headers={"Origin": ORIGIN}).status_code in (404, 405)


@pytest.mark.parametrize(
    "url", ["/docs", "/redoc", "/openapi.json", "/api/docs", "/api/openapi.json"]
)
def test_no_public_api_docs(env: Env, url: str) -> None:
    r = env.make_client().get(url)
    assert "swagger" not in r.text.lower() and '"openapi"' not in r.text


def test_unknown_api_route_is_404_json(env: Env) -> None:
    c = env.make_client()
    login(c)
    r = c.get("/api/nope")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")


def test_healthz_has_no_sensitive_info(env: Env) -> None:
    r = env.make_client().get("/healthz")
    assert r.status_code == 200
    assert set(r.json()) == {"status", "version", "build_date"}


# --- login / cookies -----------------------------------------------------------------


def test_status_unauthenticated(env: Env) -> None:
    body = env.make_client().get("/api/auth/status").json()
    assert body["authenticated"] is False and body["csrf"]


def _login_raw(c, pw: str, origin: str = ORIGIN, token: str | None = None, xff: str | None = None):  # type: ignore[no-untyped-def]
    pre = c.get("/api/auth/status").json()["csrf"] if token is None else token
    headers = {"Origin": origin, "X-CSRF-Token": pre}
    if xff:
        headers["X-Forwarded-For"] = xff
    return c.post("/api/auth/login", json={"password": pw}, headers=headers)


def test_wrong_password_rejected(env: Env) -> None:
    r = _login_raw(env.make_client(), "wrong password!!")
    assert r.status_code == 401
    assert "ssm_session" not in r.cookies


def test_login_requires_prelogin_csrf(env: Env) -> None:
    c = env.make_client()
    prelogin(c)
    r = c.post("/api/auth/login", json={"password": PASSWORD}, headers={"Origin": ORIGIN})
    assert r.status_code == 403
    assert _login_raw(c, PASSWORD, token="x" * 43).status_code == 403


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "https://testserver"])
def test_login_bad_origin_rejected(env: Env, origin: str) -> None:
    assert _login_raw(env.make_client(), PASSWORD, origin=origin).status_code == 403


def test_login_form_encoded_rejected(env: Env) -> None:
    c = env.make_client()
    pre = prelogin(c)
    r = c.post(
        "/api/auth/login",
        data={"password": PASSWORD},
        headers={"Origin": ORIGIN, "X-CSRF-Token": pre},
    )
    assert r.status_code in (415, 422)


def test_session_cookie_flags_http(env: Env) -> None:
    sc = _login_raw(env.make_client(), PASSWORD).headers["set-cookie"]
    assert "ssm_session=" in sc and "HttpOnly" in sc
    assert "samesite=strict" in sc.lower()
    assert "Secure" not in sc and "Path=/" in sc


def test_session_cookie_secure_when_forced(env: Env) -> None:
    c = env.make_client(make_settings(env.tmp, env.volume, cookie_secure="true"))
    assert "Secure" in c.get("/api/auth/status").headers["set-cookie"]


def test_session_cookie_secure_on_https(env: Env) -> None:
    from fastapi.testclient import TestClient

    from ssm.web.app import create_app

    app = create_app(env.settings, helper=env.helper, clock=env.clock)
    c = TestClient(app, base_url="https://testserver", follow_redirects=False)
    r = _login_raw(c, PASSWORD, origin="https://testserver")
    assert "Secure" in r.headers["set-cookie"]


def test_session_tokens_random_and_only_hash_stored(env: Env) -> None:
    c1, c2 = env.make_client(), env.make_client()
    login(c1)
    login(c2)
    t1, t2 = c1.cookies["ssm_session"], c2.cookies["ssm_session"]
    assert t1 != t2 and len(t1) >= 40
    db = sqlite3.connect(Path(env.settings.data_dir) / "app" / "registry.db")
    dump = "\n".join(db.iterdump())
    assert t1 not in dump and t2 not in dump


def test_forged_cookie_rejected(env: Env) -> None:
    c = env.make_client()
    c.cookies.set("ssm_session", "A" * 43)
    assert c.get("/api/shares").status_code == 401


# --- expiry and revocation -----------------------------------------------------------


def test_idle_timeout(env: Env) -> None:
    c = env.make_client()
    login(c)
    env.clock.advance(8 * 3600 - 5)
    assert c.get("/api/shares").status_code == 200
    env.clock.advance(8 * 3600 + 1)
    assert c.get("/api/shares").status_code == 401


def test_absolute_timeout(env: Env) -> None:
    c = env.make_client()
    login(c)
    for _ in range(7 * 24 - 1):
        env.clock.advance(3600)
        assert c.get("/api/auth/status").json()["authenticated"] is True
    env.clock.advance(3601)
    assert c.get("/api/shares").status_code == 401


def test_logout_revokes(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    cookie = c.cookies["ssm_session"]
    assert call(c, "POST", "/api/auth/logout", csrf).status_code == 200
    c2 = env.make_client()
    c2.cookies.set("ssm_session", cookie)
    assert c2.get("/api/shares").status_code == 401


def test_password_change_revokes_sessions(env: Env) -> None:
    c = env.make_client()
    login(c)
    cookie = c.cookies["ssm_session"]
    c2 = env.make_client(make_settings(env.tmp, env.volume, admin_password="a brand new password"))
    c2.cookies.set("ssm_session", cookie)
    assert c2.get("/api/shares").status_code == 401


# --- CSRF / Origin / Host ------------------------------------------------------------

NEW_USER = {"username": "alice", "password": "alice password 1", "display_name": "Alice"}


def test_csrf_missing_wrong_and_cross_origin(authed: tuple, env: Env) -> None:  # type: ignore[type-arg]
    c, csrf = authed
    assert c.post("/api/users", json=NEW_USER, headers={"Origin": ORIGIN}).status_code == 403
    bad = {"Origin": ORIGIN, "X-CSRF-Token": "x" * 43}
    assert c.post("/api/users", json=NEW_USER, headers=bad).status_code == 403
    evil = {"Origin": "http://evil.example", "X-CSRF-Token": csrf}
    assert c.post("/api/users", json=NEW_USER, headers=evil).status_code == 403
    assert c.post("/api/users", json=NEW_USER, headers={"X-CSRF-Token": csrf}).status_code == 403
    assert "alice" not in env.helper.users
    ok = {"Referer": ORIGIN + "/users", "X-CSRF-Token": csrf}
    assert c.post("/api/users", json=NEW_USER, headers=ok).status_code == 201
    assert "alice" in env.helper.users


def test_csrf_token_in_form_field_not_accepted(authed: tuple, env: Env) -> None:  # type: ignore[type-arg]
    # Only a header is accepted, which a cross-site form cannot set.
    c, csrf = authed
    r = c.post("/api/users", data={**NEW_USER, "csrf_token": csrf}, headers={"Origin": ORIGIN})
    assert r.status_code == 403


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("testserver", True),
        ("192.168.68.10:8095", True),
        ("[fd7a:115c:a1e0::1]:8095", True),
        ("localhost:8095", True),
        ("evil.example", False),
        ("nuc.evil.example", False),
        ("192.168.68.10.nip.io", False),
    ],
)
def test_host_allowlist(env: Env, host: str, ok: bool) -> None:
    r = env.make_client().get("/api/auth/status", headers={"Host": host})
    assert (r.status_code == 200) is ok


# --- throttle ------------------------------------------------------------------------


def test_throttle_backoff_grows_and_caps() -> None:
    t = auth.LoginThrottle(max_entries=100, base=1.0, cap=900.0)
    delays = []
    for _ in range(15):
        t.record_failure("1.2.3.4", 1000.0)
        delays.append(t.retry_after("1.2.3.4", 1000.0))
    assert delays[0] >= 1.0
    assert all(b >= a for a, b in itertools.pairwise(delays))
    assert delays[4] >= 16.0 and max(delays) == 900.0
    assert t.retry_after("5.6.7.8", 1000.0) == 0.0
    t.record_success("1.2.3.4")
    assert t.retry_after("1.2.3.4", 1000.0) == 0.0


def test_throttle_memory_bounded() -> None:
    t = auth.LoginThrottle(max_entries=1000)
    for i in range(5000):
        t.record_failure(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", 0.0)
    assert len(t) <= 1000


def test_login_throttled(env: Env) -> None:
    c = env.make_client(client=("192.168.68.50", 5000))
    for _ in range(3):
        _login_raw(c, "nope nope nope")
    r = _login_raw(c, PASSWORD)
    assert r.status_code == 429
    assert "ssm_session" not in r.cookies


def test_xff_ignored_without_trusted_proxy(env: Env) -> None:
    c = env.make_client(client=("192.168.68.50", 5000))
    for i in range(3):
        _login_raw(c, "nope nope nope", xff=f"10.9.9.{i}")
    assert _login_raw(c, PASSWORD, xff="10.9.9.99").status_code == 429


def test_xff_honoured_from_trusted_proxy(env: Env) -> None:
    s = make_settings(env.tmp, env.volume, trusted_proxies=["192.168.68.2"])
    c = env.make_client(s, client=("192.168.68.2", 5000))
    for _ in range(3):
        _login_raw(c, "nope nope nope", xff="10.9.9.1")
    assert _login_raw(c, PASSWORD, xff="10.9.9.2").status_code == 200


def test_client_ip_resolution() -> None:
    assert auth.client_ip("1.1.1.1", "9.9.9.9", []) == "1.1.1.1"
    assert auth.client_ip("10.0.0.1", "9.9.9.9", ["10.0.0.0/8"]) == "9.9.9.9"
    assert auth.client_ip("10.0.0.1", "8.8.8.8, 9.9.9.9", ["10.0.0.0/8"]) == "9.9.9.9"
    assert auth.client_ip("10.0.0.1", "garbage", ["10.0.0.0/8"]) == "10.0.0.1"
    assert auth.client_ip("10.0.0.1", None, ["10.0.0.0/8"]) == "10.0.0.1"


# --- audit (requirement 11, login part) -----------------------------------------------


def test_login_audit_events_never_contain_password(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    c = env.make_client(client=("192.168.68.51", 1))
    _login_raw(c, "wrong secret 999")
    env.clock.advance(3600)
    login(c)
    out = capsys.readouterr().out
    events = [json.loads(ln) for ln in out.splitlines() if ln.startswith("{")]
    kinds = [e["event"] for e in events]
    assert "login_failed" in kinds and "login_ok" in kinds
    assert all(e.get("peer") == "192.168.68.51" for e in events if e["event"].startswith("login"))
    assert "wrong secret 999" not in out and PASSWORD not in out


def test_settings_repr_hides_password(env: Env) -> None:
    assert PASSWORD not in repr(env.settings)
    assert isinstance(env.settings, Settings)
