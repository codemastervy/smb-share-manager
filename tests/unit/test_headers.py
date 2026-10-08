"""Requirement 1: security headers everywhere; user files are never rendered."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import Env, login

FRONTEND_SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"


def assert_security_headers(h: object) -> None:
    headers = {k.lower(): v for k, v in h.items()}  # type: ignore[attr-defined]
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp or "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    # Not no-referrer: browsers then send "Origin: null" and every POST would fail.
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert "permissions-policy" in headers
    assert "server" not in headers


@pytest.mark.parametrize(
    "url", ["/", "/files", "/healthz", "/api/auth/status", "/api/shares", "/assets/index-abc.js"]
)
def test_headers_unauthenticated(env: Env, url: str) -> None:
    assert_security_headers(env.make_client().get(url).headers)


def test_app_csp_is_strict(env: Env) -> None:
    csp = env.make_client().get("/").headers["content-security-policy"]
    assert "script-src 'self'" in csp and "style-src 'self'" in csp
    assert "object-src 'none'" in csp and "base-uri 'none'" in csp


def test_headers_authenticated_api(env: Env) -> None:
    c = env.make_client()
    login(c)
    for url in ["/api/shares", "/api/users", "/api/files/volumes", "/api/info", "/api/import",
                "/api/nope"]:
        assert_security_headers(c.get(url).headers)


def test_headers_on_bad_host(env: Env) -> None:
    r = env.make_client().get("/", headers={"Host": "evil.example"})
    assert r.status_code == 400
    assert_security_headers(r.headers)


@pytest.mark.parametrize(
    ("fname", "content"),
    [
        ("evil.html", b"<html><script>alert(1)</script></html>"),
        ("evil.svg", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'),
        ("evil.txt", b"<script>alert(1)</script>"),
        ("noext", b"%PDF-1.4"),
    ],
)
def test_download_is_attachment_never_rendered(env: Env, fname: str, content: bytes) -> None:
    (env.volume / fname).write_bytes(content)
    c = env.make_client()
    login(c)
    for extra in ({}, {"inline": "true"}):
        r = c.get("/api/files/download", params={"path": f"/files/{fname}", **extra})
        assert r.status_code == 200 and r.content == content
        assert r.headers["content-disposition"].startswith("attachment;")
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.headers["x-content-type-options"] == "nosniff"
        csp = r.headers["content-security-policy"]
        assert "sandbox" in csp and "default-src 'none'" in csp


def test_download_filename_header_safe(env: Env) -> None:
    name = 'we"ird; name=x.html'
    (env.volume / name).write_bytes(b"x")
    c = env.make_client()
    login(c)
    r = c.get("/api/files/download", params={"path": f"/files/{name}"})
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment;")
    assert '"' not in cd.split("filename*=", 1)[-1]
    assert "\n" not in cd and "\r" not in cd


def test_frontend_never_renders_user_files() -> None:
    """The SPA has no preview: no img/video/audio/iframe/object pointing at file contents,
    no inline=true downloads, no dangerouslySetInnerHTML."""
    for p in FRONTEND_SRC.rglob("*.tsx"):
        text = p.read_text()
        assert "dangerouslySetInnerHTML" not in text, p.name
        assert "inline=true" not in text and "inline = true" not in text, p.name
        assert not re.search(r"<(img|video|audio|iframe|object|embed)\b", text), p.name
    for p in FRONTEND_SRC.rglob("*.ts"):
        assert "inline" not in p.read_text().split("downloadUrl", 1)[-1][:200], p.name


def test_built_index_has_no_inline_script(env: Env) -> None:
    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist" / "index.html"
    if not dist.exists():
        pytest.skip("frontend not built (CI builds it before this test)")
    html = dist.read_text()
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.S):
        assert "src=" in m.group(1) and not m.group(2).strip(), "inline script in index.html"
    assert "<style" not in html and " style=" not in html
    assert not re.search(r"(src|href)=\"(https?:)?//", html), "external resource in index.html"
