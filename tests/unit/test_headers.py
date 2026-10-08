"""Requirement 1: security headers everywhere; user files are never rendered."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import Env, login

TEMPLATES = Path(__file__).resolve().parents[2] / "src" / "ssm" / "web" / "templates"


def assert_security_headers(h: object) -> None:
    headers = {k.lower(): v for k, v in h.items()}  # type: ignore[attr-defined]
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "script-src 'self'" in csp
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    # Must not be no-referrer: browsers then send "Origin: null" and every POST fails.
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert "permissions-policy" in headers
    assert "server" not in headers or "uvicorn" not in headers["server"].lower()


@pytest.mark.parametrize("url", ["/login", "/healthz", "/nope", "/static/app.css", "/shares"])
def test_headers_unauthenticated(env: Env, url: str) -> None:
    r = env.make_client().get(url)
    assert_security_headers(r.headers)


def test_headers_authenticated_pages(env: Env) -> None:
    c = env.make_client()
    login(c)
    for url in ["/shares", "/shares/new", "/users", "/browse", "/config", "/import", "/missing"]:
        r = c.get(url)
        assert_security_headers(r.headers)


def test_headers_on_bad_host(env: Env) -> None:
    r = env.make_client().get("/login", headers={"Host": "evil.example"})
    assert r.status_code == 400
    assert_security_headers(r.headers)


@pytest.mark.parametrize(
    "fname,content",
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
    r = c.get("/browse/download", params={"path": str(env.volume / fname)})
    assert r.status_code == 200
    assert r.content == content
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment;")
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_download_filename_header_safe(env: Env) -> None:
    name = 'we"ird; name=x.html'
    (env.volume / name).write_bytes(b"x")
    c = env.make_client()
    login(c)
    r = c.get("/browse/download", params={"path": str(env.volume / name)})
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment;")
    assert '"' not in cd.split("filename*=", 1)[-1]
    assert "\n" not in cd and "\r" not in cd


def test_templates_have_no_inline_script_or_style() -> None:
    for t in TEMPLATES.glob("*.html"):
        text = t.read_text()
        for m in re.finditer(r"<script\b([^>]*)>", text):
            assert "src=" in m.group(1), f"inline script in {t.name}"
        assert "<style" not in text, f"inline style block in {t.name}"
        assert not re.search(r"\son[a-z]+\s*=", text), f"inline event handler in {t.name}"
        assert "style=" not in text, f"inline style attribute in {t.name}"
        assert "hx-on" not in text, f"hx-on (eval) in {t.name}"
        assert "|safe" not in text, f"|safe filter in {t.name}"


def test_htmx_configured_without_eval() -> None:
    base = (TEMPLATES / "base.html").read_text()
    assert '"allowEval":false' in base.replace(" ", "")
    assert '"includeIndicatorStyles":false' in base.replace(" ", "")


def test_autoescape_of_user_controlled_names(env: Env) -> None:
    (env.volume / "<img src=x onerror=alert(1)>").mkdir()
    c = env.make_client()
    login(c)
    r = c.get("/browse", params={"path": str(env.volume)})
    assert "<img src=x" not in r.text
    assert "&lt;img src=x" in r.text
