"""Real-browser test (Chromium via Playwright) against the running container.

HTTP-client tests cannot catch browser behaviour such as the Origin header a form POST
actually carries, htmx boosting, or CSP violations. This walks the main UI flows the way
an admin does.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from typing import Any

import pytest

pytestmark = pytest.mark.integration

URL = os.environ.get("SSM_URL", "")
if not URL:
    pytest.skip("integration environment not configured", allow_module_level=True)
sync_api = pytest.importorskip("playwright.sync_api")

PASSWORD = os.environ["SSM_PASSWORD"]
PORT = os.environ.get("SSM_SMB_PORT", "445")
VOL = "/mnt/files"
USER, USER_PW = "browseruser", "browser-user-pw-1"


@pytest.fixture(scope="module")
def page() -> Iterator[Any]:
    with sync_api.sync_playwright() as pw:
        browser = pw.chromium.launch()
        pg = browser.new_page()
        problems: list[str] = []
        pg.on(
            "console", lambda m: problems.append(m.text) if m.type in ("error", "warning") else None
        )
        pg.on("pageerror", lambda e: problems.append(str(e)))
        pg.on("dialog", lambda d: d.accept())
        pg.problems = problems  # type: ignore[attr-defined]
        yield pg
        browser.close()


def body(pg: Any) -> str:
    return str(pg.inner_text("body"))


def test_browser_flows(page: Any) -> None:
    pg = page
    pg.goto(URL + "/login")
    pg.fill("input[name=password]", PASSWORD)
    pg.click("button[type=submit]")
    pg.wait_for_url("**/shares")

    pg.goto(URL + "/users")
    pg.fill("form[action='/users'] input[name=name]", USER)
    pg.fill("form[action='/users'] input[name=password]", USER_PW)
    pg.fill("form[action='/users'] input[name=password2]", USER_PW)
    pg.click("form[action='/users'] button")
    pg.wait_for_url("**/users?msg=*")
    assert f"User {USER} created" in body(pg)

    pg.goto(f"{URL}/browse?path={VOL}")
    pg.fill("form[action='/browse/mkdir'] input[name=name]", "browser-share")
    pg.click("form[action='/browse/mkdir'] button")
    pg.wait_for_url("**msg=*")
    pg.goto(f"{URL}/browse?path={VOL}/browser-share")

    pg.set_input_files(
        "form.upload input[type=file]",
        files=[
            {"name": "page.html", "mimeType": "text/html", "buffer": b"<script>alert(1)</script>"}
        ],
    )
    pg.click("form.upload button")
    pg.wait_for_selector("text=page.html")
    assert "browse?path=" in pg.url  # stayed on the folder page

    with pg.expect_download() as dl:
        pg.click("a:has-text('page.html')")
    assert dl.value.suggested_filename == "page.html"
    assert "browse" in pg.url  # the HTML file was downloaded, not opened

    pg.click("text=Share this folder")
    pg.wait_for_url("**/shares/new*")
    pg.fill("input[name=name]", "BrowserShare")
    pg.check(f"input[name=access_{USER}][value=rw]")
    pg.click("button:has-text('Create share')")
    pg.wait_for_url("**/shares/BrowserShare/edit*")
    assert "Share BrowserShare created" in body(pg)

    p = subprocess.run(
        [
            "smbclient",
            "//127.0.0.1/BrowserShare",
            "-p",
            PORT,
            "-m",
            "SMB3",
            "-U",
            f"{USER}%{USER_PW}",
            "-c",
            "ls",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode == 0 and "page.html" in p.stdout, p.stdout + p.stderr

    pg.click("button:has-text('Remove share')")
    pg.wait_for_url("**/shares?msg=*")
    assert "removed" in body(pg)

    pg.click("button:has-text('Log out')")
    pg.wait_for_url("**/login")
    assert pg.problems == []  # type: ignore[attr-defined]  # no CSP violations or JS errors
