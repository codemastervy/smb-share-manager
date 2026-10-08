"""Real-browser test (Chromium via Playwright) of the React UI against the container.

HTTP-client tests cannot catch browser behaviour: the Origin header a request really
carries, CSP violations, event ordering (e.g. a double-click landing on the wrong row).
This walks the main flows the way an admin does and fails on any console error.
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
# Not skipped silently in CI: the browser test is part of the required checks.
from playwright import sync_api  # noqa: E402

PASSWORD = os.environ["SSM_PASSWORD"]
PORT = os.environ.get("SSM_SMB_PORT", "445")
USER, USER_PW = "browseruser", "browser-user-pw-1"


@pytest.fixture(scope="module")
def page() -> Iterator[Any]:
    with sync_api.sync_playwright() as pw:
        browser = pw.chromium.launch()
        pg = browser.new_page(viewport={"width": 1280, "height": 860}, accept_downloads=True)
        problems: list[str] = []
        pg.on(
            "console",
            lambda m: problems.append(m.text) if m.type in ("error", "warning") else None,
        )
        pg.on("pageerror", lambda e: problems.append(str(e)))
        pg.problems = problems  # type: ignore[attr-defined]
        yield pg
        browser.close()


def test_ui_flows(page: Any) -> None:
    pg = page
    pg.goto(URL + "/")
    pg.fill("#pw", PASSWORD)
    pg.click("button[type=submit]")
    pg.wait_for_selector("text=Drives")

    # SMB user
    pg.click("text=Users")
    pg.click("button:has-text('Add user')")
    pg.fill("#u-name", USER)
    pg.fill("#u-pass", USER_PW)
    pg.click(".modal button:has-text('Create user')")
    pg.wait_for_selector("text=User created")

    # Folder, upload, download
    pg.click("text=Files")
    pg.click(".grid .card")
    pg.wait_for_selector("button:has-text('New folder')")
    pg.click("button:has-text('New folder')")
    pg.fill("#name-input", "browser-share")
    pg.click(".modal button:has-text('Create')")
    pg.wait_for_selector(".file-row:has-text('browser-share')")
    pg.locator(".file-row", has_text="browser-share").first.dblclick()
    pg.wait_for_selector("text=This folder is empty")
    assert pg.url.endswith("/browser-share")  # double-click opened the right folder

    pg.set_input_files(
        "input[type=file]",
        files=[
            {"name": "page.html", "mimeType": "text/html", "buffer": b"<script>alert(1)</script>"}
        ],
    )
    pg.wait_for_selector(".file-row:has-text('page.html')")
    before = pg.url
    with pg.expect_download() as dl:
        pg.click(".file-row:has-text('page.html') .name button")
    assert dl.value.suggested_filename == "page.html"
    assert pg.url == before  # downloaded, never opened in the page

    # Share via the right-click menu
    pg.click("button.crumb:has-text('files')")
    pg.wait_for_selector(".file-row:has-text('browser-share')")
    pg.locator(".file-row", has_text="browser-share").first.click(button="right")
    pg.click("text=Share via SMB…")
    pg.fill("#share-name", "BrowserShare")
    pg.click(f".modal label.check:has-text('{USER}')")
    pg.click("button:has-text('Share folder')")
    pg.wait_for_selector("text=Sharing “BrowserShare”")

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

    # Unshare from the Shares page
    pg.click("text=Shares")
    pg.wait_for_selector("td:has-text('BrowserShare')")
    pg.click("tr:has-text('BrowserShare') button:has-text('Unshare')")
    pg.click(".modal button:has-text('Unshare')")
    pg.wait_for_selector("text=is no longer shared")

    pg.click("text=Sign out")
    pg.wait_for_selector("#pw")
    assert pg.problems == []  # type: ignore[attr-defined]  # no CSP violations or JS errors
