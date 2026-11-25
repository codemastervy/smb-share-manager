"""README screenshots: runs the real admin app with demo data (the test suite's fake root
helper, so nothing touches Samba or the system) and captures every page in light and dark
mode with headless Chromium.

    cd frontend && npm run build && cd ..
    uv run playwright install chromium-headless-shell
    uv run python scripts/screenshots.py            # writes docs/screenshots/*.png
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "docs" / "screenshots"
sys.path.insert(0, str(repo))
os.chdir(repo)

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402
from tests.conftest import make_settings  # noqa: E402
from tests.fakes import FakeHelper  # noqa: E402

from ssm.dav.acl import AclStore  # noqa: E402
from ssm.portal.app import build_asgi  # noqa: E402
from ssm.portal.settings import PortalSettings  # noqa: E402
from ssm.web.app import create_app  # noqa: E402

PORTAL_SECRET = "demo-portal-secret-" + "0" * 32

PW = "demo-admin-password"
tmp = Path(tempfile.mkdtemp()).resolve()  # the portal wants canonical share paths
vol = tmp / "files"
for d in [
    "Family/Photos 2026",
    "Family/Recipes",
    "Family/School",
    "Isherveer/Projects",
    "Jagdev/Documents",
    "Media/Movies",
    "Media/Music",
    "Backups",
]:
    (vol / d).mkdir(parents=True)
files = {
    "Family/Photos 2026/Beach day.jpg": 2_400_000,
    "Family/Photos 2026/Birthday cake.jpg": 1_900_000,
    "Family/Photos 2026/Garden.heic": 3_100_000,
    "Family/Recipes/Butter chicken.pdf": 180_000,
    "Family/Recipes/Dal makhani.docx": 42_000,
    "Family/School/Term 4 report.pdf": 260_000,
    "Family/Shopping list.txt": 600,
    "Family/House budget 2026.xlsx": 88_000,
    "Isherveer/Projects/rov-notes.md": 9_000,
    "Media/Music/Playlist.m3u": 1_200,
}
for rel, size in files.items():
    (vol / rel).write_bytes(b"\0" * size)
(tmp / "data").mkdir()
(tmp / "bridge").mkdir()
settings = make_settings(
    tmp,
    vol,
    admin_password=PW,
    allowed_hosts=["nas.home"],
    frontend_dir=str(repo / "frontend" / "dist"),
    max_upload_bytes=4096 * 1024 * 1024,
    version="2026.11.25",
    build_date="2026-11-25",
    dav_bridge_dir=str(tmp / "bridge"),
)
helper = FakeHelper()
helper.import_dir = settings.import_dir
app = create_app(settings, helper=helper)
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=18095, log_level="warning"))
threading.Thread(target=server.run, daemon=True).start()
URL = "http://127.0.0.1:18095"
for _ in range(50):
    try:
        httpx.get(URL + "/healthz")
        break
    except httpx.HTTPError:
        time.sleep(0.1)

c = httpx.Client(base_url=URL)
pre = c.get("/api/auth/status").json()["csrf"]
r = c.post("/api/auth/login", json={"password": PW}, headers={"Origin": URL, "X-CSRF-Token": pre})
H = {"Origin": URL, "X-CSRF-Token": r.json()["csrf"]}


def ok(method: str, path: str, body: object = None) -> None:
    r = c.request(method, path, json=body, headers=H)
    if r.status_code >= 300:
        raise SystemExit(f"{method} {path}: {r.status_code} {r.text}")


for name, disp, remote in [
    ("isherveer", "Isherveer", True),
    ("jagdev", "Jagdev", True),
    ("simran", "Simran", False),
    ("livingroom-tv", "Living room TV", False),
]:
    ok(
        "POST",
        "/api/users",
        {"username": name, "password": f"{name}-Demo-Passw0rd!", "display_name": disp},
    )
    if remote:
        ok("PATCH", f"/api/users/{name}", {"remote_access": True, "email": f"{name}@example.org"})
ok(
    "POST",
    "/api/shares",
    {
        "name": "Family",
        "path": "/files/Family",
        "comment": "Shared family folder",
        "members": [
            {"username": "isherveer", "access": "rw"},
            {"username": "jagdev", "access": "rw"},
            {"username": "simran", "access": "rw"},
        ],
    },
)
ok(
    "POST",
    "/api/shares",
    {
        "name": "Isherveer",
        "path": "/files/Isherveer",
        "members": [{"username": "isherveer", "access": "rw"}],
    },
)
ok(
    "POST",
    "/api/shares",
    {
        "name": "Media",
        "path": "/files/Media",
        "comment": "Movies and music",
        "members": [
            {"username": "isherveer", "access": "rw"},
            {"username": "livingroom-tv", "access": "ro"},
        ],
        "all_users": "ro",
    },
)

out.mkdir(parents=True, exist_ok=True)
REAL = os.path.realpath(vol)
JS = """(real) => { const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n; while ((n = w.nextNode())) { if (n.nodeValue.includes(real))
    n.nodeValue = n.nodeValue.split(real).join('/mnt/files'); }
  document.querySelectorAll('[title]').forEach(e => { if (e.title.includes(real))
    e.title = e.title.split(real).join('/mnt/files'); }); }"""


def snap(pg, name):
    pg.evaluate(JS, REAL)
    pg.screenshot(path=str(out / name))


with sync_playwright() as pw:
    browser = pw.chromium.launch(
        args=["--host-resolver-rules=MAP nas.home 127.0.0.1, MAP files.example.org 127.0.0.1"]
    )
    U = "http://nas.home:18095"
    for scheme in ("dark", "light"):
        pg = browser.new_page(viewport={"width": 1280, "height": 800}, device_scale_factor=2)
        sfx = "" if scheme == "dark" else "-light"
        main = scheme == "dark"
        pg.goto(U + "/")
        pg.wait_for_selector("#pw")
        if main:
            snap(pg, "login.png")
        pg.fill("#pw", PW)
        pg.click("button[type=submit]")
        pg.wait_for_selector("text=Drives")
        toggle = "text=Light mode" if scheme == "light" else "text=Dark mode"
        if pg.locator(toggle).count():
            pg.click(toggle)
        pg.wait_for_timeout(400)
        snap(pg, f"drives{sfx}.png")
        pg.goto(U + "/files/files/Family")
        pg.wait_for_selector(".file-row:has-text('Recipes')")
        pg.wait_for_timeout(300)
        snap(pg, f"files{sfx}.png")
        pg.goto(U + "/files/files")
        pg.wait_for_selector(".file-row:has-text('Backups')")
        pg.locator(".file-row", has_text="Backups").first.click(button="right")
        pg.wait_for_timeout(300)
        snap(pg, f"context-menu{sfx}.png")
        pg.click("text=Share via SMB…")
        pg.wait_for_selector("#share-name")
        pg.fill("#share-name", "Backups")
        pg.click(".modal label.check:has-text('isherveer')")
        pg.wait_for_timeout(300)
        snap(pg, f"share-dialog{sfx}.png")
        pg.keyboard.press("Escape")
        pg.goto(U + "/shares")
        pg.wait_for_selector("td:has-text('Family')")
        pg.wait_for_timeout(300)
        snap(pg, f"shares{sfx}.png")
        pg.goto(U + "/users")
        pg.wait_for_selector("td:has-text('jagdev')")
        pg.wait_for_timeout(300)
        snap(pg, f"users{sfx}.png")
        pg.locator("tr", has_text="simran").locator("button").first.click()
        pg.wait_for_selector(".modal")
        pg.wait_for_timeout(300)
        snap(pg, f"remote-access{sfx}.png")
        pg.close()

    # --- files portal (as Pangolin would send it: trusted peer, secret, Remote-Email) ----
    psettings = PortalSettings(
        hosts=["files.example.org"],
        exposed_shares=["Family", "Isherveer", "Media"],
        volumes=[str(vol)],
        trusted_proxies=["127.0.0.1/32"],
        proxy_secret=PORTAL_SECRET,
        header_verified=True,
        frontend_dir=str(repo / "frontend" / "dist"),
        bridge_dir=str(tmp / "bridge"),
    )
    store = AclStore(
        str(tmp / "bridge" / "acl.json"),
        psettings.exposed_shares,
        [str(vol)],
        is_mountpoint=lambda p: True,
    )
    pserver = uvicorn.Server(
        uvicorn.Config(
            build_asgi(psettings, store), host="127.0.0.1", port=18096, log_level="warning"
        )
    )
    threading.Thread(target=pserver.run, daemon=True).start()
    time.sleep(1)
    P = "http://files.example.org:18096"
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Portal-Proxy-Secret": PORTAL_SECRET,
        "Remote-Email": "isherveer@example.org",
    }
    for scheme in ("dark", "light"):
        sfx = "" if scheme == "dark" else "-light"
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 800},
            device_scale_factor=2,
            extra_http_headers=headers,
        )
        ctx.add_init_script(f"localStorage.setItem('ssm-theme', '{scheme}')")
        pg = ctx.new_page()
        pg.goto(P + "/")
        pg.wait_for_selector(".share-card")
        pg.wait_for_timeout(300)
        snap(pg, f"portal-home{sfx}.png")
        pg.goto(P + "/?p=%2FFamily")
        pg.wait_for_selector(".file-row:has-text('Recipes')")
        pg.wait_for_timeout(300)
        snap(pg, f"portal-folder{sfx}.png")
        ctx.close()
    ctx = browser.new_context(
        viewport={"width": 390, "height": 844},
        device_scale_factor=3,
        extra_http_headers=headers,
        is_mobile=True,
        has_touch=True,
    )
    ctx.add_init_script("localStorage.setItem('ssm-theme', 'dark')")
    pg = ctx.new_page()
    pg.goto(P + "/?p=%2FFamily%2FPhotos%202026")
    pg.wait_for_selector(".file-row:has-text('Beach')")
    pg.wait_for_timeout(300)
    snap(pg, "portal-phone.png")
    ctx.close()
    pserver.should_exit = True
    browser.close()
server.should_exit = True
print("done", sorted(p.name for p in out.iterdir()))
