"""Files portal against the built image: container hardening, setup mode, the proxy secret
and identity rules, ro/rw, a round trip with SMB, and that its uid can't use the helper's
password-check socket.

Every request reaches the container from the Docker gateway (inside PORTAL_TRUSTED_PROXIES
in CI) and carries the proxy secret and identity header the way Pangolin would.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from typing import Any

import httpx
import pytest
from tests.integration.test_container import Admin, dexec, smbclient, wait_healthy

pytestmark = pytest.mark.integration

PORTAL = os.environ.get("SSM_PORTAL_URL", "")
if not PORTAL:
    pytest.skip("portal integration environment not configured", allow_module_level=True)

SECRET = os.environ["SSM_PORTAL_SECRET"]
HOST = os.environ.get("SSM_PORTAL_HOST", "files.ci.test")
CONTAINER = os.environ.get("SSM_PORTAL_CONTAINER", "smb-portal")
COMPOSE = shlex.split(os.environ.get("SSM_COMPOSE", "docker compose"))
FS = os.environ.get("SSM_FS", "ext4")
PPW = {
    "prw": "portal-rw-password-0123456789",
    "pro": "portal-ro-password-0123456789",
    "pnr": "portal-nr-password-0123456789",
}


def preq(
    method: str,
    path: str,
    email: str | None = "prw@ci.test",
    secret: str | None = SECRET,
    change: bool = False,
    **kw: Any,
) -> httpx.Response:
    headers = {"Host": HOST, "X-Forwarded-Proto": "https"}
    if secret is not None:
        headers["X-Portal-Proxy-Secret"] = secret
    if email is not None:
        headers["Remote-Email"] = email
    if change:
        headers.update({"X-SSM-Portal": "1", "Origin": f"https://{HOST}"})
    headers.update(kw.pop("headers", {}))
    with httpx.Client(timeout=60) as c:
        return c.request(method, PORTAL + path, headers=headers, **kw)


def health() -> str:
    p = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Health.Status}}", CONTAINER],
        capture_output=True,
        text=True,
        check=False,
    )
    return p.stdout.strip()


def wait_portal_healthy(timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if health() == "healthy":
            return
        time.sleep(2)
    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True)
    raise AssertionError(f"{CONTAINER} not healthy:\n{(logs.stdout + logs.stderr)[-4000:]}")


def restart_portal(**env: str) -> None:
    subprocess.run(
        [*COMPOSE, "up", "-d", "--no-deps", "--force-recreate", "smb-portal"],
        check=True,
        timeout=180,
        env={**os.environ, **env},
    )
    wait_portal_healthy()


def pexec(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", CONTAINER, *args], capture_output=True, text=True, check=False
    )


@pytest.fixture(scope="module")
def psetup() -> Admin:
    wait_healthy()
    admin = Admin()
    for name, pw in PPW.items():
        admin.ok(
            "POST",
            "/api/users",
            {"username": name, "password": pw, "display_name": "", "email": f"{name}@ci.test"},
        )
    for name in ("prw", "pro"):
        admin.ok("PATCH", f"/api/users/{name}", {"remote_access": True})
    admin.ok(
        "POST",
        "/api/shares",
        {
            "name": "Portal",
            "path": "/files/portal",
            "members": [
                {"username": "prw", "access": "rw"},
                {"username": "pro", "access": "ro"},
                {"username": "pnr", "access": "rw"},
            ],
        },
    )
    wait_portal_healthy()
    return admin


def test_portal_container_hardening(psetup: Admin) -> None:
    info = json.loads(
        subprocess.run(
            ["docker", "inspect", CONTAINER], capture_output=True, text=True, check=True
        ).stdout
    )[0]
    hc = info["HostConfig"]
    assert hc["ReadonlyRootfs"] is True
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert any("no-new-privileges" in o for o in hc.get("SecurityOpt") or [])
    assert info["Config"]["User"] == "2998:3000"
    status = pexec("cat", "/proc/1/status").stdout
    assert re.search(r"^CapEff:\s+0+$", status, re.M), status
    assert re.search(r"^NoNewPrivs:\s+1$", status, re.M), status
    for p in ("/data", "/mnt/timenest", "/run/ssm", "/import", "/mnt/files/dav-rw"):
        assert pexec("test", "-e", p).returncode != 0, p
    assert pexec("touch", "/run/ssm-dav/x").returncode != 0  # bridge mounted read-only
    assert pexec("touch", "/opt/x").returncode != 0
    assert "ADMIN_PASSWORD" not in pexec("env").stdout
    assert "PORTAL_PROXY_SECRET" in pexec("env").stdout


def test_portal_uid_cannot_check_passwords(psetup: Admin) -> None:
    # The verify socket answers DAV_UID only: the portal can't be turned into a password
    # oracle even if it were compromised.
    code = (
        "from ssm.helper_client import VerifyClient, HelperError\n"
        "try:\n"
        f"    print(VerifyClient('/run/ssm-dav/verify.sock').verify('prw', {PPW['prw']!r}))\n"
        "except (HelperError, OSError) as e:\n"
        "    print('refused', type(e).__name__)\n"
    )
    out = pexec("/opt/venv/bin/python", "-c", code)
    assert "True" not in out.stdout, out.stdout + out.stderr


def test_setup_mode_until_verified(psetup: Admin) -> None:
    assert preq("GET", "/api/portal/me").status_code == 503
    r = preq("GET", "/api/portal/probe", headers={"Remote-Email": "spoof@example.invalid"})
    assert r.status_code == 200 and r.json()["values"] == ["spoof@example.invalid"]
    assert preq("GET", "/").status_code == 503


def test_enable_and_identity_rules(psetup: Admin) -> None:
    restart_portal(PORTAL_HEADER_VERIFIED="true")
    r = preq("GET", "/api/portal/me")
    assert r.status_code == 200, r.text
    # DavRO is exposed but its folder isn't mounted into smb-portal: never served.
    assert [s["name"] for s in r.json()["shares"]] == ["Portal"]
    assert preq("GET", "/api/portal/probe").status_code == 404
    assert preq("GET", "/api/portal/me", secret="wrong-" + "x" * 40).status_code == 403
    assert preq("GET", "/api/portal/me", secret=None).status_code == 403
    r = preq("GET", "/api/portal/me", headers={"X-Forwarded-Proto": "http"})
    assert r.status_code == 403
    assert preq("GET", "/api/portal/me", email="stranger@ci.test").status_code == 403
    assert preq("GET", "/api/portal/me", email="pnr@ci.test").status_code == 403
    assert preq("GET", "/api/portal/me", email=None).status_code == 401
    assert preq("GET", "/api/users").status_code == 404  # no admin API here
    page = preq("GET", "/")
    assert page.status_code == 200 and '<div id="root">' in page.text


def test_round_trip_with_smb(psetup: Admin) -> None:
    r = preq(
        "PUT",
        "/api/portal/upload",
        change=True,
        params={"path": "/Portal", "name": "from-portal.txt"},
        content=b"hello from the portal\n",
    )
    assert r.status_code == 201, r.text
    listing = preq("GET", "/api/portal/list", params={"path": "/Portal"}).json()
    assert "from-portal.txt" in [e["name"] for e in listing["entries"]]
    d = preq("GET", "/api/portal/download", params={"path": "/Portal/from-portal.txt"})
    assert d.content == b"hello from the portal\n"
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["content-disposition"].startswith("attachment")
    rc, out = smbclient("Portal", "prw", PPW["prw"], "ls")
    assert rc == 0 and "from-portal.txt" in out, out
    if FS == "ext4":
        st = dexec("stat", "-c", "%u:%g %a", "/mnt/files/portal/from-portal.txt").split()
        assert st == ["2998:3000", "664"], st  # group smbusers may edit it over SMB


def test_read_only_and_csrf(psetup: Admin) -> None:
    r = preq(
        "PUT",
        "/api/portal/upload",
        email="pro@ci.test",
        change=True,
        params={"path": "/Portal", "name": "nope.txt"},
        content=b"x",
    )
    assert r.status_code == 403
    r = preq("POST", "/api/portal/mkdir", json={"path": "/Portal", "name": "X"})
    assert r.status_code == 403  # no CSRF header
    r = preq(
        "POST",
        "/api/portal/mkdir",
        change=True,
        headers={"Origin": "https://evil.example"},
        json={"path": "/Portal", "name": "X"},
    )
    assert r.status_code == 403
    names = [e["name"] for e in preq("GET", "/api/portal/list?path=/Portal").json()["entries"]]
    assert "nope.txt" not in names and "X" not in names


def test_admin_changes_apply_next_request(psetup: Admin) -> None:
    assert preq("GET", "/api/portal/me").status_code == 200
    psetup.ok("PATCH", "/api/users/prw", {"remote_access": False})
    try:
        deadline = time.time() + 10
        while time.time() < deadline and preq("GET", "/api/portal/me").status_code == 200:
            time.sleep(0.2)
        assert preq("GET", "/api/portal/me").status_code == 403
    finally:
        psetup.ok("PATCH", "/api/users/prw", {"remote_access": True})
    psetup.ok("PATCH", "/api/users/prw", {"email": "new-address@ci.test"})
    try:
        assert preq("GET", "/api/portal/me").status_code == 403
        assert preq("GET", "/api/portal/me", email="new-address@ci.test").status_code == 200
    finally:
        psetup.ok("PATCH", "/api/users/prw", {"email": "prw@ci.test"})
