"""WebDAV integration tests against the real image (smb-dav container), started by
scripts/ci/integration.sh with COMPOSE_PROFILES=dav and DAV_EXPOSED_SHARES=DavRW,DavRO.

Passwords are checked by the real helper against real Samba NT hashes; litmus and rclone
run against the real cheroot server; the last tests restart the service with the
production default (HTTPS required) to test the proxy and throttle rules.

Environment (in addition to test_container.py's):
  SSM_DAV_URL        e.g. http://127.0.0.1:8094 (DAV_ALLOW_HTTP=true on loopback)
  SSM_DAV_CONTAINER  smb-dav
  SSM_DAV_SRC        host folder of the volume (for checks behind the service's back)
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.integration.test_container import Admin, dexec, smbclient, wait_healthy

pytestmark = pytest.mark.integration

DAV = os.environ.get("SSM_DAV_URL", "")
if not DAV:
    pytest.skip("WebDAV integration environment not configured", allow_module_level=True)

DAV_CONTAINER = os.environ.get("SSM_DAV_CONTAINER", "smb-dav")
COMPOSE = shlex.split(os.environ.get("SSM_COMPOSE", "docker compose"))
FS = os.environ.get("SSM_FS", "ext4")
VP = "/files"
DPW = {
    "davrw": "dav-rw-password-0123456789",
    "davro": "dav-ro-password-0123456789",
    "davnr": "dav-nr-password-0123456789",
}
# By design (overwrite rule): COPY/MOVE never replace an existing folder, nor put a folder
# over a file, so these litmus steps get 403. copy_shallow then fails only because
# copy_coll left its source folder behind (MKCOL 405); depth-0 copies are covered by the
# unit tests.
LITMUS_EXPECTED_FAIL = {
    "copymove": {"copy_overwrite", "copy_coll", "copy_shallow", "move", "move_coll"},
}
LITMUS_SUITES = ("basic", "copymove", "props", "locks", "http")


# --- helpers ----------------------------------------------------------------------------


def dav(
    method: str,
    path: str,
    user: str | None = "davrw",
    password: str | None = None,
    url: str = DAV,
    **kw: Any,
) -> httpx.Response:
    auth = None if user is None else (user, password if password is not None else DPW[user])
    headers = kw.pop("headers", {})
    if method == "PROPFIND":
        headers.setdefault("Depth", "1")
    with httpx.Client(timeout=60) as c:
        return c.request(method, url + path, auth=auth, headers=headers, **kw)


def wait_dav_healthy(timeout: float = 120) -> None:
    deadline = time.time() + timeout
    status = ""
    while time.time() < deadline:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", DAV_CONTAINER],
            capture_output=True,
            text=True,
            check=False,
        )
        status = p.stdout.strip()
        if status == "healthy":
            return
        time.sleep(2)
    logs = subprocess.run(
        ["docker", "logs", DAV_CONTAINER], capture_output=True, text=True, check=False
    )
    raise AssertionError(
        f"{DAV_CONTAINER} not healthy ({status}):\n{(logs.stdout + logs.stderr)[-4000:]}"
    )


def dav_exec(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", DAV_CONTAINER, *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def dav_logs() -> str:
    p = subprocess.run(
        ["docker", "logs", DAV_CONTAINER], capture_output=True, text=True, check=False
    )
    return p.stdout + p.stderr


def wait_until(fn: Any, timeout: float = 15) -> Any:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(0.5)
    return last


def settle() -> None:
    """In CI every request comes from the same Docker gateway address, so a deliberate
    failure puts that address into backoff (as it should). Wait it out: locked answers
    carry Retry-After; a successful login then resets the address."""
    for _ in range(60):
        r = dav("PROPFIND", "/")
        if "retry-after" not in r.headers:
            assert r.status_code == 207, (r.status_code, r.text[:200])
            return
        time.sleep(min(float(r.headers["retry-after"]), 5))
    raise AssertionError("still backing off")


@pytest.fixture(autouse=True)
def _settled(request: pytest.FixtureRequest) -> None:
    if "dsetup" in request.fixturenames and request.node.name not in (
        "test_https_required_by_default",
        "test_trusted_proxy_real_ip_and_lockout",
        "test_restore_ci_mode",
    ):
        request.getfixturevalue("dsetup")
        settle()


def hrefs(r: httpx.Response) -> list[str]:
    return re.findall(r"<(?:\w+:)?href>([^<]*)</(?:\w+:)?href>", r.text)


def restart_dav(**env: str) -> None:
    env.setdefault("DAV_AUTH_CACHE_S", "300")
    subprocess.run(
        [*COMPOSE, "up", "-d", "--no-deps", "--force-recreate", "smb-dav"],
        check=True,
        timeout=180,
        env={**os.environ, **env},
    )
    wait_dav_healthy()


# --- fixtures ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def admin() -> Admin:
    wait_healthy()
    return Admin()


@pytest.fixture(scope="module")
def dsetup(admin: Admin) -> dict[str, Any]:
    for name, pw in DPW.items():
        admin.ok("POST", "/api/users", {"username": name, "password": pw, "display_name": ""})
    for name in ("davrw", "davro"):
        admin.ok("PATCH", f"/api/users/{name}", {"remote_access": True})
    admin.ok(
        "POST",
        "/api/shares",
        {
            "name": "DavRW",
            "path": f"{VP}/dav-rw",
            "members": [
                {"username": "davrw", "access": "rw"},
                {"username": "davro", "access": "ro"},
                {"username": "davnr", "access": "rw"},
            ],
        },
    )
    admin.ok(
        "POST",
        "/api/shares",
        {
            "name": "DavRO",
            "path": f"{VP}/dav-ro",
            "members": [{"username": "davro", "access": "rw"}],
        },
    )
    wait_dav_healthy()
    ok = wait_until(lambda: dav("PROPFIND", "/").status_code == 207, 30)
    assert ok, dav_logs()[-3000:]
    return {}


# --- container ------------------------------------------------------------------------


def test_dav_container_hardening(dsetup: dict[str, Any]) -> None:
    info = json.loads(
        subprocess.run(
            ["docker", "inspect", DAV_CONTAINER], capture_output=True, text=True, check=True
        ).stdout
    )[0]
    hc = info["HostConfig"]
    assert hc["ReadonlyRootfs"] is True
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert any("no-new-privileges" in o for o in hc.get("SecurityOpt") or [])
    assert info["Config"]["User"] == "2999:3000"
    assert not hc.get("Privileged")
    status = dav_exec("cat", "/proc/1/status").stdout
    assert re.search(r"^CapEff:\s+0+$", status, re.M), status
    assert re.search(r"^CapPrm:\s+0+$", status, re.M), status
    assert re.search(r"^NoNewPrivs:\s+1$", status, re.M), status
    assert re.search(r"^Uid:\s+2999\s", status, re.M), status
    # Only the two exposed share folders, never the volume, ./data, the admin socket,
    # /import or /mnt/timenest.
    for p in ("/data", "/mnt/timenest", "/run/ssm", "/import", "/mnt/files/s1"):
        assert dav_exec("test", "-e", p).returncode != 0, p
    mounts = dav_exec("cat", "/proc/self/mountinfo").stdout
    targets = {line.split()[4] for line in mounts.splitlines()}
    assert "/mnt/files" not in targets
    assert {"/mnt/files/dav-rw", "/mnt/files/dav-ro"} <= targets
    # Writing outside tmpfs fails: read-only root filesystem.
    assert dav_exec("touch", "/opt/x").returncode != 0
    assert dav_exec("touch", "/run/ssm-dav/x").returncode != 0
    env = dav_exec("env").stdout
    assert "ADMIN_PASSWORD" not in env


def test_admin_routes_not_served(dsetup: dict[str, Any]) -> None:
    for path in ("/api/auth/status", "/api/users", "/healthz", "/", "/login", "/assets/x.js"):
        r = dav("GET", path, user=None)
        assert r.status_code in (401, 403), (path, r.status_code)
        assert "csrf" not in r.text and "<html" not in r.text.lower()
        r = dav("GET", path)
        assert r.status_code in (404, 405), (path, r.status_code)
        assert "csrf" not in r.text and "<html" not in r.text.lower()
        assert "text/html" not in r.headers.get("content-type", "")
    assert "version" not in dav("OPTIONS", "/").headers.get("server", "x").lower()
    assert not re.search(r"\d", dav("OPTIONS", "/").headers.get("server", ""))


# --- auth against real Samba hashes -------------------------------------------------------


def test_real_password_verification(dsetup: dict[str, Any]) -> None:
    r = dav("PROPFIND", "/")
    assert r.status_code == 207
    listed = hrefs(r)
    assert any(h.rstrip("/").endswith("/DavRW") for h in listed)
    assert not any("DavRO" in h for h in listed)  # not a member
    assert not any(h.rstrip("/").endswith("/S1") for h in listed)  # not exposed
    assert dav("PROPFIND", "/", password="wrong-password-123456").status_code == 401
    settle()
    # Correct SMB password, but no remote access.
    assert dav("PROPFIND", "/", user="davnr").status_code == 401
    settle()
    assert dav("PROPFIND", "/DavRO/").status_code == 404
    assert dav("PROPFIND", "/S1/").status_code == 404
    logs = dav_logs()
    assert '"reason": "not_remote"' in logs and '"user": "davnr"' in logs
    for pw in DPW.values():
        assert pw not in logs
    assert (
        pw
        not in subprocess.run(
            ["docker", "logs", "smb-share-manager"], capture_output=True, text=True, check=False
        ).stdout
    )


def test_read_only_member_cannot_write(dsetup: dict[str, Any]) -> None:
    assert dav("PUT", "/DavRW/by-rw.txt", content=b"rw").status_code == 201
    assert dav("GET", "/DavRW/by-rw.txt", user="davro").content == b"rw"
    for method, kw in [
        ("PUT", {"content": b"no"}),
        ("MKCOL", {}),
        ("DELETE", {}),
        ("PROPPATCH", {"content": b"<x/>"}),
    ]:
        r = dav(
            method, "/DavRW/by-rw.txt" if method != "MKCOL" else "/DavRW/newdir", user="davro", **kw
        )
        assert r.status_code == 403, (method, r.status_code)
    assert dav("GET", "/DavRW/by-rw.txt", user="davro").content == b"rw"
    assert dav("PUT", "/DavRO/mine.txt", user="davro", content=b"x").status_code == 201


def test_file_via_dav_visible_over_smb_and_back(dsetup: dict[str, Any]) -> None:
    body = os.urandom(200_000)
    assert dav("PUT", "/DavRW/blob.bin", content=body).status_code == 201
    with tempfile.TemporaryDirectory() as td:
        rc, out = smbclient("DavRW", "davrw", DPW["davrw"], f"lcd {td}; get blob.bin")
        assert rc == 0, out
        assert Path(td, "blob.bin").read_bytes() == body
        Path(td, "from-smb.txt").write_bytes(b"from smb")
        rc, out = smbclient("DavRW", "davrw", DPW["davrw"], f"lcd {td}; put from-smb.txt")
        assert rc == 0, out
    assert dav("GET", "/DavRW/from-smb.txt").content == b"from smb"
    # Created by the DAV uid, group smbusers, group-writable (ext4; exFAT has fixed modes).
    if FS == "ext4":
        st = dexec("stat", "-c", "%u:%g:%a", "/mnt/files/dav-rw/blob.bin").strip()
        uid, gid, mode = st.split(":")
        assert (uid, gid) == ("2999", "3000"), st
        assert int(mode, 8) & 0o060 == 0o060, st


def test_download_headers_and_range(dsetup: dict[str, Any]) -> None:
    html = b"<html><script>alert(1)</script></html>"
    assert dav("PUT", "/DavRW/evil.html", content=html).status_code == 201
    r = dav("GET", "/DavRW/evil.html")
    assert r.content == html
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]
    assert r.headers["content-disposition"].startswith("attachment")
    r = dav("GET", "/DavRW/evil.html", headers={"Range": "bytes=0-5"})
    assert r.status_code == 206 and r.content == html[:6]
    r = dav("GET", "/DavRW/")
    assert r.status_code == 405 and "<html" not in r.text.lower()


@pytest.mark.skipif(FS == "exfat", reason="exFAT has no symlinks")
def test_symlink_planted_on_disk_is_invisible(dsetup: dict[str, Any]) -> None:
    dexec("ln", "-s", "/etc", "/mnt/files/dav-rw/link-out")
    dexec("ln", "-s", "/mnt/files/s1", "/mnt/files/dav-rw/link-s1")
    try:
        names = hrefs(dav("PROPFIND", "/DavRW/"))
        assert not any("link-" in h for h in names)
        for p in ("/DavRW/link-out/passwd", "/DavRW/link-out", "/DavRW/link-s1/hello.txt"):
            assert dav("GET", p).status_code == 404, p
        assert dav("DELETE", "/DavRW/link-out").status_code == 404
        assert dav("PUT", "/DavRW/link-out/x", content=b"x").status_code in (404, 409)
    finally:
        dexec("rm", "-f", "/mnt/files/dav-rw/link-out", "/mnt/files/dav-rw/link-s1")


def test_traversal_and_foreign_destination(dsetup: dict[str, Any]) -> None:
    for raw in (
        "/DavRW/../DavRO/mine.txt",
        "/DavRW/%2e%2e/DavRO/mine.txt",
        "/DavRW/a%2fb",
        "/DavRW/a%00b",
    ):
        r = httpx.request("GET", DAV + raw, auth=("davrw", DPW["davrw"]))
        assert r.status_code in (400, 404), (raw, r.status_code)
    for dest in (
        "http://evil.example/DavRW/x.txt",
        f"{DAV}/DavRO/x.txt",
        f"{DAV}/S1/x.txt",
        f"{DAV}/DavRW/../DavRO/x.txt",
    ):
        r = dav("COPY", "/DavRW/by-rw.txt", headers={"Destination": dest})
        assert r.status_code in (400, 403, 404), (dest, r.status_code)


def test_depth_infinity_refused(dsetup: dict[str, Any]) -> None:
    assert dav("PROPFIND", "/DavRW/", headers={"Depth": "infinity"}).status_code == 403


def test_upload_limit(dsetup: dict[str, Any]) -> None:
    big = b"\0" * (65 * 1024 * 1024)  # DAV_MAX_UPLOAD_MB=64 in CI

    def chunks() -> Any:
        for _ in range(65):
            yield b"\0" * (1024 * 1024)

    for name, content in (("too-big.bin", big), ("too-big2.bin", chunks())):
        # The server answers 413 and may close the connection before the client has sent
        # everything; either outcome is a refusal.
        try:
            status = dav("PUT", f"/DavRW/{name}", content=content).status_code
        except httpx.TransportError:
            status = 413
        assert status == 413, name
    left = dexec("ls", "-A", "/mnt/files/dav-rw")
    assert "too-big" not in left and ".ssm-upload" not in left


# --- registry changes take effect on the next request ---------------------------------


def test_password_change_takes_effect_immediately(admin: Admin, dsetup: dict[str, Any]) -> None:
    assert dav("PROPFIND", "/").status_code == 207  # now cached
    new = "dav-rw-password-NEW-98765"
    admin.ok("PATCH", "/api/users/davrw", {"password": new})
    try:
        # The very next request with the old (cached) password is refused.
        assert dav("PROPFIND", "/").status_code == 401
        assert wait_until(lambda: dav("PROPFIND", "/", password=new).status_code == 207, 30)
    finally:
        admin.ok("PATCH", "/api/users/davrw", {"password": DPW["davrw"]})
    assert wait_until(lambda: dav("PROPFIND", "/").status_code == 207, 30)


def test_membership_and_remote_flag_changes(admin: Admin, dsetup: dict[str, Any]) -> None:
    assert dav("PROPFIND", "/DavRW/", user="davro").status_code == 207
    admin.ok(
        "PATCH",
        "/api/shares/DavRW",
        {"members": [{"username": "davrw", "access": "rw"}, {"username": "davnr", "access": "rw"}]},
    )
    assert dav("PROPFIND", "/DavRW/", user="davro").status_code == 404  # the next request
    admin.ok("PATCH", "/api/users/davro", {"remote_access": False})
    try:
        assert dav("PROPFIND", "/", user="davro").status_code == 401  # the next request
    finally:
        admin.ok("PATCH", "/api/users/davro", {"remote_access": True})
    settle()
    admin.ok(
        "PATCH",
        "/api/shares/DavRW",
        {
            "members": [
                {"username": "davrw", "access": "rw"},
                {"username": "davro", "access": "ro"},
                {"username": "davnr", "access": "rw"},
            ]
        },
    )
    assert wait_until(lambda: dav("PROPFIND", "/DavRW/", user="davro").status_code == 207, 30)


# --- standard clients -------------------------------------------------------------------


def test_litmus(dsetup: dict[str, Any]) -> None:
    if shutil.which("litmus") is None:
        pytest.skip("litmus not installed")
    problems = []
    # One suite per run: litmus's wrapper stops at the first suite with a failure.
    for suite in LITMUS_SUITES:
        root = f"/DavRW/litmus-{suite}"
        assert dav("MKCOL", root).status_code == 201
        p = subprocess.run(
            ["litmus", f"{DAV}{root}/", "davrw", DPW["davrw"]],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            env={**os.environ, "TESTS": suite},
        )
        out = p.stdout + p.stderr
        print(out)
        if not re.search(rf"<- summary for `{suite}'", out):
            problems.append(f"{suite}: no summary\n{out[-3000:]}")
            continue
        failed = set(re.findall(r"^\s*\d+\.\s+(\S+?)\.*\s*FAIL", out, re.M))
        unexpected = failed - LITMUS_EXPECTED_FAIL.get(suite, set())
        if unexpected:
            problems.append(f"{suite}: unexpected failures {sorted(unexpected)}\n{out[-4000:]}")
    assert not problems, "\n".join(problems)
    assert DPW["davrw"] not in dav_logs()


def test_rclone_smoke(dsetup: dict[str, Any]) -> None:
    if shutil.which("rclone") is None:
        pytest.skip("rclone not installed")
    obscured = subprocess.run(
        ["rclone", "obscure", "-"], input=DPW["davrw"], capture_output=True, text=True, check=True
    ).stdout.strip()
    env = {
        **os.environ,
        "RCLONE_CONFIG_D_TYPE": "webdav",
        "RCLONE_CONFIG_D_URL": DAV,
        "RCLONE_CONFIG_D_VENDOR": "other",
        "RCLONE_CONFIG_D_USER": "davrw",
        "RCLONE_CONFIG_D_PASS": obscured,
    }

    def rc(*args: str) -> str:
        p = subprocess.run(
            ["rclone", *args], capture_output=True, text=True, timeout=300, check=False, env=env
        )
        assert p.returncode == 0, (args, p.stdout + p.stderr)
        return p.stdout

    with tempfile.TemporaryDirectory() as td:
        src = Path(td, "src")
        (src / "sub dir").mkdir(parents=True)
        (src / "a.txt").write_bytes(b"alpha\n")
        (src / "Résumé ✓.txt").write_bytes(b"unicode name\n")
        (src / "sub dir" / "b.bin").write_bytes(os.urandom(3 * 1024 * 1024))
        rc("copy", str(src), "d:DavRW/rc")
        rc("check", "--download", str(src), "d:DavRW/rc")
        rc("moveto", "d:DavRW/rc/a.txt", "d:DavRW/rc/moved.txt")
        listing = rc("lsf", "-R", "d:DavRW/rc")
        assert "moved.txt" in listing and "a.txt\n" not in listing
        assert "Résumé ✓.txt" in listing
        rc("copyto", "d:DavRW/rc/moved.txt", "d:DavRW/rc/again.txt")
        rc("purge", "d:DavRW/rc")
        assert "rc/" not in rc("lsf", "d:DavRW")
        # Read-only member: rclone's upload is refused.
        env["RCLONE_CONFIG_D_USER"] = "davro"
        env["RCLONE_CONFIG_D_PASS"] = subprocess.run(
            ["rclone", "obscure", "-"],
            input=DPW["davro"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        p = subprocess.run(
            ["rclone", "copy", str(src), "d:DavRW/rc-ro", "--retries", "1"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=env,
        )
        assert p.returncode != 0
    assert dexec("test", "!", "-e", "/mnt/files/dav-rw/rc-ro") is not None


def test_smoke_script_dav(dsetup: dict[str, Any]) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "smoke-test.sh"
    env = {
        **os.environ,
        "SMB_USER": "davrw",
        "SMB_PASSWORD": DPW["davrw"],
        "SMB_SHARE": "DavRW",
        "DAV_URL": DAV,
        "CONTAINER": "smb-share-manager",
        "WEB_URL": os.environ["SSM_URL"],
    }
    p = subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True, timeout=120, check=False
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert "FAIL" not in p.stdout
    assert "WebDAV: davrw can list" in p.stdout
    assert "does not get the admin password" in p.stdout


# --- production mode: HTTPS required, proxies, real client IP, lockout -------------------
# Keep these last: they restart the service.

PROXY_NETS = "172.16.0.0/12,192.168.0.0/16,10.0.0.0/8"


def test_https_required_by_default(dsetup: dict[str, Any]) -> None:
    restart_dav(DAV_ALLOW_HTTP="false", DAV_TRUSTED_PROXIES="")
    r = dav("PROPFIND", "/")
    assert r.status_code == 403 and "www-authenticate" not in r.headers
    # X-Forwarded-Proto from a peer that is not a trusted proxy is ignored.
    r = dav("PROPFIND", "/", headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "1.2.3.4"})
    assert r.status_code == 403 and "www-authenticate" not in r.headers
    assert DPW["davrw"] not in dav_logs()


def test_trusted_proxy_real_ip_and_lockout(admin: Admin, dsetup: dict[str, Any]) -> None:
    restart_dav(DAV_ALLOW_HTTP="false", DAV_TRUSTED_PROXIES=PROXY_NETS)

    def via(ip: str, user: str = "davrw", password: str | None = None, **h: str) -> httpx.Response:
        headers = {"X-Forwarded-Proto": "https", "X-Forwarded-For": ip, **h}
        return dav("PROPFIND", "/", user=user, password=password, headers=headers)

    # The proxy itself (no client address) is never used as the throttle key.
    assert dav("PROPFIND", "/", headers={"X-Forwarded-Proto": "https"}).status_code == 400
    # Good client B logs in (and is cached).
    assert via("198.51.100.2").status_code == 207
    # Attacker A fails; A backs off, B (same proxy) is not affected.
    assert via("203.0.113.1", password="wrong-password-1").status_code == 401
    r = via("203.0.113.1", user="davro")  # A is backing off: not even checked
    assert r.status_code == 401 and "retry-after" in r.headers
    # (davrw's verified credential would still pass from A: the cache comes first.)
    assert via("198.51.100.3").status_code == 207
    # Prepending fake entries does not change the key: the right-most untrusted entry wins.
    r = via("198.51.100.2, 203.0.113.1", password="wrong-password-2")
    assert r.status_code == 401
    # Spread over many addresses, failures lock the user (5 free, then backoff).
    for i in range(10, 16):
        via(f"203.0.113.{i}", password=f"wrong-password-{i}")
    # The user is now locked: a fresh address isn't even checked (Retry-After, no oracle).
    # (Its correct password would still pass here: it was verified and cached above.)
    r = via("198.51.100.9", user="davrw", password="another-guess-123")
    assert r.status_code == 401 and "retry-after" in r.headers
    # ...but B's already verified credential keeps working during the lockout.
    assert via("198.51.100.2").status_code == 207
    # Other users are not affected.
    assert via("198.51.100.4", user="davro").status_code == 207
    # A password change kills the cached credential on the very next request.
    admin.ok("PATCH", "/api/users/davrw", {"password": "dav-rw-password-NEW-55555"})
    try:
        assert via("198.51.100.2").status_code == 401
    finally:
        admin.ok("PATCH", "/api/users/davrw", {"password": DPW["davrw"]})
    logs = dav_logs()
    assert '"event": "dav_lockout"' in logs and '"user": "davrw"' in logs
    assert '"client": "203.0.113.1"' in logs
    for pw in DPW.values():
        assert pw not in logs


def test_restore_ci_mode(dsetup: dict[str, Any]) -> None:
    restart_dav()
    assert dav("PROPFIND", "/").status_code == 207
