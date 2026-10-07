"""Integration tests against the real image, started by scripts/ci/integration.sh.

Environment (set by the CI script):
  SSM_URL            web UI base URL, e.g. http://127.0.0.1:8095
  SSM_PASSWORD       admin password
  SSM_SMB_PORT       published SMB port on the runner (1445: exercises the port override)
  SSM_FS             filesystem of the shared volume: exfat or ext4
  SSM_CONTAINER      container name
  SSM_COMPOSE        compose command prefix (for restart)
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.integration

URL = os.environ.get("SSM_URL", "")
if not URL:
    pytest.skip("integration environment not configured", allow_module_level=True)

PASSWORD = os.environ["SSM_PASSWORD"]
PORT = os.environ.get("SSM_SMB_PORT", "445")
FS = os.environ.get("SSM_FS", "ext4")
CONTAINER = os.environ.get("SSM_CONTAINER", "smb-share-manager")
COMPOSE = shlex.split(os.environ.get("SSM_COMPOSE", "docker compose"))
VOL = "/mnt/files"
PW = {
    "rwuser": "rw-user-password-1",
    "rouser": "ro-user-password-1",
    "other": "other-user-password1",
}
IMPORTED_PW = "Isherveer-Old-Pass1"


# --- helpers ----------------------------------------------------------------------------


class Admin:
    def __init__(self) -> None:
        self.c = httpx.Client(base_url=URL, follow_redirects=False, timeout=30)
        page = self.c.get("/login")
        token = self._csrf(page.text)
        r = self.c.post(
            "/login", data={"password": PASSWORD, "csrf_token": token}, headers={"Origin": URL}
        )
        assert r.status_code == 303, r.text
        self.csrf = self._csrf(self.c.get("/shares").text)

    @staticmethod
    def _csrf(html: str) -> str:
        m = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert m
        return m.group(1)

    def post(self, path: str, data: dict[str, str] | None = None) -> httpx.Response:
        return self.c.post(
            path, data={**(data or {}), "csrf_token": self.csrf}, headers={"Origin": URL}
        )

    def ok(self, path: str, data: dict[str, str] | None = None) -> httpx.Response:
        r = self.post(path, data)
        assert r.status_code == 303, (path, r.status_code, r.text[:500])
        assert "err=" not in r.headers["location"], (path, r.headers["location"])
        return r


def smbclient(share: str, user: str | None, password: str | None, cmd: str) -> tuple[int, str]:
    args = ["smbclient", f"//127.0.0.1/{share}", "-p", PORT, "-m", "SMB3", "-c", cmd]
    if user is None:
        args += ["-N"]
        auth = None
    else:
        auth = tempfile.NamedTemporaryFile("w", delete=False)  # noqa: SIM115
        auth.write(f"username = {user}\npassword = {password}\n")
        auth.close()
        args += ["-A", auth.name]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    finally:
        if auth:
            os.unlink(auth.name)
    return p.returncode, p.stdout + p.stderr


def dexec(*args: str, user: str = "0") -> str:
    p = subprocess.run(
        ["docker", "exec", "-u", user, CONTAINER, *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout


def wait_healthy(timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", CONTAINER],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.stdout.strip() == "healthy":
            return
        time.sleep(2)
    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stdout
    raise AssertionError("container did not become healthy:\n" + logs[-4000:])


@pytest.fixture(scope="module")
def admin() -> Iterator[Admin]:
    wait_healthy()
    yield Admin()


@pytest.fixture(scope="module")
def setup(admin: Admin) -> dict[str, Any]:
    for name, pw in PW.items():
        admin.ok("/users", {"name": name, "password": pw, "password2": pw})
    admin.ok("/browse/mkdir", {"path": VOL, "name": "s1"})
    admin.ok(
        "/shares",
        {
            "name": "S1",
            "path": f"{VOL}/s1",
            "all_users": "off",
            "access_rwuser": "rw",
            "access_rouser": "ro",
            "access_other": "none",
        },
    )
    return {"share": "S1"}


# --- health, headers, hardening -----------------------------------------------------------


def test_healthz() -> None:
    wait_healthy()
    r = httpx.get(URL + "/healthz")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"status", "version", "build_date"}
    assert body["version"] not in ("", "dev")


def test_security_headers_real_server() -> None:
    for path in ("/login", "/static/app.css", "/healthz", "/nope"):
        r = httpx.get(URL + path)
        csp = r.headers["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "server" not in r.headers


def test_no_api_docs_and_bad_host() -> None:
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert httpx.get(URL + p).status_code in (303, 404)
    assert httpx.get(URL + "/login", headers={"Host": "evil.example"}).status_code == 400


def test_container_hardening() -> None:
    info = json.loads(
        subprocess.run(
            ["docker", "inspect", CONTAINER], capture_output=True, text=True, check=True
        ).stdout
    )[0]
    hc = info["HostConfig"]
    assert hc["CapDrop"] == ["ALL"]
    assert set(hc["CapAdd"]) == {
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_SETUID",
        "CAP_SETGID",
        "CAP_NET_BIND_SERVICE",
    } or set(hc["CapAdd"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "SETUID",
        "SETGID",
        "NET_BIND_SERVICE",
    }
    assert hc["Privileged"] is False
    assert hc["ReadonlyRootfs"] is True
    assert "no-new-privileges:true" in hc["SecurityOpt"]
    assert hc["NetworkMode"] != "host"
    for m in info["Mounts"]:
        assert m["Destination"] in ("/data", VOL, "/import"), m
        assert m["Source"] not in ("/", "/proc", "/sys")
        assert not m["Source"].startswith(("/proc", "/sys", "/mnt/timenest"))


def test_web_process_unprivileged() -> None:
    out = dexec(
        "python3",
        "-c",
        (
            "import os\n"
            "for p in os.listdir('/proc'):\n"
            "    if p.isdigit():\n"
            "        try: cmd=open(f'/proc/{p}/cmdline','rb').read().replace(b'\\0',b' ')\n"
            "        except OSError: continue\n"
            "        if b'ssm.web.main' in cmd:\n"
            "            st=open(f'/proc/{p}/status').read()\n"
            "            print([l for l in st.splitlines() if l.startswith(('Uid','CapEff','NoNewPrivs'))])\n"
        ),
    )
    assert "'Uid:\\t1000\\t1000\\t1000\\t1000'" in out, out
    assert "CapEff:\\t0000000000000000" in out, out
    assert "NoNewPrivs:\\t1" in out, out


def test_shipped_samba_has_required_tools() -> None:
    assert "--set-nt-hash" in dexec("pdbedit", "--help")
    # Debian's useradd has no --extrausers (documented reason for writing the files ourselves).
    p = subprocess.run(
        ["docker", "exec", CONTAINER, "useradd", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "extrausers" not in p.stdout + p.stderr
    dexec("testparm", "-s", "--suppress-prompt", "/etc/samba/smb.conf")


# --- users and shares over SMB --------------------------------------------------------------


def test_users_are_nss_accounts(setup: dict[str, Any]) -> None:
    line = dexec("getent", "passwd", "rwuser").strip().split(":")
    assert int(line[2]) >= 3000 and line[3] == "3000"
    assert line[6] == "/usr/sbin/nologin" and line[5] == "/nonexistent"


def test_rw_user_can_write(setup: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("hello")
    rc, out = smbclient("S1", "rwuser", PW["rwuser"], f"put {f.name} hello.txt; ls")
    assert rc == 0 and "NT_STATUS" not in out, out
    assert "hello.txt" in out


def test_ro_user_can_read_not_write(setup: dict[str, Any]) -> None:
    rc, out = smbclient("S1", "rouser", PW["rouser"], "ls")
    assert rc == 0 and "NT_STATUS" not in out, out
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("nope")
    rc, out = smbclient("S1", "rouser", PW["rouser"], f"put {f.name} ro.txt")
    assert "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_MEDIA_WRITE_PROTECTED" in out, out


def test_non_member_denied(setup: dict[str, Any]) -> None:
    rc, out = smbclient("S1", "other", PW["other"], "ls")
    assert rc != 0 and "NT_STATUS_ACCESS_DENIED" in out, out


def test_wrong_password_and_anonymous_denied(setup: dict[str, Any]) -> None:
    rc, out = smbclient("S1", "rwuser", "wrong password!!", "ls")
    assert rc != 0 and "NT_STATUS_LOGON_FAILURE" in out, out
    rc, out = smbclient("S1", None, None, "ls")
    assert rc != 0, out
    rc, out = smbclient("IPC$", None, None, "ls")
    assert rc != 0, out


def test_old_protocols_refused(setup: dict[str, Any]) -> None:
    p = subprocess.run(
        [
            "smbclient",
            "//127.0.0.1/S1",
            "-p",
            PORT,
            "-m",
            "NT1",
            "--option=client min protocol=NT1",
            "-U",
            f"rwuser%{PW['rwuser']}",
            "-c",
            "ls",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode != 0


def test_alternate_data_streams(setup: dict[str, Any]) -> None:
    """macOS metadata: on ext4 named streams work (fruit + streams_xattr); on exFAT (no
    xattrs) generic streams are unsupported but the resource fork works (stored as a file)."""
    from smbprotocol.connection import Connection
    from smbprotocol.exceptions import SMBResponseException
    from smbprotocol.open import (
        CreateDisposition,
        CreateOptions,
        FileAttributes,
        FilePipePrinterAccessMask,
        ImpersonationLevel,
        Open,
        ShareAccess,
    )
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect

    def write_read(tree: TreeConnect, name: str) -> bool:
        f = Open(tree, name)
        try:
            f.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
        except SMBResponseException:
            return False
        f.write(b"data", 0)
        assert f.read(0, 4) == b"data"
        f.close()
        return True

    conn = Connection(uuid.uuid4(), "127.0.0.1", int(PORT))
    conn.connect()
    try:
        sess = Session(conn, "rwuser", PW["rwuser"])
        sess.connect()
        tree = TreeConnect(sess, r"\\127.0.0.1\S1")
        tree.connect()
        assert write_read(tree, "streamtest.txt")
        assert write_read(tree, "streamtest.txt:AFP_Resource")
        generic = write_read(tree, "streamtest.txt:userstream")
        assert generic is (FS != "exfat"), f"generic named stream on {FS}: {generic}"
    finally:
        conn.disconnect()


def test_fs_warning_shown_for_exfat(admin: Admin, setup: dict[str, Any]) -> None:
    page = admin.c.get("/shares/new", params={"path": f"{VOL}/s1"}).text
    if FS == "exfat":
        assert "exfat" in page and "share level only" in page
    else:
        assert "share level only" not in page


def test_permission_plan_on_fs(admin: Admin, setup: dict[str, Any]) -> None:
    page = admin.c.get("/shares/S1/edit").text
    if FS == "exfat":
        assert "without unix permissions" in page
    else:
        # ext4 volume was prepared as 1000:3000 2775 by the CI script: nothing to change.
        assert "Permissions look right" in page or "fix permissions" in page


# --- requirement 3: zero-member share ---------------------------------------------------------


def test_zero_member_share_refused_and_unreachable(admin: Admin, setup: dict[str, Any]) -> None:
    admin.ok("/browse/mkdir", {"path": VOL, "name": "zero"})
    r = admin.post("/shares", {"name": "Zero", "path": f"{VOL}/zero", "all_users": "off"})
    assert r.status_code == 400
    # Bypass the UI: inject a member-less share straight into the registry, then ask the
    # helper to apply it. The helper must refuse, and the share must stay unreachable.
    dexec(
        "python3",
        "-c",
        (
            "import sqlite3; db=sqlite3.connect('/data/app/registry.db');"
            f"db.execute(\"INSERT INTO shares(name,path) VALUES ('Zero','{VOL}/zero')\");"
            "db.commit()"
        ),
        user="1000",
    )
    try:
        r = admin.post("/config/reapply")
        assert "err=" in r.headers["location"]
        for user in PW:
            rc, out = smbclient("Zero", user, PW[user], "ls")
            assert rc != 0, (user, out)
        rc, out = smbclient("S1", "rwuser", PW["rwuser"], "ls")  # other shares unaffected
        assert rc == 0, out
    finally:
        dexec(
            "python3",
            "-c",
            (
                "import sqlite3; db=sqlite3.connect('/data/app/registry.db');"
                "db.execute(\"DELETE FROM shares WHERE name='Zero'\"); db.commit()"
            ),
            user="1000",
        )


# --- requirement 1: planted HTML downloads as an attachment ------------------------------------


def test_planted_html_downloads_as_attachment(admin: Admin, setup: dict[str, Any]) -> None:
    html = b"<html><body><script>alert(document.cookie)</script></body></html>"
    r = admin.c.put(
        "/browse/upload",
        params={"dir": f"{VOL}/s1", "name": "evil.html"},
        content=html,
        headers={"Origin": URL, "X-CSRF-Token": admin.csrf},
    )
    assert r.status_code == 201, r.text
    name = r.json()["name"]
    r = admin.c.get("/browse/download", params={"path": f"{VOL}/s1/{name}"})
    assert r.status_code == 200 and r.content == html
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]
    # Also reachable over SMB by a member: the file really is on the share.
    _rc, out = smbclient("S1", "rwuser", PW["rwuser"], "ls")
    assert name in out


def test_upload_never_overwrites(admin: Admin, setup: dict[str, Any]) -> None:
    hdr = {"Origin": URL, "X-CSRF-Token": admin.csrf}
    names = []
    for body in (b"one", b"two"):
        r = admin.c.put(
            "/browse/upload",
            params={"dir": f"{VOL}/s1", "name": "same.txt"},
            content=body,
            headers=hdr,
        )
        assert r.status_code == 201
        names.append(r.json()["name"])
    assert names[0] != names[1]


# --- import from a real tdbsam passdb ---------------------------------------------------------


def test_import_real_passdb(admin: Admin, setup: dict[str, Any]) -> None:
    page = admin.c.get("/import").text
    assert "isherveer" in page
    assert "still mounted" in page
    assert "Was anonymous" in page
    admin.ok("/import/user", {"name": "isherveer"})
    # The imported user logs in with their OLD password (the NT hash carried over).
    admin.ok("/browse/mkdir", {"path": VOL, "name": "Isherveer"})
    admin.ok("/import/share", {"name": "Isherveer", "path": f"{VOL}/Isherveer"})
    rc, out = smbclient("Isherveer", "isherveer", IMPORTED_PW, "ls")
    assert rc == 0 and "NT_STATUS" not in out, out
    # The hash never shows up in a page or in the logs.
    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stdout
    for text in (page, admin.c.get("/import").text, logs):
        assert not re.search(r"\b[0-9A-F]{32}\b", text)


def test_import_bad_share_blocked(admin: Admin, setup: dict[str, Any]) -> None:
    r = admin.post("/import/share", {"name": "Weird"})
    assert "err=" in r.headers["location"]


# --- unsharing disconnects --------------------------------------------------------------------


def test_unshare_disconnects_open_session(admin: Admin, setup: dict[str, Any]) -> None:
    from smbprotocol.connection import Connection
    from smbprotocol.exceptions import SMBException
    from smbprotocol.open import (
        CreateDisposition,
        CreateOptions,
        FileAttributes,
        FilePipePrinterAccessMask,
        ImpersonationLevel,
        Open,
        ShareAccess,
    )
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect

    admin.ok("/browse/mkdir", {"path": VOL, "name": "temp"})
    admin.ok(
        "/shares",
        {"name": "Temp", "path": f"{VOL}/temp", "all_users": "off", "access_rwuser": "rw"},
    )
    conn = Connection(uuid.uuid4(), "127.0.0.1", int(PORT))
    conn.connect()
    try:
        sess = Session(conn, "rwuser", PW["rwuser"])
        sess.connect()
        tree = TreeConnect(sess, r"\\127.0.0.1\Temp")
        tree.connect()
        f = Open(tree, "open.txt")
        f.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ,
            CreateDisposition.FILE_OVERWRITE_IF,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        f.write(b"before", 0)
        admin.ok("/shares/Temp/delete")
        time.sleep(1)
        with pytest.raises(SMBException):
            f.write(b"after", 0)
            f.read(0, 5)
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()
    rc, out = smbclient("Temp", "rwuser", PW["rwuser"], "ls")
    assert rc != 0 and "NT_STATUS_BAD_NETWORK_NAME" in out, out
    assert "temp" in admin.c.get("/browse", params={"path": VOL}).text  # folder untouched


def test_membership_removal_disconnects(admin: Admin, setup: dict[str, Any]) -> None:
    admin.ok(
        "/shares/S1",
        {
            "name": "S1",
            "path": f"{VOL}/s1",
            "all_users": "off",
            "access_rwuser": "rw",
            "access_rouser": "none",
            "access_other": "none",
        },
    )
    rc, out = smbclient("S1", "rouser", PW["rouser"], "ls")
    assert rc != 0 and "NT_STATUS_ACCESS_DENIED" in out, out
    admin.ok(
        "/shares/S1",
        {
            "name": "S1",
            "path": f"{VOL}/s1",
            "all_users": "off",
            "access_rwuser": "rw",
            "access_rouser": "ro",
            "access_other": "none",
        },
    )


# --- status and state across restarts -----------------------------------------------------------


def test_status_agrees_with_registry(admin: Admin, setup: dict[str, Any]) -> None:
    page = admin.c.get("/config").text
    assert "running" in page
    assert "Samba agrees with the registry" in page, page[:3000]


def test_audit_log_events(setup: dict[str, Any]) -> None:
    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stdout
    events = set()
    for line in logs.splitlines():
        if line.startswith("{"):
            with contextlib.suppress(ValueError, KeyError):
                events.add(json.loads(line)["event"])
    for e in ("login_ok", "user_created", "share_created", "share_deleted", "file_uploaded"):
        assert e in events, e
    for pw in [*PW.values(), PASSWORD, IMPORTED_PW]:
        assert pw not in logs


def test_survives_recreate(admin: Admin, setup: dict[str, Any]) -> None:
    subprocess.run([*COMPOSE, "up", "-d", "--force-recreate"], check=True, timeout=180)
    wait_healthy()
    time.sleep(3)  # startup sync of the registry into Samba
    rc, out = smbclient("S1", "rwuser", PW["rwuser"], "ls")
    assert rc == 0 and "hello.txt" in out, out
    rc, out = smbclient("S1", "other", PW["other"], "ls")
    assert rc != 0
    # Old browser sessions survive a restart (same credential, sessions in ./data).
    assert admin.c.get("/shares").status_code == 200


def test_smoke_script(setup: dict[str, Any]) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "smoke-test.sh"
    env = {
        **os.environ,
        "SMB_USER": "rwuser",
        "SMB_PASSWORD": PW["rwuser"],
        "SMB_SHARE": "S1",
        "CONTAINER": CONTAINER,
        "WEB_URL": URL,
    }
    p = subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True, timeout=120, check=False
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert "FAIL" not in p.stdout
