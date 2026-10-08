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
VP = "/files"  # the same volume as the UI/API names it
PW = {
    "rwuser": "rw-user-password-1",
    "rouser": "ro-user-password-1",
    "other": "other-user-password1",
}
IMPORTED_PW = "Isherveer-Old-Pass1"


# --- helpers ----------------------------------------------------------------------------


class Admin:
    """Talks to the JSON API the way the React UI does."""

    def __init__(self) -> None:
        self.c = httpx.Client(base_url=URL, follow_redirects=False, timeout=60)
        pre = self.c.get("/api/auth/status").json()["csrf"]
        r = self.c.post(
            "/api/auth/login",
            json={"password": PASSWORD},
            headers={"Origin": URL, "X-CSRF-Token": pre},
        )
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf"]

    def req(self, method: str, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        headers = {"Origin": URL, "X-CSRF-Token": self.csrf, **kw.pop("headers", {})}
        return self.c.request(method, path, json=json, headers=headers, **kw)

    def ok(self, method: str, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        r = self.req(method, path, json, **kw)
        assert 200 <= r.status_code < 300, (method, path, r.status_code, r.text[:500])
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
        admin.ok("POST", "/api/users", {"username": name, "password": pw, "display_name": ""})
    admin.ok("POST", "/api/files/mkdir", {"parent": VP, "name": "s1"})
    admin.ok(
        "POST",
        "/api/shares",
        {
            "name": "S1",
            "path": f"{VP}/s1",
            "members": [
                {"username": "rwuser", "access": "rw"},
                {"username": "rouser", "access": "ro"},
            ],
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
    for path in ("/", "/files", "/healthz", "/api/auth/status", "/nope"):
        r = httpx.get(URL + path)
        csp = r.headers["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "same-origin"
        assert "server" not in r.headers
    html = httpx.get(URL + "/").text
    assert "<script" in html
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.S):
        assert "src=" in m.group(1) and not m.group(2).strip()


def test_no_api_docs_and_bad_host() -> None:
    for p in ("/docs", "/redoc", "/openapi.json", "/api/openapi.json"):
        r = httpx.get(URL + p)
        assert "swagger" not in r.text.lower() and '"openapi"' not in r.text
    assert httpx.get(URL + "/api/shares").status_code == 401
    assert httpx.get(URL + "/", headers={"Host": "evil.example"}).status_code == 400


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
    """macOS metadata: on ext4 named streams work (fruit + streams_xattr). On exFAT (no
    xattrs) no stream module is loaded, so streams are cleanly unsupported and macOS uses
    ._ AppleDouble files instead."""
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
        for stream in ("streamtest.txt:AFP_Resource", "streamtest.txt:userstream"):
            ok = write_read(tree, stream)
            assert ok is (FS != "exfat"), f"{stream} on {FS}: {ok}"
    finally:
        conn.disconnect()


def test_fs_warning_shown_for_exfat(admin: Admin, setup: dict[str, Any]) -> None:
    listing = admin.c.get("/api/files/list", params={"path": f"{VP}/s1"}).json()
    share = next(x for x in admin.c.get("/api/shares").json()["shares"] if x["name"] == "S1")
    if FS == "exfat":
        assert listing["fs_type"] == "exfat" and listing["no_unix_perms"] is True
        assert share["no_unix_perms"] is True
    else:
        assert listing["no_unix_perms"] is False and share["no_unix_perms"] is False


def test_permission_plan_on_fs(admin: Admin, setup: dict[str, Any]) -> None:
    plan = admin.c.get("/api/shares/S1/permissions").json()
    if FS == "exfat":
        assert plan["applicable"] is False and plan["changes"] == []
    else:
        # The ext4 volume was prepared as 1000:3000 2775 and the web app creates folders
        # group-writable, so nothing (or at most the setgid bit) needs changing.
        assert plan["applicable"] is True


# --- requirement 3: zero-member share ---------------------------------------------------------


def test_zero_member_share_refused_and_unreachable(admin: Admin, setup: dict[str, Any]) -> None:
    admin.ok("POST", "/api/files/mkdir", {"parent": VP, "name": "zero"})
    r = admin.req("POST", "/api/shares", {"name": "Zero", "path": f"{VP}/zero", "members": []})
    assert r.status_code == 400
    # Bypass the API: inject a member-less share straight into the registry, then ask the
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
        r = admin.req("POST", "/api/shares/reapply")
        assert r.status_code == 502, r.text
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
    r = admin.req(
        "PUT", "/api/files/upload", params={"path": f"{VP}/s1", "name": "evil.html"}, content=html
    )
    assert r.status_code == 201, r.text
    name = r.json()["name"]
    for extra in ({}, {"inline": "true"}):
        r = admin.c.get("/api/files/download", params={"path": f"{VP}/s1/{name}", **extra})
        assert r.status_code == 200 and r.content == html
        assert r.headers["content-disposition"].startswith("attachment;")
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "sandbox" in r.headers["content-security-policy"]
    # Also reachable over SMB by a member: the file really is on the share.
    _rc, out = smbclient("S1", "rwuser", PW["rwuser"], "ls")
    assert name in out


def test_upload_never_overwrites(admin: Admin, setup: dict[str, Any]) -> None:
    names = []
    for body in (b"one", b"two"):
        r = admin.req(
            "PUT",
            "/api/files/upload",
            params={"path": f"{VP}/s1", "name": "same.txt"},
            content=body,
        )
        assert r.status_code == 201
        names.append(r.json()["name"])
    assert names[0] != names[1]


def test_copy_move_search(admin: Admin, setup: dict[str, Any]) -> None:
    admin.ok("POST", "/api/files/mkdir", {"parent": VP, "name": "cm"})
    r = admin.ok(
        "POST", "/api/files/copy", {"sources": [f"{VP}/s1/same.txt"], "destination": f"{VP}/cm"}
    ).json()
    assert r["failed"] == [] and r["copied"] == [f"{VP}/cm/same.txt"]
    r = admin.ok(
        "POST", "/api/files/move", {"sources": [f"{VP}/cm/same.txt"], "destination": f"{VP}/s1"}
    ).json()
    assert r["moved"] == [] and "already exists" in r["failed"][0]["error"]
    found = admin.c.get("/api/files/search", params={"path": VP, "q": "same"}).json()
    assert f"{VP}/cm/same.txt" in [e["path"] for e in found["entries"]]
    r = admin.ok("POST", "/api/files/delete", {"paths": [f"{VP}/cm", VP]}).json()
    assert r["deleted"] == [f"{VP}/cm"] and len(r["failed"]) == 1


# --- import from a real tdbsam passdb ---------------------------------------------------------


def test_import_real_passdb(admin: Admin, setup: dict[str, Any]) -> None:
    page = admin.c.get("/api/import")
    data = page.json()
    assert data["mounted"] is True
    assert "isherveer" in [u["username"] for u in data["users"]]
    assert admin.c.get("/api/info").json()["import_mounted"] is True
    assert any(x["was_anonymous"] for x in data["shares"])
    admin.ok("POST", "/api/import/user", {"username": "isherveer"})
    # The imported user logs in with their OLD password (the NT hash carried over).
    admin.ok("POST", "/api/files/mkdir", {"parent": VP, "name": "Isherveer"})
    admin.ok("POST", "/api/import/share", {"name": "Isherveer", "path": f"{VP}/Isherveer"})
    rc, out = smbclient("Isherveer", "isherveer", IMPORTED_PW, "ls")
    assert rc == 0 and "NT_STATUS" not in out, out
    # The hash never shows up in an API response or in the logs.
    logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stdout
    for text in (page.text, admin.c.get("/api/import").text, logs):
        assert not re.search(r"\b[0-9A-F]{32}\b", text)


def test_import_bad_share_blocked(admin: Admin, setup: dict[str, Any]) -> None:
    assert admin.req("POST", "/api/import/share", {"name": "Weird"}).status_code == 400


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

    admin.ok("POST", "/api/files/mkdir", {"parent": VP, "name": "temp"})
    admin.ok(
        "POST",
        "/api/shares",
        {"name": "Temp", "path": f"{VP}/temp", "members": [{"username": "rwuser", "access": "rw"}]},
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
        admin.ok("DELETE", "/api/shares/Temp")
        time.sleep(1)
        with pytest.raises(SMBException):
            f.write(b"after", 0)
            f.read(0, 5)
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()
    rc, out = smbclient("Temp", "rwuser", PW["rwuser"], "ls")
    assert rc != 0 and "NT_STATUS_BAD_NETWORK_NAME" in out, out
    names = [
        e["name"] for e in admin.c.get("/api/files/list", params={"path": VP}).json()["entries"]
    ]
    assert "temp" in names  # folder untouched


def test_membership_removal_disconnects(admin: Admin, setup: dict[str, Any]) -> None:
    admin.ok("PATCH", "/api/shares/S1", {"members": [{"username": "rwuser", "access": "rw"}]})
    rc, out = smbclient("S1", "rouser", PW["rouser"], "ls")
    assert rc != 0 and "NT_STATUS_ACCESS_DENIED" in out, out
    admin.ok(
        "PATCH",
        "/api/shares/S1",
        {
            "members": [
                {"username": "rwuser", "access": "rw"},
                {"username": "rouser", "access": "ro"},
            ]
        },
    )


# --- status and state across restarts -----------------------------------------------------------


def test_status_agrees_with_registry(admin: Admin, setup: dict[str, Any]) -> None:
    st = admin.c.get("/api/shares").json()["status"]
    assert st["running"] is True
    for k in ("missing_shares", "extra_shares", "missing_users", "extra_users"):
        assert st[k] == [], (k, st)
    assert "[S1]" in admin.c.get("/api/shares/config").json()["content"]


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
    assert admin.c.get("/api/shares").status_code == 200


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
