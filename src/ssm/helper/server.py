"""Root helper: serves the fixed operation allowlist on a unix socket.

Only the configured web uid (and root) may connect; the peer uid comes from the kernel
(SO_PEERCRED / LOCAL_PEERCRED), not from anything the client sends. Requests are
handled one at a time, which also serialises config writes.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
import traceback
from typing import Any

from ssm import audit
from ssm.helper.ops import HelperConfig, HelperOpError, HelperOps
from ssm.helper_client import MAX_MESSAGE

# op name -> exact argument names
OPS: dict[str, tuple[str, ...]] = {
    "apply_shares": ("shares",),
    "user_add": ("name",),
    "user_set_password": ("name", "password"),
    "user_delete": ("name",),
    "user_list": (),
    "status": (),
    "perm_plan": ("path",),
    "perm_apply": ("path", "expected_before"),
    "import_scan": (),
    "import_user": ("name",),
}
# The verify socket (/run/ssm-dav/verify.sock) serves only this; it is the only thing the
# internet-facing WebDAV service can ask of the helper.
VERIFY_OPS: dict[str, tuple[str, ...]] = {
    "user_verify_password": ("name", "password"),
}
MAX_VERIFY_MESSAGE = 4096
# Argument values that may appear in the helper's log lines.
LOGGABLE_ARGS = ("name", "path")


def peer_uid(conn: socket.socket) -> int:
    # Chosen by platform, not hasattr: cheroot adds a fake socket.SO_PEERCRED on macOS.
    if sys.platform.startswith("linux"):
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return int(uid)
    if sys.platform == "darwin":  # development only: LOCAL_PEERCRED -> struct xucred
        raw = conn.getsockopt(0, 0x001, 76)
        _version, uid = struct.unpack_from("Ii", raw)
        return int(uid)
    raise OSError("cannot determine peer credentials on this platform")


def verify_uid_ok(dav_uid: int, puid: int) -> bool:
    """The verify socket's uid must identify only the WebDAV service."""
    return dav_uid > 0 and dav_uid != puid


class HelperServer:
    def __init__(
        self,
        ops: HelperOps,
        path: str,
        allowed_uid: int,
        sock_gid: int,
        ops_table: dict[str, tuple[str, ...]] | None = None,
        max_message: int = MAX_MESSAGE,
        allow_root: bool = True,
    ) -> None:
        self.ops = ops
        self.path = path
        self.allowed_uid = allowed_uid
        self.ops_table = OPS if ops_table is None else ops_table
        self.max_message = max_message
        self.allow_root = allow_root
        self._stop = False
        if os.path.lexists(path):
            os.unlink(path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.sock.bind(path)
        finally:
            os.umask(old)
        os.chown(path, -1, sock_gid)
        os.chmod(path, 0o660)  # nosec B103 - group = PGID of the web user, by design
        self.sock.listen(8)
        self.sock.settimeout(0.5)

    def shutdown(self) -> None:
        self._stop = True
        time.sleep(0.6)
        self.sock.close()

    def serve_forever(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop:
                    return
                raise
            with conn:
                conn.settimeout(15)
                try:
                    self._handle(conn)
                except Exception:  # never let one bad request kill the helper
                    traceback.print_exc(limit=3, file=sys.stderr)

    def _reply(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        conn.sendall(json.dumps(payload).encode() + b"\n")

    def _handle(self, conn: socket.socket) -> None:
        uid = peer_uid(conn)
        allowed = (self.allowed_uid, 0) if self.allow_root else (self.allowed_uid,)
        if uid not in allowed:
            audit.event("helper_denied", uid=uid)
            self._reply(conn, {"ok": False, "error": "peer not allowed"})
            return
        buf = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > self.max_message:
                self._reply(conn, {"ok": False, "error": "request too large"})
                return
            if buf.endswith(b"\n"):
                break
        self._reply(conn, self.dispatch(bytes(buf)))

    def dispatch(self, raw: bytes) -> dict[str, Any]:
        try:
            req = json.loads(raw)
        except ValueError:
            return {"ok": False, "error": "invalid request"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "invalid request"}
        op, args = req.get("op"), req.get("args")
        if not isinstance(op, str) or op not in self.ops_table:
            return {"ok": False, "error": "unknown operation"}
        if not isinstance(args, dict) or set(args) != set(self.ops_table[op]):
            return {"ok": False, "error": "invalid arguments"}
        safe = {k: args[k] for k in LOGGABLE_ARGS if k in args and isinstance(args[k], str)}
        try:
            result = getattr(self.ops, op)(**args)
        except HelperOpError as e:
            audit.event("helper_op", op=op, ok=False, error=str(e), **safe)
            return {"ok": False, "error": str(e)}
        except Exception:
            traceback.print_exc(limit=3, file=sys.stderr)
            audit.event("helper_op", op=op, ok=False, error="internal error", **safe)
            return {"ok": False, "error": f"{op}: internal error (see container log)"}
        audit.event("helper_op", op=op, ok=True, **safe)
        return {"ok": True, "result": result}


def _env_list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def main() -> None:
    p = argparse.ArgumentParser(description="smb-share-manager root helper")
    p.add_argument("--init", action="store_true", help="write globals/extrausers and exit")
    a = p.parse_args()
    puid = int(os.environ.get("PUID", "1000"))
    pgid = int(os.environ.get("PGID", "1000"))
    cfg = HelperConfig(volumes=_env_list("VOLUMES"))
    ops = HelperOps(cfg)
    if a.init:
        from ssm.helper import extrausers

        ops.write_globals(
            _env_list("SMB_HOSTS_ALLOW"),
            os.environ.get("SMB_SERVER_NAME", "NAS"),
            os.environ.get("ENABLE_NMBD", "false").lower() == "true",
        )
        extrausers.ensure_files(cfg.extrausers_dir, cfg.smb_gid)
        return
    sock = os.environ.get("HELPER_SOCKET", "/run/ssm/helper.sock")
    server = HelperServer(ops, sock, allowed_uid=puid, sock_gid=pgid)
    audit.event("helper_started", socket=sock, allowed_uid=puid)
    _start_verify_server(ops, puid)
    server.serve_forever()


def _start_verify_server(ops: HelperOps, puid: int) -> None:
    """Start the verify-only socket for the WebDAV service, if WebDAV is enabled."""
    if not _env_list("DAV_EXPOSED_SHARES"):
        return
    try:
        dav_uid = int(os.environ.get("DAV_UID", "2999"))
    except ValueError:
        dav_uid = -1
    if not verify_uid_ok(dav_uid, puid):
        audit.event("helper_verify_disabled", error="DAV_UID must be a number, not 0 or PUID")
        return
    path = os.environ.get("DAV_VERIFY_SOCKET", "/run/ssm-dav/verify.sock")
    vserver = HelperServer(
        ops,
        path,
        allowed_uid=dav_uid,
        sock_gid=int(os.environ.get("SMB_GID", "3000")),
        ops_table=VERIFY_OPS,
        max_message=MAX_VERIFY_MESSAGE,
        allow_root=False,
    )
    threading.Thread(target=vserver.serve_forever, name="verify", daemon=True).start()
    audit.event("helper_verify_started", socket=path, allowed_uid=dav_uid)


if __name__ == "__main__":
    main()
