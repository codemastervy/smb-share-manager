"""Client for the root helper: one JSON request per unix-socket connection."""

from __future__ import annotations

import json
import socket
from typing import Any, Protocol

from ssm.models import ShareSpec

MAX_MESSAGE = 4 * 1024 * 1024


class HelperError(Exception):
    """The helper refused or failed an operation; the message is safe to display."""


class Helper(Protocol):
    def apply_shares(self, shares: list[ShareSpec]) -> dict[str, Any]: ...
    def user_add(self, name: str) -> None: ...
    def user_set_password(self, name: str, password: str) -> None: ...
    def user_delete(self, name: str) -> None: ...
    def user_list(self) -> list[str]: ...
    def status(self) -> dict[str, Any]: ...
    def perm_plan(self, path: str) -> dict[str, Any]: ...
    def perm_apply(self, path: str, expected_before: dict[str, Any]) -> dict[str, Any]: ...
    def import_scan(self) -> dict[str, Any]: ...
    def import_user(self, name: str) -> None: ...


def recv_message(sock: socket.socket) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_MESSAGE:
            raise HelperError("message too large")
        if buf.endswith(b"\n"):
            break
    return bytes(buf)


class HelperClient:
    def __init__(self, socket_path: str, timeout: float = 60.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def call(self, op: str, **args: Any) -> Any:
        payload = json.dumps({"op": op, "args": args}).encode() + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
                raw = recv_message(s)
        except OSError as e:
            raise HelperError(f"helper unavailable: {e.strerror or e}") from e
        try:
            reply = json.loads(raw)
        except ValueError as e:
            raise HelperError("invalid reply from helper") from e
        if not isinstance(reply, dict) or not reply.get("ok"):
            err = reply.get("error") if isinstance(reply, dict) else None
            raise HelperError(str(err or "helper error"))
        return reply.get("result")

    def apply_shares(self, shares: list[ShareSpec]) -> dict[str, Any]:
        return dict(self.call("apply_shares", shares=[s.to_dict() for s in shares]))

    def user_add(self, name: str) -> None:
        self.call("user_add", name=name)

    def user_set_password(self, name: str, password: str) -> None:
        self.call("user_set_password", name=name, password=password)

    def user_delete(self, name: str) -> None:
        self.call("user_delete", name=name)

    def user_list(self) -> list[str]:
        return [str(x) for x in self.call("user_list")]

    def status(self) -> dict[str, Any]:
        return dict(self.call("status"))

    def perm_plan(self, path: str) -> dict[str, Any]:
        return dict(self.call("perm_plan", path=path))

    def perm_apply(self, path: str, expected_before: dict[str, Any]) -> dict[str, Any]:
        return dict(self.call("perm_apply", path=path, expected_before=expected_before))

    def import_scan(self) -> dict[str, Any]:
        return dict(self.call("import_scan"))

    def import_user(self, name: str) -> None:
        self.call("import_user", name=name)
