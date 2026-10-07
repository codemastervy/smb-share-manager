"""In-memory stand-in for the root helper, used by web-app tests."""

from __future__ import annotations

from typing import Any

from ssm.models import ShareSpec


class FakeHelper:
    def __init__(self) -> None:
        self.users: dict[str, str] = {}  # name -> password
        self.shares: list[ShareSpec] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_next: str | None = None
        self.perm_state: dict[str, dict[str, Any]] = {}
        self.import_users: list[str] = []

    def _call(self, op: str, **kw: Any) -> None:
        self.calls.append((op, kw))
        if self.fail_next == op:
            self.fail_next = None
            from ssm.helper_client import HelperError

            raise HelperError(f"{op} failed (simulated)")

    def apply_shares(self, shares: list[ShareSpec]) -> dict[str, Any]:
        self._call("apply_shares", shares=[s.to_dict() for s in shares])
        self.shares = list(shares)
        return {"ok": True}

    def user_add(self, name: str) -> None:
        self._call("user_add", name=name)
        self.users[name] = ""

    def user_set_password(self, name: str, password: str) -> None:
        self._call("user_set_password", name=name)
        self.users[name] = password

    def user_delete(self, name: str) -> None:
        self._call("user_delete", name=name)
        self.users.pop(name, None)

    def user_list(self) -> list[str]:
        self._call("user_list")
        return sorted(self.users)

    def status(self) -> dict[str, Any]:
        self._call("status")
        return {
            "smbd_running": True,
            "shares": {s.name: {"path": s.path} for s in self.shares},
            "users": sorted(self.users),
            "config_text": "",
        }

    def perm_plan(self, path: str) -> dict[str, Any]:
        self._call("perm_plan", path=path)
        return self.perm_state.get(
            path,
            {"path": path, "fs_type": "ext4", "changes": [], "before": {"uid": 0, "gid": 0, "mode": "0755"}},
        )

    def perm_apply(self, path: str, expected_before: dict[str, Any]) -> dict[str, Any]:
        self._call("perm_apply", path=path, expected_before=expected_before)
        return {"ok": True}

    def import_scan(self) -> dict[str, Any]:
        self._call("import_scan")
        return {"users": list(self.import_users)}

    def import_user(self, name: str) -> None:
        self._call("import_user", name=name)
        self.users[name] = "<imported>"
