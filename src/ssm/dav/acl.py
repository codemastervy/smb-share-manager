"""The WebDAV service's view of users and shares: the snapshot written by the admin app.

The file is stat()ed on every request and reloaded when it changes, so a removed user,
a changed membership or a new password generation applies to the very next request.
A missing or malformed snapshot makes every request fail (fail closed).

A share is *served* only when all of these hold:
- its name is listed in DAV_EXPOSED_SHARES (case-insensitive, like Samba share names);
- its path is not a volume root (a share covering a whole volume is never served);
- its path is a mount point inside the WebDAV container (only those folders are mounted);
- it has at least one member or all-users access.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ssm import audit
from ssm import validators as v

ACCESS = ("ro", "rw")


@dataclass(frozen=True)
class DavShare:
    name: str
    path: str
    members: dict[str, str]
    all_users: str | None

    def access_for(self, user: str) -> str | None:
        levels = {self.members.get(user), self.all_users}
        if "rw" in levels:
            return "rw"
        if "ro" in levels:
            return "ro"
        return None


@dataclass(frozen=True)
class AclSnapshot:
    users: dict[str, tuple[int, bool]]  # name -> (credential generation, remote access)
    served: dict[str, DavShare]  # casefolded name -> share
    share_paths: tuple[str, ...]  # every registry share path (for "protected" checks)

    def user(self, name: str) -> tuple[int, bool] | None:
        return self.users.get(name)

    def share_for(self, user: str, name: str) -> tuple[DavShare, str] | None:
        s = self.served.get(name.casefold())
        if s is None:
            return None
        access = s.access_for(user)
        return (s, access) if access else None

    def visible(self, user: str) -> list[DavShare]:
        return sorted(
            (s for s in self.served.values() if s.access_for(user)), key=lambda s: s.name.lower()
        )


class AclError(ValueError):
    pass


def _parse(raw: Any) -> tuple[dict[str, tuple[int, bool]], list[DavShare], list[str]]:
    if not isinstance(raw, dict) or raw.get("format") != 1:
        raise AclError("unknown snapshot format")
    users_raw, shares_raw = raw.get("users"), raw.get("shares")
    vols = raw.get("volumes", [])
    if not isinstance(users_raw, dict) or not isinstance(shares_raw, list):
        raise AclError("snapshot must have users and shares")
    if not isinstance(vols, list) or not all(isinstance(x, str) for x in vols):
        raise AclError("bad volumes")
    users: dict[str, tuple[int, bool]] = {}
    for name, u in users_raw.items():
        try:
            v.validate_username(name)
        except v.ValidationError as e:
            raise AclError("bad user name") from e
        if (
            not isinstance(u, dict)
            or type(u.get("cred")) is not int
            or type(u.get("remote")) is not bool
        ):
            raise AclError("bad user entry")
        users[name] = (u["cred"], u["remote"])
    shares: list[DavShare] = []
    for s in shares_raw:
        if not isinstance(s, dict) or set(s) != {"name", "path", "all_users", "members"}:
            raise AclError("bad share entry")
        name, path, all_users, members = s["name"], s["path"], s["all_users"], s["members"]
        if not isinstance(name, str) or not isinstance(path, str):
            raise AclError("bad share entry")
        try:
            v.validate_share_name(name)
            v.validate_path_text(path)
        except v.ValidationError as e:
            raise AclError("bad share entry") from e
        if all_users is not None and all_users not in ACCESS:
            raise AclError("bad all_users")
        if not isinstance(members, dict) or not all(
            isinstance(k, str) and val in ACCESS for k, val in members.items()
        ):
            raise AclError("bad members")
        shares.append(DavShare(name, path, dict(members), all_users))
    return users, shares, list(vols)


def parse_mountinfo(text: str) -> set[str]:
    """Mount points from /proc/self/mountinfo (field 5, octal escapes decoded)."""
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split(" ")
        if len(parts) > 4:
            out.add(_unescape(parts[4]))
    return out


def _unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 4 <= len(s) and s[i + 1 : i + 4].isdigit():
            out.append(chr(int(s[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def system_mountpoints() -> set[str]:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as f:
            return parse_mountinfo(f.read())
    except OSError:
        return set()


def is_system_mountpoint(path: str) -> bool:
    return path in system_mountpoints()


def is_volume_root(path: str, volumes: list[str]) -> bool:
    norm = os.path.normpath(path)
    return any(norm == os.path.normpath(vol) for vol in volumes)


class AclStore:
    def __init__(
        self,
        path: str,
        exposed: list[str],
        volumes: list[str],
        is_mountpoint: Callable[[str], bool] = is_system_mountpoint,
        on_reload: Callable[[AclSnapshot | None, AclSnapshot], None] | None = None,
    ) -> None:
        self.path = path
        self.exposed = {x.casefold() for x in exposed}
        self.volumes = list(volumes)
        self.is_mountpoint = is_mountpoint
        self.on_reload = on_reload
        self._lock = threading.Lock()
        self._key: tuple[int, int, int] | None = None
        self._snap: AclSnapshot | None = None
        self.all_shares: list[DavShare] = []
        self.all_volumes: list[str] = list(volumes)

    def current(self) -> AclSnapshot | None:
        try:
            st = os.stat(self.path)
        except OSError:
            self._set(None, None)
            return None
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._lock:
            if key == self._key:
                return self._snap
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
            users, shares, vols = _parse(raw)
        except (OSError, ValueError) as e:
            audit.event("dav_acl", ok=False, error=type(e).__name__)
            self._set(key, None)
            return None
        volumes = sorted(set(self.volumes) | set(vols))
        served: dict[str, DavShare] = {}
        for s in shares:
            if s.name.casefold() not in self.exposed:
                continue
            if is_volume_root(s.path, volumes):
                audit.event("dav_share_refused", share=s.name, reason="whole_volume")
                continue
            if not s.members and s.all_users is None:
                continue
            if not self.is_mountpoint(s.path):
                audit.event("dav_share_refused", share=s.name, reason="not_mounted")
                continue
            served[s.name.casefold()] = s
        snap = AclSnapshot(users, served, tuple(s.path for s in shares))
        self.all_shares = shares
        self.all_volumes = volumes
        self._set(key, snap)
        audit.event(
            "dav_acl", ok=True, users=len(users), served=sorted(x.name for x in served.values())
        )
        return snap

    def _set(self, key: tuple[int, int, int] | None, snap: AclSnapshot | None) -> None:
        with self._lock:
            old = self._snap
            self._key, self._snap = key, snap
        if snap is not None and self.on_reload is not None and old is not snap:
            self.on_reload(old, snap)

    def whole_volume_exposed(self) -> list[str]:
        """Exposed shares (by name) whose path is a volume root, from the last snapshot."""
        self.current()
        volumes = self.all_volumes
        return sorted(
            s.name
            for s in self.all_shares
            if s.name.casefold() in self.exposed and is_volume_root(s.path, volumes)
        )
