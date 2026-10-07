"""Plain data types shared by the web app and the root helper."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Access = Literal["ro", "rw"]
ACCESS_VALUES: tuple[str, ...] = ("ro", "rw")


@dataclass(frozen=True)
class ShareSpec:
    """A share as stored in the registry and sent to the helper.

    ``all_users`` grants every SMB user of this server access (login is still required;
    anonymous/guest access is impossible with the mandated global settings).
    ``no_unix_perms`` is set when the path lives on exFAT/vfat/ntfs and selects the
    macOS metadata settings that do not need extended attributes.
    """

    name: str
    path: str
    comment: str = ""
    members: dict[str, str] = field(default_factory=dict)
    all_users: str | None = None
    no_unix_perms: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ShareSpec:
        allowed = {"name", "path", "comment", "members", "all_users", "no_unix_perms"}
        unknown = set(d) - allowed
        if unknown:
            raise ValueError(f"unknown share fields: {sorted(unknown)}")
        members = d.get("members", {})
        if not isinstance(members, dict):
            raise ValueError("members must be a mapping")
        return cls(
            name=str(d["name"]),
            path=str(d["path"]),
            comment=str(d.get("comment", "")),
            members={str(k): str(val) for k, val in members.items()},
            all_users=None if d.get("all_users") is None else str(d["all_users"]),
            no_unix_perms=bool(d.get("no_unix_perms", False)),
        )
