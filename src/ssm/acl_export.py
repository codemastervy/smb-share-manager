"""Snapshot of users and shares for the WebDAV service (/run/ssm-dav/acl.json).

The WebDAV container never opens the registry database: it would need write access to
SQLite's WAL files, could read the admin sessions table, and /data is not mounted there.
Instead the admin app writes this small JSON file atomically after every registry change.
It contains no secrets: user names, their credential generation and remote-access flag,
and each share's name, path, members and all-users access.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any

from ssm import audit
from ssm.registry import Registry

ACL_FILE = "acl.json"
ACL_MODE = 0o640  # group smbusers (the WebDAV uid's group) may read it
FORMAT = 1


def build_acl(registry: Registry, volumes: list[str]) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "volumes": list(volumes),
        "users": {
            name: {"cred": gen, "remote": remote}
            for name, (gen, remote) in sorted(registry.user_flags().items())
        },
        "shares": [
            {
                "name": s.name,
                "path": s.path,
                "all_users": s.all_users,
                "members": dict(sorted(s.members.items())),
            }
            for s in registry.list_shares()
        ],
    }


class AclExporter:
    """Callable used as Registry.on_change. Never raises. A failed export removes the old
    snapshot, so the WebDAV service refuses every request rather than serve permissions
    that may no longer be true; the next successful export brings it back."""

    def __init__(
        self, registry: Registry, bridge_dir: str, volumes: list[str], gid: int | None = None
    ) -> None:
        self.registry = registry
        self.bridge_dir = bridge_dir
        self.volumes = list(volumes)
        self.gid = gid
        self._lock = threading.Lock()

    def __call__(self) -> None:
        if not os.path.isdir(self.bridge_dir):
            return  # WebDAV bridge not mounted: nothing to do
        with self._lock:
            try:
                self._write(json.dumps(build_acl(self.registry, self.volumes), sort_keys=True))
            except OSError as e:
                audit.event("acl_export", ok=False, error=e.strerror or str(e))
                try:
                    os.unlink(os.path.join(self.bridge_dir, ACL_FILE))
                except FileNotFoundError:
                    pass
                except OSError as e2:
                    audit.event(
                        "acl_export",
                        ok=False,
                        error="stale snapshot not removed",
                        detail=e2.strerror or str(e2),
                    )

    def _write(self, text: str) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.bridge_dir, prefix=".acl-", suffix=".tmp")
        try:
            # The group must be smbusers so the WebDAV container can read it. The setgid
            # bit on the folder can't be relied on (root without CAP_FSETID loses it).
            if self.gid is not None and os.fstat(fd).st_gid != self.gid:
                os.fchown(fd, -1, self.gid)
            with os.fdopen(fd, "w") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, ACL_MODE)
            os.replace(tmp, os.path.join(self.bridge_dir, ACL_FILE))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
