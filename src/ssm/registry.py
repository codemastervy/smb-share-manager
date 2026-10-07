"""SQLite registry: SMB users, shares, members and admin sessions.

SQLite (stdlib) gives atomic multi-row updates (a share and its members change together)
and survives container recreation in ./data. The registry is the source of truth: on
start the app pushes it to the root helper.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

from ssm.models import ShareSpec

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    path TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    all_users TEXT CHECK (all_users IN ('ro', 'rw')),
    no_unix_perms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS share_members (
    share TEXT NOT NULL REFERENCES shares(name) ON DELETE CASCADE ON UPDATE CASCADE,
    user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    access TEXT NOT NULL CHECK (access IN ('ro', 'rw')),
    PRIMARY KEY (share, user)
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created REAL NOT NULL,
    last_seen REAL NOT NULL,
    cred_fp TEXT NOT NULL,
    csrf TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class SessionRow:
    token_hash: str
    created: float
    last_seen: float
    cred_fp: str
    csrf: str


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript(SCHEMA)
        os.chmod(path, 0o600)

    def close(self) -> None:
        self._db.close()

    # --- users -----------------------------------------------------------------------

    def list_users(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._db.execute("SELECT name FROM users ORDER BY name")]

    def has_user(self, name: str) -> bool:
        with self._lock:
            r = self._db.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone()
        return r is not None

    def add_user(self, name: str, now: float) -> None:
        with self._lock:
            try:
                self._db.execute("INSERT INTO users (name, created) VALUES (?, ?)", (name, now))
            except sqlite3.IntegrityError as e:
                raise RegistryError(f"user {name!r} already exists") from e

    def delete_user(self, name: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM users WHERE name = ?", (name,))

    def shares_only_reachable_by(self, name: str) -> list[str]:
        """Shares that would become unreachable if this user were deleted."""
        out = []
        for s in self.list_shares():
            if s.all_users is None and set(s.members) == {name}:
                out.append(s.name)
        return out

    # --- shares ----------------------------------------------------------------------

    def list_shares(self) -> list[ShareSpec]:
        with self._lock:
            rows = self._db.execute(
                "SELECT name, path, comment, all_users, no_unix_perms FROM shares ORDER BY name"
            ).fetchall()
            members = self._db.execute(
                "SELECT share, user, access FROM share_members ORDER BY user"
            ).fetchall()
        by_share: dict[str, dict[str, str]] = {}
        for share, user, access in members:
            by_share.setdefault(share.lower(), {})[user] = access
        return [
            ShareSpec(
                name=n,
                path=p,
                comment=c,
                members=by_share.get(n.lower(), {}),
                all_users=a,
                no_unix_perms=bool(x),
            )
            for n, p, c, a, x in rows
        ]

    def get_share(self, name: str) -> ShareSpec | None:
        for s in self.list_shares():
            if s.name.lower() == name.lower():
                return s
        return None

    def save_share(self, spec: ShareSpec, old_name: str | None = None) -> None:
        """Insert or replace a share and its members in one transaction."""
        with self._lock:
            cur = self._db.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if old_name is not None:
                    cur.execute("DELETE FROM shares WHERE name = ?", (old_name,))
                existing = cur.execute(
                    "SELECT name FROM shares WHERE name = ?", (spec.name,)
                ).fetchone()
                if existing is not None:
                    raise RegistryError(f"a share named {spec.name!r} already exists")
                cur.execute(
                    "INSERT INTO shares (name, path, comment, all_users, no_unix_perms) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (spec.name, spec.path, spec.comment, spec.all_users, int(spec.no_unix_perms)),
                )
                for user, access in spec.members.items():
                    cur.execute(
                        "INSERT INTO share_members (share, user, access) VALUES (?, ?, ?)",
                        (spec.name, user, access),
                    )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise

    def delete_share(self, name: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM shares WHERE name = ?", (name,))

    # --- sessions --------------------------------------------------------------------

    def create_session(self, row: SessionRow) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions (token_hash, created, last_seen, cred_fp, csrf) "
                "VALUES (?, ?, ?, ?, ?)",
                (row.token_hash, row.created, row.last_seen, row.cred_fp, row.csrf),
            )

    def get_session(self, token_hash: str) -> SessionRow | None:
        with self._lock:
            r = self._db.execute(
                "SELECT token_hash, created, last_seen, cred_fp, csrf FROM sessions "
                "WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return SessionRow(*r) if r else None

    def touch_session(self, token_hash: str, now: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash)
            )

    def delete_session(self, token_hash: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def purge_sessions(self, cred_fp: str, idle_before: float, created_before: float) -> None:
        """Remove sessions for an old credential and sessions past either timeout."""
        with self._lock:
            self._db.execute(
                "DELETE FROM sessions WHERE cred_fp != ? OR last_seen < ? OR created < ?",
                (cred_fp, idle_before, created_before),
            )
