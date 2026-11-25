"""SQLite registry: SMB users, shares, members and admin sessions.

SQLite (stdlib) gives atomic multi-row updates (a share and its members change together)
and survives container recreation in ./data. The registry is the source of truth: on
start the app pushes it to the root helper.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Callable
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
        self._migrate()
        os.chmod(path, 0o600)
        # Called after every committed change to users or shares (the WebDAV snapshot).
        self.on_change: Callable[[], None] | None = None

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def _next_gen(self, current: int) -> int:
        """A credential generation larger than any used before (microsecond clock), so a
        re-created user never repeats a value a cached credential could hold."""
        return max(current + 1, time.time_ns() // 1000)

    def _migrate(self) -> None:
        """Additive, backwards-compatible schema changes only (rollbacks must keep working)."""
        with self._lock:
            ucols = {r[1] for r in self._db.execute("PRAGMA table_info(users)")}
            if "display_name" not in ucols:
                self._db.execute(
                    "ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"
                )
            scols = {r[1] for r in self._db.execute("PRAGMA table_info(shares)")}
            if "created" not in scols:
                self._db.execute("ALTER TABLE shares ADD COLUMN created REAL NOT NULL DEFAULT 0")
            if "cred_gen" not in ucols:
                self._db.execute("ALTER TABLE users ADD COLUMN cred_gen INTEGER NOT NULL DEFAULT 0")
            if "remote_access" not in ucols:
                self._db.execute(
                    "ALTER TABLE users ADD COLUMN remote_access INTEGER NOT NULL DEFAULT 0"
                )
            if "email" not in ucols:
                self._db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email) WHERE email != ''"
            )

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

    def user_details(self) -> list[tuple[str, str, float]]:
        """[(name, display_name, created)] ordered by name."""
        with self._lock:
            return [
                (r[0], r[1], r[2])
                for r in self._db.execute(
                    "SELECT name, display_name, created FROM users ORDER BY name"
                )
            ]

    def set_display_name(self, name: str, display_name: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET display_name = ? WHERE name = ?", (display_name, name)
            )
        self._changed()

    def add_user(self, name: str, now: float, display_name: str = "") -> None:
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (name, created, display_name, cred_gen) VALUES (?, ?, ?, ?)",
                    (name, now, display_name, self._next_gen(0)),
                )
            except sqlite3.IntegrityError as e:
                raise RegistryError(f"user {name!r} already exists") from e
        self._changed()

    def delete_user(self, name: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM users WHERE name = ?", (name,))
        self._changed()

    def user_flags(self) -> dict[str, tuple[int, bool]]:
        """{name: (credential generation, remote access)}."""
        with self._lock:
            return {
                r[0]: (int(r[1]), bool(r[2]))
                for r in self._db.execute("SELECT name, cred_gen, remote_access FROM users")
            }

    def bump_cred(self, name: str) -> None:
        """Invalidate every cached WebDAV credential of this user (password change)."""
        with self._lock:
            row = self._db.execute("SELECT cred_gen FROM users WHERE name = ?", (name,)).fetchone()
            if row is None:
                return
            self._db.execute(
                "UPDATE users SET cred_gen = ? WHERE name = ?", (self._next_gen(row[0]), name)
            )
        self._changed()

    def set_remote_access(self, name: str, enabled: bool) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET remote_access = ? WHERE name = ?", (int(enabled), name)
            )
        self._changed()

    def user_emails(self) -> dict[str, str]:
        """{name: e-mail} for users that have one (lower case)."""
        with self._lock:
            return {
                r[0]: r[1]
                for r in self._db.execute("SELECT name, email FROM users WHERE email != ''")
            }

    def set_email(self, name: str, email: str) -> None:
        """Link a user to the e-mail the files portal identifies them by ('' unlinks).
        The caller validates and lower-cases it; one e-mail belongs to one user."""
        with self._lock:
            try:
                self._db.execute("UPDATE users SET email = ? WHERE name = ?", (email, name))
            except sqlite3.IntegrityError as e:
                raise RegistryError("that e-mail address is already linked to another user") from e
        self._changed()

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

    def share_created(self) -> dict[str, float]:
        with self._lock:
            return {r[0]: r[1] for r in self._db.execute("SELECT name, created FROM shares")}

    def save_share(
        self, spec: ShareSpec, old_name: str | None = None, created: float = 0.0
    ) -> None:
        """Insert or replace a share and its members in one transaction."""
        with self._lock:
            cur = self._db.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if old_name is not None:
                    row = cur.execute(
                        "SELECT created FROM shares WHERE name = ?", (old_name,)
                    ).fetchone()
                    if row and not created:
                        created = row[0]
                    cur.execute("DELETE FROM shares WHERE name = ?", (old_name,))
                existing = cur.execute(
                    "SELECT name FROM shares WHERE name = ?", (spec.name,)
                ).fetchone()
                if existing is not None:
                    raise RegistryError(f"a share named {spec.name!r} already exists")
                cur.execute(
                    "INSERT INTO shares (name, path, comment, all_users, no_unix_perms, created) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        spec.name,
                        spec.path,
                        spec.comment,
                        spec.all_users,
                        int(spec.no_unix_perms),
                        created,
                    ),
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
        self._changed()

    def delete_share(self, name: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM shares WHERE name = ?", (name,))
        self._changed()

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
