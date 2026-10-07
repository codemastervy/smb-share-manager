"""Admin credential, server-side sessions and login throttling."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw

from ssm.registry import Registry, SessionRow

IDLE_TIMEOUT = 8 * 3600
ABSOLUTE_TIMEOUT = 7 * 24 * 3600


def _load_or_create_secret(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        data = path.read_bytes()
        if len(data) != 32:
            raise RuntimeError(f"{path} is corrupt; delete it to regenerate") from None
        return data
    data = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


class AdminCredential:
    """Verifies the admin password and fingerprints the configured credential.

    The fingerprint is stored with each session; when ADMIN_PASSWORD(_HASH) changes, every
    existing session stops matching and is revoked. For a plain password the fingerprint
    is an argon2id hash salted with a per-install secret, so the database alone does not
    allow a cheap offline guess.
    """

    def __init__(self, password: str | None, password_hash: str | None, secret_path: Path) -> None:
        self._ph = PasswordHasher()  # argon2id with library defaults
        secret = _load_or_create_secret(secret_path)
        if password_hash:
            self._hash = password_hash
            self.fingerprint = hashlib.sha256(secret + password_hash.encode()).hexdigest()
        elif password:
            self._hash = self._ph.hash(password)
            raw = hash_secret_raw(
                password.encode(),
                secret,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID,
            )
            self.fingerprint = raw.hex()
        else:
            raise ValueError("no admin credential configured")

    def verify(self, password: str) -> bool:
        try:
            return bool(self._ph.verify(self._hash, password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionManager:
    def __init__(self, registry: Registry, cred_fp: str, clock: Callable[[], float]) -> None:
        self.registry = registry
        self.cred_fp = cred_fp
        self.clock = clock

    def purge(self) -> None:
        now = self.clock()
        self.registry.purge_sessions(self.cred_fp, now - IDLE_TIMEOUT, now - ABSOLUTE_TIMEOUT)

    def create(self) -> tuple[str, str]:
        """Returns (cookie token, csrf token)."""
        self.purge()
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = self.clock()
        self.registry.create_session(SessionRow(hash_token(token), now, now, self.cred_fp, csrf))
        return token, csrf

    def validate(self, token: str | None) -> SessionRow | None:
        if not token or len(token) > 128:
            return None
        th = hash_token(token)
        row = self.registry.get_session(th)
        if row is None:
            return None
        now = self.clock()
        if (
            not hmac.compare_digest(row.cred_fp, self.cred_fp)
            or now - row.last_seen > IDLE_TIMEOUT
            or now - row.created > ABSOLUTE_TIMEOUT
        ):
            self.registry.delete_session(th)
            return None
        self.registry.touch_session(th, now)
        return row

    def revoke(self, token: str | None) -> None:
        if token:
            self.registry.delete_session(hash_token(token))


class LoginThrottle:
    """Exponential backoff per client address, with bounded memory (LRU eviction)."""

    def __init__(self, max_entries: int = 4096, base: float = 1.0, cap: float = 900.0) -> None:
        self.max_entries = max_entries
        self.base = base
        self.cap = cap
        self._entries: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def _delay(self, failures: int) -> float:
        if failures <= 0:
            return 0.0
        return float(min(self.cap, self.base * (2 ** min(failures - 1, 30))))

    def retry_after(self, key: str, now: float) -> float:
        entry = self._entries.get(key)
        if entry is None:
            return 0.0
        failures, last = entry
        return max(0.0, last + self._delay(failures) - now)

    def record_failure(self, key: str, now: float) -> None:
        failures, last = self._entries.pop(key, (0, now))
        # Forget old history once a full cap-length period has passed quietly.
        if now - last > 2 * self.cap:
            failures = 0
        self._entries[key] = (failures + 1, now)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def record_success(self, key: str) -> None:
        self._entries.pop(key, None)


def _in_nets(addr: str, nets: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n, strict=False) for n in nets)


def peer_is_trusted(peer: str, trusted_proxies: list[str]) -> bool:
    return bool(trusted_proxies) and _in_nets(peer, trusted_proxies)


def client_ip(peer: str, xff: str | None, trusted_proxies: list[str]) -> str:
    """The real client address. X-Forwarded-For is honoured only from a trusted proxy,
    and then the right-most untrusted entry is used (entries to its left are spoofable)."""
    if not xff or not trusted_proxies or not _in_nets(peer, trusted_proxies):
        return peer
    for part in reversed([p.strip() for p in xff.split(",")]):
        try:
            ipaddress.ip_address(part)
        except ValueError:
            return peer
        if not _in_nets(part, trusted_proxies):
            return part
    return peer
