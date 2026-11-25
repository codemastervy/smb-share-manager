"""WebDAV authentication: Basic credentials checked by the root helper, throttled per user
and per real client IP, with a short-lived cache of verified credentials.

Order for every request (see Authenticator.check):
1. A credential that matches a valid cache entry passes. The cache holds an HMAC of the
   password under a random per-process key, never the password, and every entry is tied
   to the user's credential generation from the ACL snapshot. A cache hit proves the
   caller knows the password, so it is allowed even while the user is locked out: an
   attacker hammering a name can't disconnect that user's already-verified devices.
2. If the client IP or the user is backing off: refuse without checking the password
   (no guessing oracle during a lockout).
3. Unknown users and users without remote access are refused without a helper call,
   after a delay similar to a real check, and count as failures.
4. Otherwise the helper verifies the password against the Samba NT hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import urllib.request
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ssm import audit
from ssm.auth import LoginThrottle
from ssm.dav.acl import AclSnapshot
from ssm.helper_client import HelperError

USER_FREE_FAILURES = 5
LOCKOUT_CAP = 900.0
NOTIFY_PER_USER_S = 3600.0
NOTIFY_GLOBAL_PER_HOUR = 10


class Verifier(Protocol):
    def verify(self, name: str, password: str) -> bool: ...


class BackoffThrottle(LoginThrottle):
    """LoginThrottle that tolerates `free` failures before backing off."""

    def __init__(
        self, free: int = 0, base: float = 1.0, cap: float = LOCKOUT_CAP, max_entries: int = 4096
    ) -> None:
        super().__init__(max_entries=max_entries, base=base, cap=cap)
        self.free = free

    def _delay(self, failures: int) -> float:
        over = failures - self.free
        if over <= 0:
            return 0.0
        return float(min(self.cap, self.base * (2 ** min(over - 1, 30))))

    def failures(self, key: str) -> int:
        entry = self._entries.get(key)
        return entry[0] if entry else 0


class CredCache:
    def __init__(self, ttl: float, clock: Callable[[], float], max_entries: int = 1024) -> None:
        self.ttl = ttl
        self.clock = clock
        self.max_entries = max_entries
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, bytes], tuple[int, float]] = OrderedDict()

    def _digest(self, user: str, password: str) -> bytes:
        msg = user.encode() + b"\x00" + password.encode("utf-8", "surrogatepass")
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def hit(self, user: str, password: str, gen: int) -> bool:
        if self.ttl <= 0:
            return False
        k = (user, self._digest(user, password))
        with self._lock:
            entry = self._entries.get(k)
            if entry is None:
                return False
            cached_gen, at = entry
            if cached_gen != gen or self.clock() - at > self.ttl:
                del self._entries[k]
                return False
            self._entries.move_to_end(k)
            return True

    def store(self, user: str, password: str, gen: int) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            self._entries[(user, self._digest(user, password))] = (gen, self.clock())
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def prune(self, snapshot: AclSnapshot) -> None:
        """Drop entries of users that are gone, lost remote access or changed password."""
        with self._lock:
            for k in list(self._entries):
                u = snapshot.user(k[0])
                if u is None or not u[1] or u[0] != self._entries[k][0]:
                    del self._entries[k]

    def __len__(self) -> int:
        return len(self._entries)


def _post_ntfy(msg: dict[str, Any]) -> None:
    req = urllib.request.Request(  # noqa: S310  # nosec B310 - scheme checked in settings
        msg["url"], data=msg["body"].encode(), method="POST", headers=msg["headers"]
    )
    with urllib.request.urlopen(req, timeout=5):  # noqa: S310  # nosec B310
        pass


class Notifier:
    """ntfy notification when a per-user lockout starts. Rate-limited per user and
    globally; sending happens on a background thread and never affects a request."""

    def __init__(
        self,
        url: str | None,
        token: str | None,
        clock: Callable[[], float],
        sender: Callable[[dict[str, Any]], None] | None = None,
        background: bool = True,
    ) -> None:
        self.url = url
        self.token = token
        self.clock = clock
        self.sender = sender or _post_ntfy
        self.background = background and sender is None
        self._lock = threading.Lock()
        self._last_user: OrderedDict[str, float] = OrderedDict()
        self._recent: list[float] = []
        self.dropped = 0

    def lockout(self, user: str, failures: int, client: str) -> None:
        if not self.url:
            return
        now = self.clock()
        with self._lock:
            last = self._last_user.get(user)
            self._recent = [t for t in self._recent if now - t < 3600]
            if (last is not None and now - last < NOTIFY_PER_USER_S) or len(
                self._recent
            ) >= NOTIFY_GLOBAL_PER_HOUR:
                self.dropped += 1
                audit.event("dav_notify", ok=False, reason="rate_limited", user=user)
                return
            self._last_user[user] = now
            self._last_user.move_to_end(user)
            while len(self._last_user) > 4096:
                self._last_user.popitem(last=False)
            self._recent.append(now)
        headers = {"Title": "WebDAV lockout", "Tags": "warning", "Priority": "high"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        msg = {
            "url": self.url,
            "headers": headers,
            "body": (
                f"WebDAV: user {user} locked out after {failures} failed logins, "
                f"last from {client}."
            ),
        }
        if self.background:
            threading.Thread(target=self._send, args=(msg,), daemon=True).start()
        else:
            self._send(msg)

    def _send(self, msg: dict[str, Any]) -> None:
        try:
            self.sender(msg)
        except Exception as e:  # never let a notification failure reach a request
            audit.event("dav_notify", ok=False, reason="send_failed", error=type(e).__name__)
        else:
            audit.event("dav_notify", ok=True)


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    status: int = 401  # 401 refused, 503 helper unavailable
    retry_after: float = 0.0


class Authenticator:
    def __init__(
        self,
        verifier: Verifier,
        cache: CredCache,
        notifier: Notifier,
        clock: Callable[[], float],
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.verifier = verifier
        self.cache = cache
        self.notifier = notifier
        self.clock = clock
        self.sleep = sleep
        self.peer_throttle = BackoffThrottle(free=0, base=1.0)
        self.user_throttle = BackoffThrottle(free=USER_FREE_FAILURES, base=2.0)
        self._lock = threading.Lock()
        self._verify_time = 0.05  # running estimate of a helper check, for equal timing

    def _log(self, result: str, user: str, client: str, reason: str = "") -> None:
        fields: dict[str, Any] = {"result": result, "user": user, "client": client}
        if reason:
            fields["reason"] = reason
        audit.event("dav_auth", **fields)

    def _failure(self, user: str, client: str, reason: str, known: bool = True) -> AuthResult:
        """Count a failure. Names that are not in the snapshot count against the client
        only: otherwise sprayed junk names could evict a real user's lockout entry from
        the bounded per-user table."""
        now = self.clock()
        started, failures = False, 0
        with self._lock:
            self.peer_throttle.record_failure(client, now)
            if known:
                before = self.user_throttle.retry_after(user, now) > 0
                self.user_throttle.record_failure(user, now)
                failures = self.user_throttle.failures(user)
                started = not before and self.user_throttle.retry_after(user, now) > 0
        self._log("fail", user, client, reason)
        if started:
            audit.event("dav_lockout", user=user, client=client, failures=failures)
            self.notifier.lockout(user, failures, client)
        return AuthResult(False)

    def check(
        self, user: str, password: str, client: str, snap: AclSnapshot, log_user: str
    ) -> AuthResult:
        """`user` must already be a syntactically valid username; `log_user` is what may
        appear in the audit log."""
        info = snap.user(user)
        if info is not None and info[1] and self.cache.hit(user, password, info[0]):
            return AuthResult(True)

        now = self.clock()
        with self._lock:
            wait = max(
                self.peer_throttle.retry_after(client, now),
                self.user_throttle.retry_after(user, now),
            )
        if wait > 0:
            self._log("locked", log_user, client, "locked")
            return AuthResult(False, retry_after=wait)

        if info is None or not info[1]:
            self.sleep(min(self._verify_time, 0.5))
            if info is None:
                return self._failure(log_user, client, "unknown_user", known=False)
            return self._failure(user, client, "not_remote")

        start = time.monotonic()
        try:
            ok = self.verifier.verify(user, password)
        except HelperError:
            audit.event(
                "dav_auth",
                result="error",
                user=log_user,
                client=client,
                reason="helper_unavailable",
            )
            return AuthResult(False, status=503)
        elapsed = time.monotonic() - start
        self._verify_time = 0.8 * self._verify_time + 0.2 * elapsed
        if not ok:
            return self._failure(user, client, "bad_password")
        with self._lock:
            self.peer_throttle.record_success(client)
            self.user_throttle.record_success(user)
        self.cache.store(user, password, info[0])
        self._log("ok", user, client)
        return AuthResult(True)
