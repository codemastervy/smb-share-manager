"""The WebDAV WSGI application: a strict guard in front of WsgiDAV.

The guard runs first on every request and decides, in this order:
1. method allow-list;
2. HTTPS: X-Forwarded-Proto counts only from TRUSTED_PROXIES; plain HTTP is refused with
   403 and no WWW-Authenticate, so a client never sends the password in clear text;
3. the real client IP (X-Forwarded-For right-most untrusted entry, or CF-Connecting-IP
   when configured), only from TRUSTED_PROXIES; a trusted proxy that sends none is
   refused so the throttle can never fall back to the proxy's own address;
4. request size limits;
5. Basic credentials (see ssm.dav.auth for throttling and caching);
6. path, share and access checks (read-only members can't write, Destination must be a
   clean path on this host in a share the user may write, PROPFIND depth 0 or 1 only,
   a missing Overwrite header means F);
then hands the request to WsgiDAV and rewrites the response headers: security headers on
everything, attachment + octet-stream on downloads, no version banner, and error bodies
replaced by plain text so no HTML or internal detail ever leaves the service.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import time
import traceback
from collections.abc import Callable, Iterable, Iterator
from typing import Any
from urllib.parse import quote, unquote_to_bytes, urlsplit

from wsgidav.dav_error import DAVError
from wsgidav.error_printer import ErrorPrinter
from wsgidav.request_resolver import RequestResolver
from wsgidav.wsgidav_app import WsgiDAVApp

from ssm import audit
from ssm import validators as v
from ssm.auth import client_ip, peer_is_trusted
from ssm.dav.acl import AclSnapshot, AclStore
from ssm.dav.auth import Authenticator, CredCache, Notifier, Verifier
from ssm.dav.provider import (
    CTX_KEY,
    BoundedLockStorage,
    BoundedPropertyManager,
    RequestCtx,
    ShareProvider,
    split_path,
)
from ssm.dav.settings import DavSettings

StartResponse = Callable[..., Any]

READ_METHODS = frozenset({"OPTIONS", "PROPFIND", "GET", "HEAD", "UNLOCK"})
WRITE_METHODS = frozenset({"PUT", "MKCOL", "DELETE", "MOVE", "COPY", "PROPPATCH", "LOCK"})
ALLOWED_METHODS = READ_METHODS | WRITE_METHODS
# Request headers that only a trusted proxy may set; never passed on to WsgiDAV.
PROXY_HEADERS = (
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_FORWARDED_PROTO",
    "HTTP_X_FORWARDED_HOST",
    "HTTP_X_FORWARDED_PORT",
    "HTTP_X_FORWARDED_PREFIX",
    "HTTP_X_FORWARDED_SERVER",
    "HTTP_FORWARDED",
    "HTTP_X_REAL_IP",
    "HTTP_CF_CONNECTING_IP",
    "HTTP_TRUE_CLIENT_IP",
    "HTTP_X_ORIGINAL_URL",
    "HTTP_X_REWRITE_URL",
    "HTTP_X_OC_MTIME",
)
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'none'; sandbox"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    # Never let Cloudflare (or anything else) cache a user's files.
    ("Cache-Control", "private, no-store"),
    ("Server", "WebDAV"),
]
DROP_RESPONSE_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "cache-control",
        "content-security-policy",
        "x-content-type-options",
        "set-cookie",
        "x-frame-options",
        "referrer-policy",
    }
)
MAX_AUTH_HEADER = 1024
MAX_USER_LEN = 32
FINITE_DEPTH_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>'
)
STATUS_TEXT = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    412: "Precondition Failed",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    423: "Locked",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    507: "Insufficient Storage",
}


class _Refuse(Exception):
    def __init__(
        self,
        status: int,
        text: str = "",
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
        content_type: str = "text/plain; charset=utf-8",
    ):
        super().__init__(status)
        self.status = status
        self.text = text or STATUS_TEXT.get(status, "Error")
        self.headers = headers or []
        self.body = body
        self.content_type = content_type


class _LimitedInput:
    """wsgi.input that refuses to deliver more than `limit` bytes."""

    def __init__(self, stream: Any, limit: int) -> None:
        self._s = stream
        self._left = limit

    def _check(self, data: bytes) -> bytes:
        self._left -= len(data)
        if self._left < 0:
            raise DAVError(413)
        return data

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._left + 1
        return self._check(self._s.read(min(size, self._left + 1)))

    def readline(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._left + 1
        return self._check(self._s.readline(min(size, self._left + 1)))

    def __iter__(self) -> Iterator[bytes]:
        while True:
            line = self.readline()
            if not line:
                return
            yield line


class _Body:
    """Response iterable that yields an already-read first chunk, then the rest."""

    def __init__(self, first: bytes | None, rest: Iterator[bytes], orig: Iterable[bytes]) -> None:
        self._first = first
        self._rest = rest
        self._orig = orig

    def __iter__(self) -> Iterator[bytes]:
        if self._first is not None:
            yield self._first
        yield from self._rest

    def close(self) -> None:
        close = getattr(self._orig, "close", None)
        if close is not None:
            close()


def _status_code(status: str) -> int:
    try:
        return int(status.split(" ", 1)[0])
    except ValueError:
        return 500


def _attachment(name: str) -> str:
    ascii_name = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\;' else "_" for ch in name)
    return f"attachment; filename=\"{ascii_name or 'download'}\"; filename*=UTF-8''{quote(name)}"


class DavGuard:
    def __init__(
        self,
        settings: DavSettings,
        store: AclStore,
        auth: Authenticator,
        provider: ShareProvider,
        inner: Callable[[dict[str, Any], StartResponse], Iterable[bytes]],
    ) -> None:
        self.settings = settings
        self.store = store
        self.auth = auth
        self.provider = provider
        self.inner = inner

    # --- responses -----------------------------------------------------------------------

    def _send(self, start_response: StartResponse, r: _Refuse) -> list[bytes]:
        body = r.body if r.body is not None else (r.text + "\n").encode()
        headers = [
            ("Content-Type", r.content_type),
            ("Content-Length", str(len(body))),
            *SECURITY_HEADERS,
            *r.headers,
        ]
        start_response(f"{r.status} {STATUS_TEXT.get(r.status, 'Error')}", headers)
        return [body]

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        try:
            return self._handle(environ, start_response)
        except _Refuse as r:
            return self._send(start_response, r)
        except Exception:
            traceback.print_exc(limit=5)
            return self._send(start_response, _Refuse(500))

    # --- request checks ------------------------------------------------------------------

    def _scheme_and_client(self, environ: dict[str, Any]) -> tuple[bool, str]:
        peer = str(environ.get("REMOTE_ADDR", ""))
        trusted = peer_is_trusted(peer, self.settings.trusted_proxies)
        https = environ.get("wsgi.url_scheme") == "https"
        client = peer
        if trusted:
            proto = str(environ.get("HTTP_X_FORWARDED_PROTO", "")).strip().lower()
            https = https or proto == "https"
            if self.settings.real_ip_header == "cf-connecting-ip":
                raw = str(environ.get("HTTP_CF_CONNECTING_IP", "")).strip()
                try:
                    client = str(ipaddress.ip_address(raw))
                except ValueError:
                    client = ""
            else:
                xff = environ.get("HTTP_X_FORWARDED_FOR")
                client = client_ip(peer, xff, self.settings.trusted_proxies) if xff else ""
                if client == peer:
                    client = ""  # nothing usable: never key the throttle on the proxy
        for k in PROXY_HEADERS:
            environ.pop(k, None)
        if not https and not self.settings.allow_http:
            raise _Refuse(403, "HTTPS required")
        if trusted and not client:
            raise _Refuse(400, "Missing client address from proxy")
        environ["wsgi.url_scheme"] = "https" if https else "http"
        return https, client

    def _limits(self, environ: dict[str, Any], method: str) -> None:
        limit = self.settings.max_upload_bytes if method == "PUT" else self.settings.max_body_bytes
        raw = str(environ.get("CONTENT_LENGTH", "") or "").strip()
        if raw:
            if not raw.isdigit() or len(raw) > 20:
                raise _Refuse(400)
            if int(raw) > limit:
                raise _Refuse(413)
        environ["wsgi.input"] = _LimitedInput(environ["wsgi.input"], limit)

    def _credentials(self, environ: dict[str, Any]) -> tuple[str, str] | None:
        """(user, password) from a well-formed Basic header; None if absent or malformed."""
        header = str(environ.pop("HTTP_AUTHORIZATION", "") or "")
        if not header:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "basic" or not token or len(token) > MAX_AUTH_HEADER:
            return ("", "")
        try:
            decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return ("", "")
        user, sep, password = decoded.partition(":")
        if not sep or not password or len(password) > v.MAX_PASSWORD_LEN:
            return ("", "")
        if v.has_control_chars(password):
            return ("", "")
        return user, password

    def _authenticate(self, environ: dict[str, Any], client: str, snap: AclSnapshot) -> str:
        challenge = [("WWW-Authenticate", f'Basic realm="{self.settings.realm}", charset="UTF-8"')]
        creds = self._credentials(environ)
        if creds is None:
            raise _Refuse(401, "Authentication required", challenge)
        user, password = creds
        valid = len(user) <= MAX_USER_LEN and not v.has_control_chars(user)
        if valid:
            try:
                v.validate_username(user)
            except v.ValidationError:
                valid = False
        if not valid or not password:
            # Malformed: no helper call, but it counts against the client IP.
            now = self.auth.clock()
            with self.auth._lock:
                self.auth.peer_throttle.record_failure(client, now)
            audit.event(
                "dav_auth", result="fail", user="<invalid>", client=client, reason="malformed"
            )
            raise _Refuse(401, "Authentication required", challenge)
        result = self.auth.check(user, password, client, snap, log_user=user)
        if result.ok:
            return user
        if result.status == 503:
            raise _Refuse(503, "Temporarily unavailable")
        headers = list(challenge)
        if result.retry_after > 0:
            headers.append(("Retry-After", str(int(result.retry_after) + 1)))
        raise _Refuse(401, "Authentication required", headers)

    def _path_parts(self, raw: str) -> tuple[str, list[str]]:
        try:
            path = raw.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            raise _Refuse(400) from e
        if v.has_control_chars(path):
            raise _Refuse(400)
        try:
            return path, split_path(path or "/")
        except DAVError as e:
            raise _Refuse(400) from e

    def _destination(self, environ: dict[str, Any]) -> list[str]:
        raw = str(environ.get("HTTP_DESTINATION", "") or "")
        if not raw or len(raw) > 4096:
            raise _Refuse(400, "Destination required")
        parts = urlsplit(raw)
        if parts.query or parts.fragment:
            raise _Refuse(400)
        if parts.netloc and parts.netloc.lower() != str(environ.get("HTTP_HOST", "")).lower():
            raise _Refuse(400, "Destination must be on this server")
        if parts.scheme and parts.scheme.lower() not in ("http", "https"):
            raise _Refuse(400)
        try:
            dpath = unquote_to_bytes(parts.path).decode("utf-8")
        except UnicodeDecodeError as e:
            raise _Refuse(400) from e
        if v.has_control_chars(dpath):
            raise _Refuse(400)
        try:
            dparts = split_path(dpath or "/")
        except DAVError as e:
            raise _Refuse(400) from e
        # Hand WsgiDAV an unambiguous, same-scheme absolute URL.
        environ["HTTP_DESTINATION"] = (
            f"{environ['wsgi.url_scheme']}://{environ.get('HTTP_HOST', '')}{quote(dpath, safe='/')}"
        )
        return dparts

    def _authorise(
        self,
        environ: dict[str, Any],
        method: str,
        user: str,
        snap: AclSnapshot,
        path: str,
        parts: list[str],
    ) -> None:
        access: str | None = None
        if parts:
            hit = snap.share_for(user, parts[0])
            if hit is None:
                # Creating something at "/" is never allowed; everything else looks
                # the same for a foreign share and a missing one.
                if len(parts) == 1 and method in ("PUT", "MKCOL", "LOCK"):
                    raise _Refuse(403)
                raise _Refuse(404)
            access = hit[1]
        if method in ("COPY", "MOVE"):
            dparts = self._destination(environ)
            if len(dparts) < 2:
                raise _Refuse(403)
            dhit = snap.share_for(user, dparts[0])
            if dhit is None:
                raise _Refuse(404)
            if dhit[1] != "rw" or (method == "MOVE" and access != "rw"):
                raise _Refuse(403)
            ov = environ.get("HTTP_OVERWRITE")
            if ov is None:
                environ["HTTP_OVERWRITE"] = "F"  # stricter than RFC 4918's default
            elif ov not in ("T", "F"):
                raise _Refuse(400)
        elif method in WRITE_METHODS and access != "rw":
            raise _Refuse(403)
        if method == "PROPFIND":
            depth = environ.get("HTTP_DEPTH")
            if depth not in ("0", "1"):
                raise _Refuse(
                    403, body=FINITE_DEPTH_BODY, content_type="application/xml; charset=utf-8"
                )
        if method in ("GET", "HEAD"):
            probe = dict(environ)
            probe["wsgidav.provider"] = self.provider
            res = self.provider.get_resource_inst(path or "/", probe)
            if res is not None and res.is_collection:
                raise _Refuse(405, headers=[("Allow", "OPTIONS, PROPFIND")])

    def _handle(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "")).upper()
        if method not in ALLOWED_METHODS:
            raise _Refuse(405)
        _, client = self._scheme_and_client(environ)
        self._limits(environ, method)
        snap = self.store.current()
        if snap is None:
            raise _Refuse(503, "Temporarily unavailable")
        user = self._authenticate(environ, client, snap)
        path, parts = self._path_parts(str(environ.get("PATH_INFO", "") or "/"))
        environ[CTX_KEY] = RequestCtx(user, snap, self.settings.max_upload_bytes)
        environ["wsgidav.auth.user_name"] = user
        environ["wsgidav.auth.realm"] = self.settings.realm
        environ["wsgidav.auth.roles"] = []
        try:
            self._authorise(environ, method, user, snap, path, parts)
        except DAVError as e:
            raise _Refuse(e.value if isinstance(e.value, int) else 400) from e
        return self._forward(environ, start_response, method, parts)

    # --- response rewriting -------------------------------------------------------------

    def _forward(
        self,
        environ: dict[str, Any],
        start_response: StartResponse,
        method: str,
        parts: list[str],
    ) -> Iterable[bytes]:
        captured: dict[str, Any] = {}

        def sr(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            captured["status"], captured["headers"] = status, headers

            def write(_data: bytes) -> None:
                raise RuntimeError("write() is not supported")

            return write

        orig = self.inner(environ, sr)
        it = iter(orig)
        try:
            first: bytes | None = next(it)
        except StopIteration:
            first = None
        status = str(captured.get("status", "500 Internal Server Error"))
        headers: list[tuple[str, str]] = list(captured.get("headers", []))
        code = _status_code(status)
        ctype = next((val for k, val in headers if k.lower() == "content-type"), "")
        if code >= 400 and not ctype.lower().startswith(("application/xml", "text/xml")):
            close = getattr(orig, "close", None)
            if close is not None:
                close()
            extra = [(k, val) for k, val in headers if k.lower() in ("allow", "retry-after")]
            return self._send(start_response, _Refuse(code if code < 600 else 500, headers=extra))
        out = [(k, val) for k, val in headers if k.lower() not in DROP_RESPONSE_HEADERS]
        if method in ("GET", "HEAD") and code in (200, 206) and parts:
            out = [
                (k, val)
                for k, val in out
                if k.lower() not in ("content-type", "content-disposition")
            ]
            out.append(("Content-Type", "application/octet-stream"))
            out.append(("Content-Disposition", _attachment(parts[-1])))
        out.extend(SECURITY_HEADERS)
        start_response(status, out)
        return _Body(first, it, orig)


def build_app(
    settings: DavSettings,
    store: AclStore,
    verifier: Verifier,
    clock: Callable[[], float] = time.time,
    notify_sender: Callable[[dict[str, Any]], None] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> DavGuard:
    provider = ShareProvider()
    locks = BoundedLockStorage()
    config = {
        "provider_mapping": {"/": provider},
        "middleware_stack": [ErrorPrinter, RequestResolver],
        "lock_storage": locks,
        "property_manager": BoundedPropertyManager(),
        "verbose": 0,
        "logging": {"enable": False},
        "suppress_version_info": True,
        "add_header_MS_Author_Via": True,
        "dir_browser": {"enable": False},
        "http_authenticator": {
            "domain_controller": None,
            "accept_basic": False,
            "accept_digest": False,
            "default_to_digest": False,
        },
        "hotfixes": {"re_encode_path_info": True, "unquote_path_info": False},
        "block_size": 256 * 1024,
        "mutable_live_props": [],
        "honor_mtime_header": False,
    }
    inner = WsgiDAVApp(config)
    cache = CredCache(settings.auth_cache_s, clock)
    notifier = Notifier(settings.ntfy_url, settings.ntfy_token, clock, sender=notify_sender)
    auth = Authenticator(
        verifier,
        cache,
        notifier,
        clock,
        sleep=sleep if sleep is not None else (time.sleep if notify_sender is None else _no_sleep),
    )

    def on_reload(old: AclSnapshot | None, new: AclSnapshot) -> None:
        cache.prune(new)
        keep = {u for u, (_, remote) in new.users.items() if remote}
        locks.drop_principals(keep)

    store.on_reload = on_reload
    return DavGuard(settings, store, auth, provider, inner)


def _no_sleep(_seconds: float) -> None:
    pass
