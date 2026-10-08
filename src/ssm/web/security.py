"""ASGI middleware: Host allowlist and security headers on every response."""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; "
    "frame-ancestors 'none'"
)
DOWNLOAD_CSP = "default-src 'none'; sandbox; frame-ancestors 'none'"

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on POSTs,
    # which the CSRF Origin check (correctly) rejects. Nothing leaks cross-site.
    (b"referrer-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    (b"cache-control", b"no-store"),
]


def host_without_port(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else ""
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def host_allowed(host_header: str, allowed: list[str]) -> bool:
    h = host_without_port(host_header)
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True  # IP literals cannot be used for DNS rebinding
    except ValueError:
        pass
    return h == "localhost" or h in allowed


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        self.app = app
        self.allowed_hosts = [h.lower() for h in allowed_hosts]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, val) for k, val in message.get("headers", []) if k.lower() != b"server"
                ]
                present = {k.lower() for k, _ in headers}
                for k, val in SECURITY_HEADERS:
                    if k not in present:
                        headers.append((k, val))
                message["headers"] = headers
            await send(message)

        host = ""
        for k, val in scope.get("headers", []):
            if k == b"host":
                host = val.decode("latin-1")
                break
        if not host_allowed(host, self.allowed_hosts):
            body = b"Bad Request: host not allowed. Add it to ALLOWED_HOSTS.\n"
            await send_with_headers(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send_with_headers)
