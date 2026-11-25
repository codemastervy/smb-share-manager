"""The files portal web app (its own container, never the admin app).

Who is asking comes from one header (PORTAL_IDENTITY_HEADER, default Remote-Email) that
Pangolin adds after its single sign-on. Because a header is only as trustworthy as whoever
set it, every rule below is fail-closed:

- Only a TCP peer in PORTAL_TRUSTED_PROXIES that also presents PORTAL_PROXY_SECRET (a
  custom header Pangolin adds) gets any answer, apart from /healthz; everything else gets
  403 before a header is read. The secret matters because the trusted range is usually a
  whole Docker network: another container on it could otherwise forge the identity
  header. The request must have come in over HTTPS.
- Exactly one identity header, holding one valid e-mail address. Two copies, a list, or
  anything odd is refused (a proxy that appends instead of replacing shows up as two).
- The e-mail must be linked to exactly one SMB user (admin UI), and that user must have
  remote access switched on.
- Until PORTAL_HEADER_VERIFIED=true (set after scripts/portal-spoof-test.sh passes against
  the live proxy) the portal is in setup mode: no file is reachable, only /api/portal/probe,
  which shows what identity header values arrived.

Authorisation is the WebDAV service's: the same ACL snapshot, the same exposed-shares
allowlist, the registry's ro/rw, re-read on every request. File work goes through
ssm.files (fd-based, O_NOFOLLOW, nothing ever overwritten).
"""

from __future__ import annotations

import hmac
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from ssm import audit
from ssm import validators as v
from ssm.auth import peer_is_trusted
from ssm.dav.acl import AclSnapshot, AclStore, DavShare
from ssm.files import COPY_TEMP_PREFIX, FileOpError, FileOps
from ssm.portal.settings import PortalSettings
from ssm.web.security import DOWNLOAD_CSP, SecurityMiddleware

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CSRF_HEADER = "x-ssm-portal"
SECRET_HEADER = b"x-portal-proxy-secret"
SETUP_MESSAGE = (
    "The files portal is in setup mode. Run scripts/portal-spoof-test.sh against it, "
    "then set PORTAL_HEADER_VERIFIED=true and restart smb-portal."
)
HIDDEN_PREFIXES = (v.UPLOAD_TEMP_PREFIX, COPY_TEMP_PREFIX)


async def _plain(send: Send, status: int, text: str) -> None:
    body = (text + "\n").encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class PeerGate:
    """Outermost check: trusted proxy, HTTPS, and a size cap on non-upload bodies."""

    def __init__(self, app: ASGIApp, settings: PortalSettings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/healthz":
            await self.app(scope, receive, send)
            return
        peer = (scope.get("client") or ("", 0))[0]
        if not peer_is_trusted(peer, self.settings.trusted_proxies):
            audit.event("portal_refused", peer=peer, reason="untrusted_peer")
            await _plain(send, 403, "Forbidden")
            return
        secrets = [val for k, val in scope.get("headers", []) if k == SECRET_HEADER]
        if len(secrets) != 1 or not hmac.compare_digest(
            secrets[0], self.settings.proxy_secret.encode()
        ):
            audit.event("portal_refused", peer=peer, reason="proxy_secret")
            await _plain(send, 403, "Forbidden")
            return
        protos = [val for k, val in scope.get("headers", []) if k == b"x-forwarded-proto"]
        if protos != [b"https"]:
            await _plain(send, 403, "HTTPS required")
            return
        if path != "/api/portal/upload":
            receive = self._capped(scope, receive)
        await self.app(scope, receive, send)

    def _capped(self, scope: Scope, receive: Receive) -> Receive:
        limit = self.settings.max_json_bytes
        seen = 0

        async def wrapped() -> Message:
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, "request body too large")
            return msg

        for k, val in scope.get("headers", []):
            if k == b"content-length" and val.isdigit() and int(val) > limit:

                async def refuse() -> Message:
                    raise HTTPException(413, "request body too large")

                return refuse
        return wrapped


@dataclass(frozen=True)
class Ctx:
    user: str
    email: str
    snap: AclSnapshot


@dataclass(frozen=True)
class Target:
    ops: FileOps
    real: str
    share: DavShare
    access: str
    vpath: str


class PathBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str


class NameBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    name: str


def _err(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail=detail)


def identity_values(request: Request, header: str) -> list[str]:
    raw = header.encode()
    return [val.decode("latin-1") for k, val in request.headers.raw if k == raw]


def create_portal_app(settings: PortalSettings, store: AclStore) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    frontend = Path(settings.frontend_dir)
    allowed_origins = {f"https://{h}" for h in settings.hosts}

    # Starlette's ServerErrorMiddleware turns an HTTPException raised in a receive wrapper
    # into 500; map it back to the status it carries.
    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    # --- identity --------------------------------------------------------------------------

    def snapshot() -> AclSnapshot:
        snap = store.current()
        if snap is None:
            raise _err(503, "The portal is not available right now.")
        return snap

    def identify(request: Request) -> Ctx:
        if not settings.header_verified:
            raise _err(503, SETUP_MESSAGE)
        snap = snapshot()
        values = identity_values(request, settings.identity_header)
        if not values:
            raise _err(401, "Not signed in. Open the portal through its sign-in page.")
        if len(values) != 1 or "," in values[0]:
            audit.event("portal_refused", reason="identity_header_ambiguous", count=len(values))
            raise _err(400, "Ambiguous identity; refusing the request.")
        try:
            email = v.validate_email(values[0])
        except v.ValidationError as e:
            audit.event("portal_refused", reason="identity_header_invalid")
            raise _err(403, "Your sign-in did not carry a usable e-mail address.") from e
        user = snap.user_by_email(email)
        flags = snap.user(user) if user else None
        if user is None or flags is None:
            audit.event("portal_refused", reason="not_linked")
            raise _err(
                403,
                f"{email} is not linked to a file account. Ask whoever runs the server "
                "to add it to your user.",
            )
        if not flags[1]:
            audit.event("portal_refused", user=user, reason="not_remote")
            raise _err(403, "Remote access is switched off for your account.")
        return Ctx(user, email, snap)

    def csrf(request: Request) -> None:
        """Cross-site pages can't set a custom header without a CORS preflight (which is
        never granted) and can't forge Origin; both are required for every change."""
        if request.headers.get(CSRF_HEADER) != "1":
            raise _err(403, "Missing request header.")
        origin = request.headers.get("origin", "")
        host = request.headers.get("host", "").lower()
        if origin not in allowed_origins or urlsplit(origin).netloc != host:
            raise _err(403, "Cross-site request refused.")

    def changer(request: Request) -> Ctx:
        csrf(request)
        return identify(request)

    # --- paths -----------------------------------------------------------------------------

    def target(ctx: Ctx, vpath: str, write: bool) -> Target:
        if (
            not isinstance(vpath, str)
            or not vpath.startswith("/")
            or len(vpath) > 4096
            or v.has_control_chars(vpath)
            or os.path.normpath(vpath) != vpath
            or vpath == "/"
        ):
            raise _err(400, "Bad path.")
        parts = vpath[1:].split("/")
        got = ctx.snap.share_for(ctx.user, parts[0])
        if got is None:
            raise _err(404, "Not found.")
        share, access = got
        if write and access != "rw":
            raise _err(403, f"You can only read {share.name}.")
        root = share.path
        if os.path.realpath(root) != root:
            raise _err(404, "Not found.")
        real = root if len(parts) == 1 else root + "/" + "/".join(parts[1:])
        snap = ctx.snap
        ops = FileOps([root], protected=lambda: list(snap.share_paths))
        try:
            ops.split(real)
        except FileOpError as e:
            raise _err(400, str(e)) from e
        return Target(ops, real, share, access, "/" + share.name + real[len(root) :])

    def file_error(e: FileOpError) -> HTTPException:
        msg = str(e)
        if msg in ("not found", "folder not found"):
            return _err(404, "Not found.")
        if "limit" in msg:
            return _err(413, msg)
        return _err(400, msg)

    # --- API -------------------------------------------------------------------------------

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        ok = store.current() is not None
        return PlainTextResponse("ok" if ok else "no snapshot", status_code=200 if ok else 503)

    @app.get("/api/portal/probe")
    async def probe(request: Request) -> Any:
        if settings.header_verified:
            raise _err(404, "Not found.")
        values = identity_values(request, settings.identity_header)
        audit.event("portal_probe", values=len(values))
        return {
            "setup_mode": True,
            "identity_header": settings.identity_header,
            "values": values,
        }

    @app.get("/api/portal/me")
    async def me(ctx: Ctx = Depends(identify)) -> Any:
        return {
            "user": ctx.user,
            "email": ctx.email,
            "max_upload_bytes": settings.max_upload_bytes,
            "shares": [
                {"name": s.name, "access": s.access_for(ctx.user)}
                for s in ctx.snap.visible(ctx.user)
            ],
        }

    @app.get("/api/portal/list")
    async def listing(path: str, ctx: Ctx = Depends(identify)) -> Any:
        t = target(ctx, path, write=False)
        try:
            entries = t.ops.list_dir(t.real)
        except FileOpError as e:
            raise file_error(e) from e
        return {
            "path": t.vpath,
            "share": t.share.name,
            "access": t.access,
            "entries": [
                {
                    "name": e.name,
                    "is_dir": e.kind == "dir",
                    "size": e.size if e.kind == "file" else None,
                    "modified": e.mtime,
                }
                for e in entries
                if e.kind in ("dir", "file") and not e.name.startswith(HIDDEN_PREFIXES)
            ],
        }

    @app.get("/api/portal/download")
    async def download(path: str, ctx: Ctx = Depends(identify)) -> Response:
        t = target(ctx, path, write=False)
        try:
            fd, size, fname = t.ops.open_download(t.real)
        except FileOpError as e:
            raise file_error(e) from e
        audit.event("portal_download", user=ctx.user, path=t.real)

        def stream() -> Iterator[bytes]:
            with os.fdopen(fd, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    yield chunk

        ascii_name = "".join(
            c if (c.isascii() and c.isalnum()) or c in "._- " else "_" for c in fname
        )
        return StreamingResponse(
            stream(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{ascii_name}"; '
                f"filename*=UTF-8''{quote(fname, safe='')}",
                "Content-Length": str(size),
                "Content-Security-Policy": DOWNLOAD_CSP,
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.put("/api/portal/upload", status_code=201)
    async def upload(request: Request, path: str, name: str, ctx: Ctx = Depends(changer)) -> Any:
        t = target(ctx, path, write=True)
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > settings.max_upload_bytes:
            raise _err(413, "upload exceeds the size limit")

        async def body() -> AsyncIterator[bytes]:
            async for chunk in request.stream():
                if chunk:
                    yield chunk

        try:
            final = await t.ops.upload(t.real, name, body(), settings.max_upload_bytes)
        except FileOpError as e:
            raise file_error(e) from e
        audit.event("portal_upload", user=ctx.user, path=t.real + "/" + final)
        return {"name": final}

    @app.post("/api/portal/mkdir", status_code=201)
    async def mkdir(body: NameBody, ctx: Ctx = Depends(changer)) -> Any:
        t = target(ctx, body.path, write=True)
        try:
            t.ops.mkdir(t.real, body.name)
        except FileOpError as e:
            raise file_error(e) from e
        audit.event("portal_mkdir", user=ctx.user, path=t.real + "/" + body.name)
        return {"name": body.name}

    @app.post("/api/portal/rename")
    async def rename(body: NameBody, ctx: Ctx = Depends(changer)) -> Any:
        t = target(ctx, body.path, write=True)
        try:
            new = t.ops.rename(t.real, body.name)
        except FileOpError as e:
            raise file_error(e) from e
        audit.event("portal_rename", user=ctx.user, path=t.real, to=new)
        return {"name": body.name}

    @app.post("/api/portal/delete")
    async def delete(body: PathBody, ctx: Ctx = Depends(changer)) -> Any:
        t = target(ctx, body.path, write=True)
        try:
            t.ops.delete(t.real, recursive=True)
        except FileOpError as e:
            raise file_error(e) from e
        audit.event("portal_delete", user=ctx.user, path=t.real)
        return {"deleted": t.vpath}

    @app.api_route(
        "/api/{rest:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def api_not_found(rest: str) -> Response:
        return JSONResponse({"detail": "not found"}, status_code=404)

    # --- the page --------------------------------------------------------------------------

    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/{rest:path}", include_in_schema=False)
    async def page(rest: str) -> Response:
        if not settings.header_verified:
            return PlainTextResponse(SETUP_MESSAGE + "\n", status_code=503)
        index = frontend / "portal.html"
        if not index.is_file():
            return PlainTextResponse("The portal page is not built.\n", status_code=503)
        return FileResponse(index, media_type="text/html; charset=utf-8")

    outer: Any = SecurityMiddleware(PeerGate(app, settings), allowed_hosts=settings.hosts)
    app.state.asgi = outer
    return app


def build_asgi(settings: PortalSettings, store: AclStore) -> ASGIApp:
    """The complete portal: host allow-list and headers, then the peer gate, then the app."""
    app = create_portal_app(settings, store)
    outer: ASGIApp = app.state.asgi
    return outer
