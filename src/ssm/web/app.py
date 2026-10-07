"""FastAPI application: server-rendered pages, no public API."""

from __future__ import annotations

import hmac
import os
import secrets
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ssm import audit, fsinfo, importer
from ssm import validators as v
from ssm.auth import AdminCredential, LoginThrottle, SessionManager, client_ip, peer_is_trusted
from ssm.files import FileOpError, FileOps
from ssm.helper_client import Helper, HelperClient, HelperError
from ssm.models import ShareSpec
from ssm.registry import Registry, RegistryError, SessionRow
from ssm.settings import ConfigError, Settings
from ssm.web.security import DOWNLOAD_CSP, SecurityMiddleware

HERE = Path(__file__).parent
SESSION_COOKIE = "ssm_session"
PRELOGIN_COOKIE = "ssm_pre"


class NotAuthenticated(Exception):
    pass


class Forbidden(Exception):
    pass


def create_app(
    settings: Settings,
    helper: Helper | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    settings.check()
    try:
        volumes = v.validate_volumes(settings.volumes)
    except v.ValidationError as e:
        raise ConfigError(f"VOLUMES: {e}") from e
    if not volumes:
        raise ConfigError("VOLUMES is empty; set it to the folders you want to share.")

    data = Path(settings.data_dir) / "app"
    registry = Registry(data / "registry.db")
    cred = AdminCredential(settings.admin_password, settings.admin_password_hash, data / "secret")
    sessions = SessionManager(registry, cred.fingerprint, clock)
    sessions.purge()
    throttle = LoginThrottle()
    helper_ = helper if helper is not None else HelperClient(settings.helper_socket)
    fileops = FileOps(volumes, protected=lambda: [s.path for s in registry.list_shares()])

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware, allowed_hosts=settings.allowed_hosts)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    app.state.registry = registry
    app.state.helper = helper_

    # --- helpers ---------------------------------------------------------------------

    def peer(request: Request) -> str:
        host = request.client.host if request.client else ""
        return client_ip(host, request.headers.get("x-forwarded-for"), settings.trusted_proxies)

    def scheme(request: Request) -> str:
        host = request.client.host if request.client else ""
        if peer_is_trusted(host, settings.trusted_proxies):
            proto = request.headers.get("x-forwarded-proto", "").lower()
            if proto in ("http", "https"):
                return proto
        return request.url.scheme

    def cookie_secure(request: Request) -> bool:
        if settings.cookie_secure == "true":
            return True
        if settings.cookie_secure == "false":
            return False
        return scheme(request) == "https"

    def check_origin(request: Request) -> None:
        expected = f"{scheme(request)}://{request.headers.get('host', '')}".lower()
        origin = request.headers.get("origin")
        if origin is None:
            ref = request.headers.get("referer")
            if not ref:
                raise Forbidden("missing Origin")
            parts = urlsplit(ref)
            origin = f"{parts.scheme}://{parts.netloc}"
        if origin.lower() != expected:
            raise Forbidden("cross-origin request")

    async def submitted_csrf(request: Request) -> str:
        token = request.headers.get("x-csrf-token")
        if token:
            return token
        ctype = request.headers.get("content-type", "")
        if ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()
            val = form.get("csrf_token")
            return val if isinstance(val, str) else ""
        return ""

    def session_of(request: Request) -> SessionRow:
        row = sessions.validate(request.cookies.get(SESSION_COOKIE))
        if row is None:
            raise NotAuthenticated()
        return row

    async def require_read(request: Request) -> SessionRow:
        return session_of(request)

    async def require_write(request: Request) -> SessionRow:
        row = session_of(request)
        check_origin(request)
        token = await submitted_csrf(request)
        if not token or not hmac.compare_digest(token, row.csrf):
            raise Forbidden("invalid CSRF token")
        return row

    def import_mounted() -> bool:
        # /import is root-only (it holds password hashes); its presence is enough.
        return os.path.isdir(settings.import_dir)

    def render(
        request: Request,
        name: str,
        ctx: dict[str, Any],
        status: int = 200,
        session: SessionRow | None = None,
    ) -> Response:
        base = {
            "csrf": session.csrf if session else ctx.get("csrf", ""),
            "logged_in": session is not None,
            "version": settings.version,
            "build_date": settings.build_date,
            "import_mounted": session is not None and import_mounted(),
            "msg": request.query_params.get("msg", "")[:300],
            "err": request.query_params.get("err", "")[:300],
        }
        return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status)

    def back(url: str, msg: str = "", err: str = "") -> RedirectResponse:
        q = {k: val for k, val in (("msg", msg), ("err", err)) if val}
        sep = "&" if "?" in url else "?"
        return RedirectResponse(url + (sep + urlencode(q) if q else ""), status_code=303)

    async def form_dict(request: Request) -> dict[str, str]:
        form = await request.form()
        return {k: val for k, val in form.items() if isinstance(val, str)}

    def share_view(s: ShareSpec) -> dict[str, Any]:
        return {"spec": s, "fs": fsinfo.fs_type(s.path), "no_unix": s.no_unix_perms}

    def apply(new_shares: list[ShareSpec]) -> None:
        helper_.apply_shares(new_shares)

    # --- exception handlers ----------------------------------------------------------

    @app.exception_handler(NotAuthenticated)
    async def _not_auth(request: Request, exc: NotAuthenticated) -> Response:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden) -> Response:
        return Response(f"Forbidden: {exc}\n", status_code=403, media_type="text/plain")

    # --- public ----------------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            {"status": "ok", "version": settings.version, "build_date": settings.build_date}
        )

    @app.get("/login")
    async def login_page(request: Request) -> Response:
        if sessions.validate(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse("/shares", status_code=303)
        pre = secrets.token_urlsafe(32)
        resp = render(request, "login.html", {"csrf": pre})
        resp.set_cookie(
            PRELOGIN_COOKIE,
            pre,
            max_age=3600,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(request),
            path="/login",
        )
        return resp

    @app.post("/login")
    async def login_submit(request: Request) -> Response:
        check_origin(request)
        form = await form_dict(request)
        pre = request.cookies.get(PRELOGIN_COOKIE, "")
        token = form.get("csrf_token", "")
        if not pre or not token or not hmac.compare_digest(pre, token):
            raise Forbidden("invalid CSRF token")
        ip = peer(request)
        now = clock()
        wait = throttle.retry_after(ip, now)
        if wait > 0:
            audit.event("login_throttled", peer=ip, retry_after=round(wait))
            return render(
                request,
                "login.html",
                {"csrf": pre, "error": f"Too many attempts. Try again in {int(wait) + 1} s."},
                status=429,
            )
        if not cred.verify(form.get("password", "")):
            throttle.record_failure(ip, now)
            audit.event("login_failed", peer=ip)
            return render(
                request, "login.html", {"csrf": pre, "error": "Wrong password."}, status=401
            )
        throttle.record_success(ip)
        token, _csrf = sessions.create()
        audit.event("login_ok", peer=ip)
        resp = RedirectResponse("/shares", status_code=303)
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(request),
            path="/",
        )
        resp.delete_cookie(PRELOGIN_COOKIE, path="/login")
        return resp

    @app.post("/logout")
    async def logout(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        sessions.revoke(request.cookies.get(SESSION_COOKIE))
        audit.event("logout", peer=peer(request))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # --- shares ----------------------------------------------------------------------

    @app.get("/")
    async def index(s: SessionRow = Depends(require_read)) -> Response:
        return RedirectResponse("/shares", status_code=303)

    @app.get("/shares")
    async def shares_list(request: Request, s: SessionRow = Depends(require_read)) -> Response:
        shares = [share_view(x) for x in registry.list_shares()]
        return render(request, "shares.html", {"shares": shares}, session=s)

    def share_form_ctx(spec: ShareSpec | None, path: str = "") -> dict[str, Any]:
        p = spec.path if spec else path
        return {
            "spec": spec,
            "path": p,
            "users": registry.list_users(),
            "fs": fsinfo.fs_type(p) if p else "",
            "no_unix": fsinfo.lacks_unix_perms(p) if p else False,
        }

    @app.get("/shares/new")
    async def share_new(
        request: Request, path: str = "", s: SessionRow = Depends(require_read)
    ) -> Response:
        return render(request, "share_form.html", share_form_ctx(None, path), session=s)

    def spec_from_form(form: dict[str, str]) -> ShareSpec:
        members = {}
        for user in registry.list_users():
            access = form.get(f"access_{user}", "none")
            if access in ("ro", "rw"):
                members[user] = access
            elif access != "none":
                raise v.ValidationError(f"invalid access for {user}")
        all_users = form.get("all_users", "off")
        path = form.get("path", "")
        spec = ShareSpec(
            name=form.get("name", ""),
            path=path,
            comment=form.get("comment", ""),
            members=members,
            all_users=None if all_users == "off" else all_users,
            no_unix_perms=False,
        )
        spec = v.validate_share(spec, volumes, registry.list_users())
        return ShareSpec(**{**spec.to_dict(), "no_unix_perms": fsinfo.lacks_unix_perms(spec.path)})

    @app.post("/shares")
    async def share_create(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        try:
            spec = spec_from_form(form)
            if registry.get_share(spec.name):
                raise v.ValidationError(f"a share named {spec.name!r} already exists")
            apply([*registry.list_shares(), spec])
            registry.save_share(spec)
        except (v.ValidationError, HelperError, RegistryError) as e:
            ctx = share_form_ctx(None, form.get("path", ""))
            ctx.update(error=str(e), form=form)
            return render(request, "share_form.html", ctx, status=400, session=s)
        audit.event(
            "share_created",
            share=spec.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return back(f"/shares/{quote(spec.name)}/edit", msg=f"Share {spec.name} created.")

    @app.get("/shares/{name}/edit")
    async def share_edit(
        request: Request, name: str, s: SessionRow = Depends(require_read)
    ) -> Response:
        spec = registry.get_share(name)
        if spec is None:
            return back("/shares", err="No such share.")
        ctx = share_form_ctx(spec)
        try:
            ctx["perm"] = None if spec.no_unix_perms else helper_.perm_plan(spec.path)
        except HelperError as e:
            ctx["perm_error"] = str(e)
        return render(request, "share_form.html", ctx, session=s)

    @app.post("/shares/{name}")
    async def share_update(
        request: Request, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        old = registry.get_share(name)
        if old is None:
            return back("/shares", err="No such share.")
        form = await form_dict(request)
        try:
            spec = spec_from_form(form)
            others = [x for x in registry.list_shares() if x.name.lower() != old.name.lower()]
            if any(x.name.lower() == spec.name.lower() for x in others):
                raise v.ValidationError(f"a share named {spec.name!r} already exists")
            apply([*others, spec])
            registry.save_share(spec, old_name=old.name)
        except (v.ValidationError, HelperError, RegistryError) as e:
            ctx = share_form_ctx(old)
            ctx.update(error=str(e), form=form)
            return render(request, "share_form.html", ctx, status=400, session=s)
        audit.event(
            "share_updated",
            share=spec.name,
            old_name=old.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return back(f"/shares/{quote(spec.name)}/edit", msg="Share saved.")

    @app.post("/shares/{name}/delete")
    async def share_delete(
        request: Request, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        old = registry.get_share(name)
        if old is None:
            return back("/shares", err="No such share.")
        try:
            apply([x for x in registry.list_shares() if x.name.lower() != old.name.lower()])
        except HelperError as e:
            return back("/shares", err=str(e))
        registry.delete_share(old.name)
        audit.event("share_deleted", share=old.name, path=old.path)
        return back("/shares", msg=f"Share {old.name} removed. The folder was not touched.")

    @app.post("/shares/{name}/permissions")
    async def share_permissions(
        request: Request, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        spec = registry.get_share(name)
        if spec is None:
            return back("/shares", err="No such share.")
        form = await form_dict(request)
        url = f"/shares/{quote(spec.name)}/edit"
        if form.get("fix_permissions") != "yes":
            return back(url, err="Tick 'fix permissions' to confirm the change.")
        try:
            expected = {
                "uid": int(form.get("before_uid", "")),
                "gid": int(form.get("before_gid", "")),
                "mode": form.get("before_mode", ""),
            }
            result = helper_.perm_apply(spec.path, expected)
        except (ValueError, HelperError) as e:
            return back(url, err=f"Permissions not changed: {e}")
        audit.event("permissions_applied", share=spec.name, path=spec.path, result=result)
        return back(url, msg="Permissions updated on the share folder (not recursive).")

    # --- users -----------------------------------------------------------------------

    @app.get("/users")
    async def users_page(request: Request, s: SessionRow = Depends(require_read)) -> Response:
        shares = registry.list_shares()
        users = [
            {"name": u, "shares": [x.name for x in shares if u in x.members]}
            for u in registry.list_users()
        ]
        return render(request, "users.html", {"users": users}, session=s)

    def check_new_password(form: dict[str, str]) -> str:
        pw = v.validate_password(form.get("password", ""))
        if not hmac.compare_digest(pw.encode(), form.get("password2", "").encode()):
            raise v.ValidationError("the two passwords do not match")
        return pw

    @app.post("/users")
    async def user_create(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        try:
            name = v.validate_username(form.get("name", ""))
            pw = check_new_password(form)
            if registry.has_user(name):
                raise v.ValidationError(f"user {name!r} already exists")
            helper_.user_add(name)
            try:
                helper_.user_set_password(name, pw)
            except HelperError:
                helper_.user_delete(name)
                raise
            registry.add_user(name, clock())
        except (v.ValidationError, HelperError, RegistryError) as e:
            return back("/users", err=str(e))
        audit.event("user_created", user=name)
        return back("/users", msg=f"User {name} created.")

    @app.post("/users/{name}/password")
    async def user_password(
        request: Request, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        form = await form_dict(request)
        try:
            v.validate_username(name)
            if not registry.has_user(name):
                raise v.ValidationError("no such user")
            helper_.user_set_password(name, check_new_password(form))
        except (v.ValidationError, HelperError) as e:
            return back("/users", err=str(e))
        audit.event("user_password_set", user=name)
        return back("/users", msg=f"Password for {name} changed.")

    @app.post("/users/{name}/delete")
    async def user_delete(
        request: Request, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        if not registry.has_user(name):
            return back("/users", err="No such user.")
        orphaned = registry.shares_only_reachable_by(name)
        if orphaned:
            return back(
                "/users",
                err=f"{name} is the only member of: {', '.join(orphaned)}. "
                "Add another member or remove those shares first.",
            )
        new_shares = [
            ShareSpec(
                **{**x.to_dict(), "members": {u: a for u, a in x.members.items() if u != name}}
            )
            for x in registry.list_shares()
        ]
        try:
            apply(new_shares)
            helper_.user_delete(name)
        except HelperError as e:
            return back("/users", err=str(e))
        registry.delete_user(name)
        audit.event("user_deleted", user=name)
        return back("/users", msg=f"User {name} deleted.")

    # --- browse ----------------------------------------------------------------------

    @app.get("/browse")
    async def browse(
        request: Request, path: str = "", s: SessionRow = Depends(require_read)
    ) -> Response:
        if not path:
            if len(volumes) == 1:
                path = volumes[0]
            else:
                return render(request, "browse.html", {"volumes": volumes, "path": ""}, session=s)
        try:
            entries = fileops.list_dir(path)
            root, parts = fileops.split(path)
        except FileOpError as e:
            return render(
                request,
                "browse.html",
                {"volumes": volumes, "path": "", "error": str(e)},
                status=400,
                session=s,
            )
        crumbs = [(root, root)]
        cur = root
        for p in parts:
            cur = cur.rstrip("/") + "/" + p
            crumbs.append((p, cur))
        shared = {x.path: x.name for x in registry.list_shares()}
        return render(
            request,
            "browse.html",
            {
                "volumes": volumes,
                "path": path,
                "crumbs": crumbs,
                "entries": entries,
                "shared": shared,
                "parent": os.path.dirname(path) if parts else "",
                "fs": fsinfo.fs_type(path),
                "max_upload_mb": settings.max_upload_bytes // (1024 * 1024),
            },
            session=s,
        )

    def browse_url(path: str) -> str:
        return "/browse?" + urlencode({"path": path})

    @app.post("/browse/mkdir")
    async def browse_mkdir(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        parent = form.get("path", "")
        try:
            created = fileops.mkdir(parent, form.get("name", ""))
        except FileOpError as e:
            return back(browse_url(parent), err=str(e))
        audit.event("folder_created", path=created)
        return back(browse_url(parent), msg="Folder created.")

    @app.post("/browse/rename")
    async def browse_rename(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        path = form.get("path", "")
        parent = os.path.dirname(path)
        try:
            new = fileops.rename(path, form.get("new_name", ""))
        except FileOpError as e:
            return back(browse_url(parent), err=str(e))
        audit.event("file_renamed", path=path, new_path=new)
        return back(browse_url(parent), msg="Renamed.")

    @app.post("/browse/delete")
    async def browse_delete(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        path = form.get("path", "")
        parent = os.path.dirname(path)
        if form.get("confirm", "") != os.path.basename(path):
            return back(browse_url(parent), err="Type the exact name to confirm deletion.")
        try:
            fileops.delete(path, recursive=form.get("recursive") == "yes")
        except FileOpError as e:
            return back(browse_url(parent), err=str(e))
        audit.event("file_deleted", path=path, recursive=form.get("recursive") == "yes")
        return back(browse_url(parent), msg="Deleted.")

    @app.put("/browse/upload")
    async def browse_upload(
        request: Request, dir: str, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > settings.max_upload_bytes:
            return JSONResponse({"error": "upload exceeds the size limit"}, status_code=413)

        async def body() -> AsyncIterator[bytes]:
            async for chunk in request.stream():
                if chunk:
                    yield chunk

        try:
            final = await fileops.upload(dir, name, body(), settings.max_upload_bytes)
        except FileOpError as e:
            code = 413 if "limit" in str(e) else 400
            return JSONResponse({"error": str(e)}, status_code=code)
        audit.event("file_uploaded", dir=dir, name=final)
        return JSONResponse({"name": final}, status_code=201)

    @app.get("/browse/download")
    async def browse_download(
        request: Request, path: str, s: SessionRow = Depends(require_read)
    ) -> Response:
        try:
            fd, size, fname = fileops.open_download(path)
        except FileOpError as e:
            return back(browse_url(os.path.dirname(path)), err=str(e))

        def stream() -> Iterator[bytes]:
            with os.fdopen(fd, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    yield chunk

        ascii_name = "".join(
            c if (c.isascii() and c.isalnum()) or c in "._- " else "_" for c in fname
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{ascii_name}"; '
            f"filename*=UTF-8''{quote(fname, safe='')}",
            "Content-Length": str(size),
            "Content-Security-Policy": DOWNLOAD_CSP,
            "X-Content-Type-Options": "nosniff",
        }
        return StreamingResponse(stream(), media_type="application/octet-stream", headers=headers)

    # --- config & status -------------------------------------------------------------

    @app.get("/config")
    async def config_page(request: Request, s: SessionRow = Depends(require_read)) -> Response:
        ctx: dict[str, Any] = {"status": None}
        try:
            st = helper_.status()
            ctx["status"] = st
            reg_shares = {x.name for x in registry.list_shares()}
            live_shares = set(st.get("shares", {}))
            reg_users = set(registry.list_users())
            live_users = set(st.get("users", []))
            ctx["drift"] = {
                "missing_shares": sorted(reg_shares - live_shares),
                "extra_shares": sorted(live_shares - reg_shares),
                "missing_users": sorted(reg_users - live_users),
                "extra_users": sorted(live_users - reg_users),
            }
        except HelperError as e:
            ctx["error"] = str(e)
        return render(request, "config.html", ctx, session=s)

    @app.post("/config/reapply")
    async def config_reapply(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        try:
            apply(registry.list_shares())
        except HelperError as e:
            return back("/config", err=str(e))
        audit.event("config_reapplied")
        return back("/config", msg="Configuration re-applied from the registry.")

    # --- import ----------------------------------------------------------------------

    importer.register_routes(
        app,
        settings=settings,
        registry=registry,
        helper=helper_,
        volumes=volumes,
        render=render,
        back=back,
        require_read=require_read,
        require_write=require_write,
        form_dict=form_dict,
        apply=apply,
        clock=clock,
    )

    @app.api_route("/{rest:path}", methods=["GET"], include_in_schema=False)
    async def not_found(request: Request, rest: str) -> Response:
        s = sessions.validate(request.cookies.get(SESSION_COOKIE))
        if s is None:
            return RedirectResponse("/login", status_code=303)
        return render(request, "error.html", {"error": "Page not found."}, status=404, session=s)

    return app
