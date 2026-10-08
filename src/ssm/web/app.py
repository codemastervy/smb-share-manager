"""FastAPI application: a JSON API under /api for the React UI, plus the built UI itself.

Everything under /api except /api/auth/status and /api/auth/login needs a session.
Every state-changing request needs the session's CSRF token in the X-CSRF-Token header
and a same-origin Origin (or Referer). Responses never render user files.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from ssm import audit, fsinfo, importer
from ssm import validators as v
from ssm.auth import AdminCredential, LoginThrottle, SessionManager, client_ip, peer_is_trusted
from ssm.files import Entry, FileOpError, FileOps
from ssm.helper_client import Helper, HelperClient, HelperError
from ssm.models import ShareSpec
from ssm.registry import Registry, SessionRow
from ssm.settings import ConfigError, Settings
from ssm.vpath import VolumeMap, VPathError
from ssm.web.security import DOWNLOAD_CSP, SecurityMiddleware

SESSION_COOKIE = "ssm_session"
PRELOGIN_COOKIE = "ssm_pre"
SHARES_CONF = "/data/samba/shares.conf"


# --- request bodies (unknown fields are rejected) --------------------------------------------


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LoginBody(Body):
    password: str


class Member(Body):
    username: str
    access: Literal["ro", "rw"]


class ShareCreate(Body):
    path: str
    name: str
    members: list[Member] = []
    all_users: Literal["ro", "rw"] | None = None
    comment: str = ""


class ShareUpdate(Body):
    members: list[Member] | None = None
    all_users: Literal["ro", "rw"] | None = None
    comment: str | None = None


class PermBefore(Body):
    uid: int
    gid: int
    mode: str


class PermApply(Body):
    fix_permissions: bool
    before: PermBefore


class UserCreate(Body):
    username: str
    password: str
    display_name: str = ""


class UserUpdate(Body):
    password: str | None = None
    display_name: str | None = None


class MkdirBody(Body):
    parent: str
    name: str


class RenameBody(Body):
    path: str
    new_name: str


class TransferBody(Body):
    sources: list[str]
    destination: str


class DeleteBody(Body):
    paths: list[str]


class ImportUserBody(Body):
    username: str


class ImportShareBody(Body):
    name: str
    path: str | None = None
    ack_anonymous: bool = False


def bad(msg: str, code: int = 400) -> HTTPException:
    return HTTPException(status_code=code, detail=msg)


def create_app(
    settings: Settings,
    helper: Helper | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    settings.check()
    try:
        volumes = v.validate_volumes(settings.volumes)
        vmap = VolumeMap(volumes)
    except (v.ValidationError, VPathError) as e:
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
    frontend = Path(settings.frontend_dir)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware, allowed_hosts=settings.allowed_hosts)
    app.state.registry = registry
    app.state.helper = helper_

    # --- request helpers -------------------------------------------------------------------

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
        if settings.cookie_secure in ("true", "false"):
            return settings.cookie_secure == "true"
        return scheme(request) == "https"

    def check_origin(request: Request) -> None:
        expected = f"{scheme(request)}://{request.headers.get('host', '')}".lower()
        origin = request.headers.get("origin")
        if origin is None:
            ref = request.headers.get("referer")
            if not ref:
                raise bad("missing Origin", 403)
            parts = urlsplit(ref)
            origin = f"{parts.scheme}://{parts.netloc}"
        if origin.lower() != expected:
            raise bad("cross-origin request refused", 403)

    def session_of(request: Request) -> SessionRow | None:
        return sessions.validate(request.cookies.get(SESSION_COOKIE))

    async def require_read(request: Request) -> SessionRow:
        row = session_of(request)
        if row is None:
            raise bad("Not signed in", 401)
        return row

    async def require_write(request: Request) -> SessionRow:
        row = await require_read(request)
        check_origin(request)
        token = request.headers.get("x-csrf-token", "")
        if not token or not hmac.compare_digest(token, row.csrf):
            raise bad("invalid CSRF token", 403)
        return row

    def to_real(vpath: str) -> str:
        try:
            return vmap.to_real(vpath)
        except VPathError as e:
            raise bad(f"invalid path: {e}") from e

    def to_virtual(real: str) -> str:
        return vmap.to_virtual(real)

    def shares_by_path() -> dict[str, ShareSpec]:
        return {s.path: s for s in registry.list_shares()}

    def entry_json(real: str, e: Entry, shared: dict[str, ShareSpec]) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": e.name,
            "path": to_virtual(real),
            "type": e.kind,
            "is_dir": e.kind == "dir",
            "is_symlink": e.kind == "link",
            "size": e.size if e.kind == "file" else None,
            "modified": e.mtime,
            "hidden": e.name.startswith("."),
        }
        if real in shared:
            out["share"] = {"id": shared[real].name, "name": shared[real].name}
        return out

    def share_json(s: ShareSpec, created: dict[str, float]) -> dict[str, Any]:
        return {
            "id": s.name,
            "name": s.name,
            "path": to_virtual(s.path),
            "real_path": s.path,
            "members": [{"username": u, "access": a} for u, a in s.members.items()],
            "all_users": s.all_users,
            "comment": s.comment,
            "created_at": created.get(s.name) or None,
            "fs_type": fsinfo.fs_type(s.path),
            "no_unix_perms": s.no_unix_perms,
        }

    def apply(new_shares: list[ShareSpec]) -> None:
        try:
            helper_.apply_shares(new_shares)
        except HelperError as e:
            raise bad(str(e), 502) from e

    def validated_share(spec: ShareSpec) -> ShareSpec:
        try:
            spec = v.validate_share(spec, volumes, registry.list_users())
        except v.ValidationError as e:
            raise bad(str(e)) from e
        return ShareSpec(**{**spec.to_dict(), "no_unix_perms": fsinfo.lacks_unix_perms(spec.path)})

    def get_share(share_id: str) -> ShareSpec:
        s = registry.get_share(share_id)
        if s is None:
            raise bad("no such share", 404)
        return s

    def import_mounted() -> bool:
        # /import is root-only (it holds password hashes); its presence is enough.
        return os.path.isdir(settings.import_dir)

    # --- public -------------------------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            {"status": "ok", "version": settings.version, "build_date": settings.build_date}
        )

    @app.get("/api/auth/status")
    async def auth_status(request: Request) -> Response:
        row = session_of(request)
        if row is not None:
            return JSONResponse({"authenticated": True, "configured": True, "csrf": row.csrf})
        pre = request.cookies.get(PRELOGIN_COOKIE) or secrets.token_urlsafe(32)
        resp = JSONResponse({"authenticated": False, "configured": True, "csrf": pre})
        resp.set_cookie(
            PRELOGIN_COOKIE,
            pre,
            max_age=3600,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(request),
            path="/api/auth",
        )
        return resp

    @app.post("/api/auth/login")
    async def login(request: Request, body: LoginBody) -> Response:
        check_origin(request)
        pre = request.cookies.get(PRELOGIN_COOKIE, "")
        token = request.headers.get("x-csrf-token", "")
        if not pre or not token or not hmac.compare_digest(pre, token):
            raise bad("invalid CSRF token", 403)
        ip = peer(request)
        now = clock()
        wait = throttle.retry_after(ip, now)
        if wait > 0:
            audit.event("login_throttled", peer=ip, retry_after=round(wait))
            raise bad(f"Too many attempts. Try again in {int(wait) + 1} s.", 429)
        if not cred.verify(body.password):
            throttle.record_failure(ip, now)
            audit.event("login_failed", peer=ip)
            raise bad("Wrong password", 401)
        throttle.record_success(ip)
        cookie, csrf = sessions.create()
        audit.event("login_ok", peer=ip)
        resp = JSONResponse({"authenticated": True, "csrf": csrf})
        resp.set_cookie(
            SESSION_COOKIE,
            cookie,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(request),
            path="/",
        )
        resp.delete_cookie(PRELOGIN_COOKIE, path="/api/auth")
        return resp

    @app.post("/api/auth/logout")
    async def logout(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        sessions.revoke(request.cookies.get(SESSION_COOKIE))
        audit.event("logout", peer=peer(request))
        resp = JSONResponse({"authenticated": False})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/info")
    async def info(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        return {
            "version": settings.version,
            "build_date": settings.build_date,
            "server_name": settings.server_name,
            "import_mounted": import_mounted(),
        }

    # --- files --------------------------------------------------------------------------------

    @app.get("/api/files/volumes")
    async def files_volumes(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        shared = [x.path for x in registry.list_shares()]
        out = []
        for vol in vmap.volumes:
            total: int | None = None
            free: int | None = None
            used: int | None = None
            try:
                st = os.statvfs(vol.root)
                total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
                used = total - st.f_bfree * st.f_frsize
            except OSError:
                pass
            out.append(
                {
                    "name": vol.name,
                    "path": "/" + vol.name,
                    "total": total,
                    "used": used,
                    "free": free,
                    "writable": os.access(vol.root, os.W_OK),
                    "has_shares": any(
                        p == vol.root or p.startswith(vol.root + "/") for p in shared
                    ),
                    "fs_type": fsinfo.fs_type(vol.root),
                    "no_unix_perms": fsinfo.lacks_unix_perms(vol.root),
                }
            )
        return {"volumes": out}

    def listing(
        vpath: str, real: str, items: list[tuple[str, Entry]], show_hidden: bool, **extra: Any
    ) -> dict[str, Any]:
        shared = shares_by_path()
        return {
            "path": vpath,
            "volume": vmap.volume_of(real).name,
            "writable": os.access(real, os.W_OK),
            "fs_type": fsinfo.fs_type(real),
            "no_unix_perms": fsinfo.lacks_unix_perms(real),
            "entries": [
                entry_json(p, e, shared)
                for p, e in items
                if show_hidden or not e.name.startswith(".")
            ],
            **extra,
        }

    @app.get("/api/files/list")
    async def files_list(
        path: str, show_hidden: bool = False, s: SessionRow = Depends(require_read)
    ) -> dict[str, Any]:
        real = to_real(path)
        try:
            entries = fileops.list_dir(real)
        except FileOpError as e:
            raise bad(str(e)) from e
        items = [(real.rstrip("/") + "/" + e.name, e) for e in entries]
        return listing(path, real, items, show_hidden)

    @app.get("/api/files/search")
    async def files_search(
        path: str, q: str, show_hidden: bool = False, s: SessionRow = Depends(require_read)
    ) -> dict[str, Any]:
        real = to_real(path)
        try:
            items, truncated = fileops.search(real, q, show_hidden)
        except FileOpError as e:
            raise bad(str(e)) from e
        return listing(path, real, items, show_hidden, truncated=truncated, query=q)

    def entry_for(real: str) -> dict[str, Any]:
        for e in fileops.list_dir(os.path.dirname(real)):
            if e.name == os.path.basename(real):
                return entry_json(real, e, shares_by_path())
        raise bad("not found", 404)

    @app.post("/api/files/mkdir")
    async def files_mkdir(body: MkdirBody, s: SessionRow = Depends(require_write)) -> Any:
        try:
            created = fileops.mkdir(to_real(body.parent), body.name)
        except FileOpError as e:
            raise bad(str(e)) from e
        audit.event("folder_created", path=created)
        return entry_for(created)

    @app.post("/api/files/rename")
    async def files_rename(body: RenameBody, s: SessionRow = Depends(require_write)) -> Any:
        real = to_real(body.path)
        try:
            new = fileops.rename(real, body.new_name)
        except FileOpError as e:
            raise bad(str(e)) from e
        audit.event("file_renamed", path=real, new_path=new)
        return entry_for(new)

    def transfer(body: TransferBody, op: Literal["copy", "move"]) -> dict[str, Any]:
        dest = to_real(body.destination)
        done: list[str] = []
        failed: list[dict[str, str]] = []
        for src_v in body.sources:
            try:
                src = to_real(src_v)
                out = fileops.copy(src, dest) if op == "copy" else fileops.move(src, dest)
            except (FileOpError, HTTPException) as e:
                msg = e.detail if isinstance(e, HTTPException) else str(e)
                failed.append({"source": src_v, "error": str(msg)})
                continue
            audit.event("file_copied" if op == "copy" else "file_moved", path=src, new_path=out)
            done.append(to_virtual(out))
        return {"copied" if op == "copy" else "moved": done, "failed": failed}

    @app.post("/api/files/copy")
    async def files_copy(body: TransferBody, s: SessionRow = Depends(require_write)) -> Any:
        return transfer(body, "copy")

    @app.post("/api/files/move")
    async def files_move(body: TransferBody, s: SessionRow = Depends(require_write)) -> Any:
        return transfer(body, "move")

    @app.post("/api/files/delete")
    async def files_delete(body: DeleteBody, s: SessionRow = Depends(require_write)) -> Any:
        deleted: list[str] = []
        failed: list[dict[str, str]] = []
        for p in body.paths:
            try:
                real = to_real(p)
                fileops.delete(real, recursive=True)
            except (FileOpError, HTTPException) as e:
                msg = e.detail if isinstance(e, HTTPException) else str(e)
                failed.append({"path": p, "error": str(msg)})
                continue
            audit.event("file_deleted", path=real)
            deleted.append(p)
        return {"deleted": deleted, "failed": failed}

    @app.put("/api/files/upload")
    async def files_upload(
        request: Request, path: str, name: str, s: SessionRow = Depends(require_write)
    ) -> Response:
        real_dir = to_real(path)
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > settings.max_upload_bytes:
            raise bad("upload exceeds the size limit", 413)

        async def body() -> AsyncIterator[bytes]:
            async for chunk in request.stream():
                if chunk:
                    yield chunk

        try:
            final = await fileops.upload(real_dir, name, body(), settings.max_upload_bytes)
        except FileOpError as e:
            raise bad(str(e), 413 if "limit" in str(e) else 400) from e
        real = real_dir.rstrip("/") + "/" + final
        audit.event("file_uploaded", path=real)
        return JSONResponse(
            {"name": final, "path": to_virtual(real), "size": os.lstat(real).st_size},
            status_code=201,
        )

    @app.get("/api/files/download")
    async def files_download(path: str, s: SessionRow = Depends(require_read)) -> Response:
        # There is deliberately no inline mode: files are always downloaded, never rendered.
        real = to_real(path)
        try:
            fd, size, fname = fileops.open_download(real)
        except FileOpError as e:
            raise bad(str(e)) from e

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

    # --- shares -------------------------------------------------------------------------------

    def samba_status() -> dict[str, Any]:
        reg = [x.name for x in registry.list_shares()]
        try:
            st = helper_.status()
        except HelperError as e:
            return {
                "running": False,
                "detail": str(e),
                "registry_shares": reg,
                "active_shares": [],
                "missing_shares": reg,
                "extra_shares": [],
                "missing_users": [],
                "extra_users": [],
                "config_text": "",
            }
        live = sorted(st.get("shares", {}))
        reg_users = set(registry.list_users())
        live_users = set(st.get("users", []))
        return {
            "running": bool(st.get("smbd_running")),
            "detail": "",
            "registry_shares": reg,
            "active_shares": live,
            "missing_shares": sorted(set(reg) - set(live)),
            "extra_shares": sorted(set(live) - set(reg)),
            "missing_users": sorted(reg_users - live_users),
            "extra_users": sorted(live_users - reg_users),
            "config_text": st.get("config_text", ""),
        }

    @app.get("/api/shares")
    async def shares_list(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        created = registry.share_created()
        status = samba_status()
        status.pop("config_text", None)
        return {
            "shares": [share_json(x, created) for x in registry.list_shares()],
            "status": status,
        }

    @app.get("/api/shares/config")
    async def shares_config(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        return {"path": SHARES_CONF, "content": samba_status()["config_text"]}

    @app.post("/api/shares", status_code=201)
    async def share_create(body: ShareCreate, s: SessionRow = Depends(require_write)) -> Any:
        spec = validated_share(
            ShareSpec(
                name=body.name,
                path=to_real(body.path),
                comment=body.comment,
                members={m.username: m.access for m in body.members},
                all_users=body.all_users,
            )
        )
        if registry.get_share(spec.name):
            raise bad(f"a share named {spec.name!r} already exists")
        if spec.path in shares_by_path():
            raise bad("this folder is already shared")
        apply([*registry.list_shares(), spec])
        registry.save_share(spec, created=clock())
        audit.event(
            "share_created",
            share=spec.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return share_json(spec, registry.share_created())

    @app.post("/api/shares/reapply")
    async def shares_reapply(s: SessionRow = Depends(require_write)) -> Any:
        apply(registry.list_shares())
        audit.event("config_reapplied")
        return {"ok": True}

    @app.patch("/api/shares/{share_id}")
    async def share_update(
        share_id: str, body: ShareUpdate, s: SessionRow = Depends(require_write)
    ) -> Any:
        old = get_share(share_id)
        fields = body.model_fields_set
        members = old.members
        if "members" in fields and body.members is not None:
            members = {m.username: m.access for m in body.members}
        comment = body.comment if body.comment is not None else old.comment
        all_users = body.all_users if "all_users" in fields else old.all_users
        spec = validated_share(
            ShareSpec(
                name=old.name,
                path=old.path,
                comment=comment,
                members=members,
                all_users=all_users,
            )
        )
        others = [x for x in registry.list_shares() if x.name != old.name]
        apply([*others, spec])
        registry.save_share(spec, old_name=old.name)
        audit.event(
            "share_updated",
            share=spec.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return share_json(spec, registry.share_created())

    @app.delete("/api/shares/{share_id}")
    async def share_delete(share_id: str, s: SessionRow = Depends(require_write)) -> Any:
        old = get_share(share_id)
        apply([x for x in registry.list_shares() if x.name != old.name])
        registry.delete_share(old.name)
        audit.event("share_deleted", share=old.name, path=old.path)
        return {"removed": old.name, "path": to_virtual(old.path)}

    @app.get("/api/shares/{share_id}/permissions")
    async def share_perm_plan(share_id: str, s: SessionRow = Depends(require_read)) -> Any:
        share = get_share(share_id)
        try:
            return helper_.perm_plan(share.path)
        except HelperError as e:
            raise bad(str(e), 502) from e

    @app.post("/api/shares/{share_id}/permissions")
    async def share_perm_apply(
        share_id: str, body: PermApply, s: SessionRow = Depends(require_write)
    ) -> Any:
        share = get_share(share_id)
        if not body.fix_permissions:
            raise bad("tick 'fix permissions' to confirm the change")
        try:
            result = helper_.perm_apply(share.path, body.before.model_dump())
        except HelperError as e:
            raise bad(f"permissions not changed: {e}", 409) from e
        audit.event("permissions_applied", share=share.name, path=share.path, result=result)
        return result

    # --- users --------------------------------------------------------------------------------

    @app.get("/api/users")
    async def users_list(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        shares = registry.list_shares()
        out = []
        for name, display, created in registry.user_details():
            out.append(
                {
                    "username": name,
                    "display_name": display or name,
                    "created_at": created or None,
                    "shares": [
                        {"id": x.name, "name": x.name, "access": x.members[name]}
                        for x in shares
                        if name in x.members
                    ],
                }
            )
        return {"users": out}

    def check_display(name: str) -> str:
        try:
            v.validate_comment(name)
        except v.ValidationError as e:
            raise bad(f"display name: {e}") from e
        if len(name) > 64:
            raise bad("display name must be at most 64 characters")
        return name

    @app.post("/api/users", status_code=201)
    async def user_create(body: UserCreate, s: SessionRow = Depends(require_write)) -> Any:
        try:
            name = v.validate_username(body.username)
            pw = v.validate_password(body.password)
        except v.ValidationError as e:
            raise bad(str(e)) from e
        display = check_display(body.display_name)
        if registry.has_user(name):
            raise bad(f"user {name!r} already exists")
        try:
            helper_.user_add(name)
            try:
                helper_.user_set_password(name, pw)
            except HelperError:
                helper_.user_delete(name)
                raise
        except HelperError as e:
            raise bad(str(e), 502) from e
        registry.add_user(name, clock(), display)
        audit.event("user_created", user=name)
        return {
            "username": name,
            "display_name": display or name,
            "created_at": clock(),
            "shares": [],
        }

    @app.patch("/api/users/{username}")
    async def user_update(
        username: str, body: UserUpdate, s: SessionRow = Depends(require_write)
    ) -> Any:
        if not registry.has_user(username):
            raise bad("no such user", 404)
        if body.display_name is not None:
            registry.set_display_name(username, check_display(body.display_name))
        if body.password:
            try:
                helper_.user_set_password(username, v.validate_password(body.password))
            except v.ValidationError as e:
                raise bad(str(e)) from e
            except HelperError as e:
                raise bad(str(e), 502) from e
            audit.event("user_password_set", user=username)
        audit.event("user_updated", user=username)
        return {"username": username}

    @app.delete("/api/users/{username}")
    async def user_delete(username: str, s: SessionRow = Depends(require_write)) -> Any:
        if not registry.has_user(username):
            raise bad("no such user", 404)
        orphaned = registry.shares_only_reachable_by(username)
        if orphaned:
            raise bad(
                f"{username} is the only member of {', '.join(orphaned)}. Add another member "
                "or unshare it first; a share nobody can reach is not allowed.",
                409,
            )
        shares = registry.list_shares()
        affected = [x.name for x in shares if username in x.members]
        apply(
            [
                ShareSpec(
                    **{
                        **x.to_dict(),
                        "members": {u: a for u, a in x.members.items() if u != username},
                    }
                )
                for x in shares
            ]
        )
        try:
            helper_.user_delete(username)
        except HelperError as e:
            raise bad(str(e), 502) from e
        registry.delete_user(username)
        audit.event("user_deleted", user=username)
        return {"deleted": username, "removed_from_shares": affected}

    # --- import -------------------------------------------------------------------------------

    def import_scan() -> dict[str, Any]:
        try:
            return helper_.import_scan()
        except HelperError as e:
            raise bad(str(e), 502) from e

    def imported_share_json(x: importer.ImportedShare) -> dict[str, Any]:
        try:
            local = to_virtual(x.path)
        except VPathError:
            local = ""
        return {
            "name": x.name,
            "path": x.path,
            "local_path": local,
            "comment": x.comment,
            "members": [{"username": u, "access": a} for u, a in x.members.items()],
            "all_users": x.all_users,
            "was_anonymous": x.was_anonymous,
            "notes": x.notes,
            "problems": x.problems,
            "exists": registry.get_share(x.name) is not None,
        }

    @app.get("/api/import")
    async def import_page(s: SessionRow = Depends(require_read)) -> dict[str, Any]:
        if not import_mounted():
            return {"mounted": False, "users": [], "shares": [], "users_error": ""}
        scan = import_scan()
        existing = set(registry.list_users())
        shares = importer.shares_from_sections(scan.get("sections"), volumes)
        return {
            "mounted": True,
            "users": [{"username": u, "exists": u in existing} for u in scan.get("users", [])],
            "users_error": scan.get("users_error", ""),
            "shares": [imported_share_json(x) for x in shares],
        }

    @app.post("/api/import/user")
    async def import_user(body: ImportUserBody, s: SessionRow = Depends(require_write)) -> Any:
        try:
            name = v.validate_username(body.username)
        except v.ValidationError as e:
            raise bad(str(e)) from e
        if registry.has_user(name):
            raise bad(f"user {name!r} already exists")
        if name not in import_scan().get("users", []):
            raise bad(f"user {name!r} is not in the imported passdb")
        try:
            helper_.import_user(name)
        except HelperError as e:
            raise bad(str(e), 502) from e
        registry.add_user(name, clock())
        audit.event("user_imported", user=name)
        return {"imported": name}

    @app.post("/api/import/share")
    async def import_share(body: ImportShareBody, s: SessionRow = Depends(require_write)) -> Any:
        sections = import_scan().get("sections")
        found = {x.name: x for x in importer.shares_from_sections(sections, volumes)}.get(body.name)
        if found is None:
            raise bad("that share is not in the imported configuration", 404)
        real = to_real(body.path) if body.path else found.path
        problems = importer.check_problems(found, volumes, real)
        if problems:
            raise bad(f"{found.name}: " + "; ".join(problems))
        if found.was_anonymous and not body.ack_anonymous:
            raise bad(
                f"{found.name} was open without a password; confirm that it will now "
                "require an SMB login"
            )
        spec = validated_share(found.to_spec(real))
        if registry.get_share(spec.name):
            raise bad(f"a share named {spec.name!r} already exists")
        apply([*registry.list_shares(), spec])
        registry.save_share(spec, created=clock())
        audit.event(
            "share_imported",
            share=spec.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return share_json(spec, registry.share_created())

    # --- the React UI (static files only; it fetches everything else from /api) -------------

    @app.api_route(
        "/api/{rest:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def api_not_found(rest: str) -> Response:
        return JSONResponse({"detail": "not found"}, status_code=404)

    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/{rest:path}", include_in_schema=False)
    async def spa(rest: str) -> Response:
        index = frontend / "index.html"
        if not index.is_file():
            return Response("The web UI is not built.\n", status_code=503, media_type="text/plain")
        return FileResponse(
            index, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-store"}
        )

    return app
