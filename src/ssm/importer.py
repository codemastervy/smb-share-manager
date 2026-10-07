"""One-time import of shares from an old smb.conf, and of users from an old passdb.

Expected layout of the read-only /import mount (see README):

    /import/etc-samba/       copy of the old /etc/samba
    /import/var-lib-samba/   copy of the old /var/lib/samba  (read by the root helper only)

The parser only reads. It follows ``include =`` lines that point into the old
/etc/samba, mapped onto /import/etc-samba; anything else is ignored. Nothing parsed here
is trusted: every imported value goes through the normal validators, and the admin
confirms each share and user individually.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response

from ssm import audit, fsinfo
from ssm import validators as v
from ssm.helper_client import Helper, HelperError
from ssm.models import ShareSpec
from ssm.registry import Registry, RegistryError, SessionRow
from ssm.settings import Settings

SKIP_SECTIONS = frozenset({"global", "globals", "homes", "printers", "print$"})
MAX_INCLUDE_DEPTH = 5
MAX_FILE_BYTES = 1024 * 1024
TRUE = frozenset({"yes", "true", "1", "on"})


@dataclass
class ImportedShare:
    name: str
    path: str
    comment: str
    members: dict[str, str]
    all_users: str | None
    was_anonymous: bool
    notes: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def to_spec(self, path: str | None = None) -> ShareSpec:
        return ShareSpec(
            name=self.name,
            path=path or self.path,
            comment=self.comment,
            members=dict(self.members),
            all_users=self.all_users,
        )


def _read_conf(path: str, etc_dir: str, depth: int, out: list[tuple[str, str, str]]) -> None:
    """Append (section, key, value) triples. Section '' means before any section."""
    if depth > MAX_INCLUDE_DEPTH:
        return
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE_BYTES)
    except OSError:
        return
    text = raw.decode("utf-8", "replace")
    # Join backslash continuation lines, as Samba does.
    text = re.sub(r"\\\r?\n", " ", text)
    section = out[-1][0] if out else ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("["):
            end = s.rfind("]")
            section = s[1:end] if end > 0 else s[1:]
            out.append((section, "", ""))
            continue
        key, sep, val = s.partition("=")
        if not sep:
            continue
        key = " ".join(key.lower().split())
        val = val.strip()
        if key == "include":
            target = _map_include(val, etc_dir)
            if target:
                _read_conf(target, etc_dir, depth + 1, out)
                section = out[-1][0] if out else section
            continue
        out.append((section, key, val))


def _map_include(val: str, etc_dir: str) -> str | None:
    """Map /etc/samba/<file> onto the import copy; refuse anything else."""
    norm = os.path.normpath(val)
    if not norm.startswith("/etc/samba/") or "%" in norm:
        return None
    target = os.path.join(etc_dir, norm[len("/etc/samba/") :])
    real = os.path.realpath(target)
    if not real.startswith(os.path.realpath(etc_dir) + "/"):
        return None
    return real


def _users(val: str) -> tuple[list[str], list[str]]:
    users, groups = [], []
    for item in re.split(r"[\s,]+", val.strip()):
        if not item:
            continue
        if item.startswith(("@", "+", "&")):
            groups.append(item)
        else:
            users.append(item)
    return users, groups


def parse_import(import_dir: str, volumes: list[str]) -> list[ImportedShare]:
    etc_dir = os.path.join(import_dir, "etc-samba")
    main = os.path.join(etc_dir, "smb.conf")
    if not os.path.isfile(main):
        return []
    triples: list[tuple[str, str, str]] = []
    _read_conf(main, etc_dir, 0, triples)
    sections: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for sec, key, val in triples:
        if sec.lower() in SKIP_SECTIONS or not sec:
            continue
        if sec not in sections:
            sections[sec] = {}
            order.append(sec)
        if key:
            sections[sec][key] = val
    return [_to_share(name, sections[name], volumes) for name in order]


def _to_share(name: str, p: dict[str, str], volumes: list[str]) -> ImportedShare:
    notes: list[str] = []
    guest = p.get("guest ok", p.get("public", "no")).lower() in TRUE
    writable = p.get("read only", "yes").lower() not in TRUE
    for alias in ("writeable", "writable", "write ok"):
        if alias in p:
            writable = p[alias].lower() in TRUE
    valid, vgroups = _users(p.get("valid users", ""))
    write, wgroups = _users(p.get("write list", ""))
    read, rgroups = _users(p.get("read list", ""))
    for g in vgroups + wgroups + rgroups:
        notes.append(f"group entry {g} is not imported; add its users individually")
    members: dict[str, str] = {}
    for u in valid:
        if u in read:
            members[u] = "ro"
        elif writable or u in write:
            members[u] = "rw"
        else:
            members[u] = "ro"
    all_users = None
    if not valid and not vgroups:
        # Old share open to everyone (guest) or to every authenticated user.
        all_users = "rw" if writable else "ro"
        if not guest:
            notes.append("was open to every user of the old server")
    if p.get("force user"):
        notes.append(f"'force user = {p['force user']}' is not carried over")
    share = ImportedShare(
        name=name,
        path=p.get("path", ""),
        comment=p.get("comment", ""),
        members=members,
        all_users=all_users,
        was_anonymous=guest,
        notes=notes,
    )
    share.problems = check_problems(share, volumes, share.path)
    return share


def check_problems(share: ImportedShare, volumes: list[str], path: str) -> list[str]:
    problems = []
    checks: list[tuple[Callable[[str], object], str]] = [
        (v.validate_share_name, share.name),
        (v.validate_comment, share.comment),
    ]
    for fn, val in checks:
        try:
            fn(val)
        except v.ValidationError as e:
            problems.append(str(e))
    for user in share.members:
        try:
            v.validate_username(user)
        except v.ValidationError as e:
            problems.append(f"{user!r}: {e}")
    try:
        v.validate_share_path(path, volumes)
    except v.ValidationError as e:
        problems.append(str(e))
    return problems


def register_routes(
    app: FastAPI,
    *,
    settings: Settings,
    registry: Registry,
    helper: Helper,
    volumes: list[str],
    render: Callable[..., Response],
    back: Callable[..., Response],
    require_read: Callable[..., Any],
    require_write: Callable[..., Any],
    form_dict: Callable[..., Any],
    apply: Callable[[list[ShareSpec]], None],
    clock: Callable[[], float],
) -> None:
    @app.get("/import")
    async def import_page(request: Request, s: SessionRow = Depends(require_read)) -> Response:
        shares = parse_import(settings.import_dir, volumes)
        ctx: dict[str, Any] = {
            "shares": shares,
            "existing_shares": {x.name.lower() for x in registry.list_shares()},
            "existing_users": set(registry.list_users()),
            "users": [],
            "mounted": os.path.isdir(settings.import_dir) and bool(os.listdir(settings.import_dir)),
        }
        if ctx["mounted"]:
            try:
                ctx["users"] = helper.import_scan().get("users", [])
            except HelperError as e:
                ctx["users_error"] = str(e)
        return render(request, "import.html", ctx, session=s)

    @app.post("/import/user")
    async def import_user(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        try:
            name = v.validate_username(form.get("name", ""))
            if registry.has_user(name):
                raise v.ValidationError(f"user {name!r} already exists")
            if name not in helper.import_scan().get("users", []):
                raise v.ValidationError(f"user {name!r} is not in the imported passdb")
            helper.import_user(name)
            registry.add_user(name, clock())
        except (v.ValidationError, HelperError, RegistryError) as e:
            return back("/import", err=str(e))
        audit.event("user_imported", user=name)
        return back("/import", msg=f"User {name} imported with their old password.")

    @app.post("/import/share")
    async def import_share(request: Request, s: SessionRow = Depends(require_write)) -> Response:
        form = await form_dict(request)
        name = form.get("name", "")
        found = {x.name: x for x in parse_import(settings.import_dir, volumes)}.get(name)
        if found is None:
            return back("/import", err="That share is not in the imported configuration.")
        path = form.get("path") or found.path
        problems = check_problems(found, volumes, path)
        if problems:
            return back("/import", err=f"{name}: " + "; ".join(problems))
        if found.was_anonymous and form.get("ack_anonymous") != "yes":
            return back(
                "/import",
                err=f"{name} was open without a password. Tick the box to confirm it will "
                "now require an SMB login.",
            )
        try:
            spec = v.validate_share(found.to_spec(path), volumes, registry.list_users())
            spec = ShareSpec(
                **{**spec.to_dict(), "no_unix_perms": fsinfo.lacks_unix_perms(spec.path)}
            )
            if registry.get_share(spec.name):
                raise v.ValidationError(f"a share named {spec.name!r} already exists")
            apply([*registry.list_shares(), spec])
            registry.save_share(spec)
        except (v.ValidationError, HelperError, RegistryError) as e:
            return back("/import", err=f"{name}: {e}")
        audit.event(
            "share_imported",
            share=spec.name,
            path=spec.path,
            members=spec.members,
            all_users=spec.all_users,
        )
        return back("/import", msg=f"Share {spec.name} imported.")
