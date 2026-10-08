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

from ssm import validators as v
from ssm.models import ShareSpec

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


def read_sections(import_dir: str) -> dict[str, dict[str, str]]:
    """Read the old smb.conf (and its includes) into {section: {param: value}}.

    Runs in the root helper: the /import copy is root-only because it holds password
    hashes. Nothing here is validated; that happens in ``shares_from_sections``.
    """
    etc_dir = os.path.join(import_dir, "etc-samba")
    main = os.path.join(etc_dir, "smb.conf")
    if not os.path.isfile(main) or os.path.islink(main):
        return {}
    triples: list[tuple[str, str, str]] = []
    _read_conf(main, etc_dir, 0, triples)
    sections: dict[str, dict[str, str]] = {}
    for sec, key, val in triples:
        if sec.lower() in SKIP_SECTIONS or not sec:
            continue
        sections.setdefault(sec, {})
        if key:
            sections[sec][key] = val
    return sections


def shares_from_sections(sections: object, volumes: list[str]) -> list[ImportedShare]:
    if not isinstance(sections, dict):
        return []
    out = []
    for name, params in sections.items():
        if isinstance(name, str) and isinstance(params, dict):
            clean = {str(k): str(val) for k, val in params.items()}
            out.append(_to_share(name, clean, volumes))
    return out


def parse_import(import_dir: str, volumes: list[str]) -> list[ImportedShare]:
    return shares_from_sections(read_sections(import_dir), volumes)


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
