"""Input validation. Every function either returns a safe value or raises ValidationError.

Validators never try to "clean up" values destined for smb.conf: invalid input is refused.
The only exception is ``sanitize_upload_filename``, which turns a browser-supplied name
into a safe basename (the result is still checked with ``validate_filename``).
These functions are used by both the web app and the root helper.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections.abc import Iterable

from ssm.models import ACCESS_VALUES, ShareSpec


class ValidationError(ValueError):
    """Raised for any rejected input. Messages never contain secret values."""


SHARE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", re.ASCII)
USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}", re.ASCII)

RESERVED_SHARE_NAMES = frozenset(
    {"global", "globals", "homes", "printers", "print$", "ipc$", "admin$", "c$"}
)
# Names that must never become SMB/unix accounts even if absent from /etc/passwd.
RESERVED_USERNAMES = frozenset(
    {
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "nobody",
        "nogroup",
        "smbusers",
        "ssm",
        "admin",
        "guest",
        "sambashare",
    }
)
DENIED_VOLUMES = (
    "/",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/data",
    "/run",
    "/usr",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var",
    "/root",
    "/tmp",  # noqa: S108 - a denylist entry, not a temp file
    "/home",
)
DENIED_VOLUME_TREES = ("/proc", "/sys", "/dev", "/etc", "/data", "/run", "/usr", "/boot")

MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 256
MAX_COMMENT_LEN = 256
MAX_NAME_BYTES = 255
UPLOAD_TEMP_PREFIX = ".ssm-upload-"

# Characters that have meaning inside an smb.conf value: % starts a substitution,
# a trailing backslash continues the line. Both are refused in values we render.
_SMBCONF_VALUE_FORBIDDEN = ("%", "\\")
# Path values additionally must not contain list separators that Samba parses.
_PATH_FORBIDDEN = (*_SMBCONF_VALUE_FORBIDDEN, ";", "#", '"')


def has_control_chars(s: str) -> bool:
    """True for C0/C1 controls, DEL, and Unicode line/paragraph separators."""
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:
            return True
        if unicodedata.category(ch) in ("Zl", "Zp"):
            return True
    return False


def _no_control(value: str, what: str) -> None:
    if not isinstance(value, str):
        raise ValidationError(f"{what} must be text")
    if has_control_chars(value):
        raise ValidationError(f"{what} contains control characters")


def validate_share_name(name: str) -> str:
    _no_control(name, "share name")
    if not SHARE_NAME_RE.fullmatch(name):
        raise ValidationError(
            "share name must start with a letter or digit and contain only "
            "letters, digits, space, '.', '_' or '-' (max 64)"
        )
    if name != name.strip():
        raise ValidationError("share name must not end with a space")
    if name.lower() in RESERVED_SHARE_NAMES:
        raise ValidationError(f"share name {name!r} is reserved")
    return name


def validate_username(name: str) -> str:
    _no_control(name, "username")
    if not USERNAME_RE.fullmatch(name):
        raise ValidationError(
            "username must be lowercase ASCII: start with a-z or '_', then a-z, 0-9, '_' "
            "or '-' (max 32)"
        )
    if name in RESERVED_USERNAMES:
        raise ValidationError(f"username {name!r} is reserved")
    return name


def validate_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValidationError("password must be text")
    if has_control_chars(password):
        raise ValidationError("password contains control characters")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValidationError(f"password must be at most {MAX_PASSWORD_LEN} characters")
    return password


def validate_comment(comment: str) -> str:
    _no_control(comment, "comment")
    if len(comment) > MAX_COMMENT_LEN:
        raise ValidationError(f"comment must be at most {MAX_COMMENT_LEN} characters")
    for bad in _SMBCONF_VALUE_FORBIDDEN:
        if bad in comment:
            raise ValidationError(f"comment must not contain {bad!r}")
    if comment != comment.strip():
        raise ValidationError("comment must not start or end with whitespace")
    return comment


def validate_filename(name: str) -> str:
    """A single path component for file operations (mkdir, rename, upload)."""
    _no_control(name, "file name")
    if name in ("", ".", ".."):
        raise ValidationError("invalid file name")
    if "/" in name:
        raise ValidationError("file name must not contain '/'")
    if len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        raise ValidationError("file name is too long")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValidationError("file name is not valid UTF-8") from e
    return name


def sanitize_upload_filename(raw: str) -> str:
    """Reduce a browser-supplied upload name to a safe basename."""
    if not isinstance(raw, str):
        raise ValidationError("file name must be text")
    base = re.split(r"[/\\]", raw)[-1]
    base = "".join(ch for ch in base if not has_control_chars(ch))
    base = base.strip()
    if base in ("", ".", ".."):
        raise ValidationError("invalid upload file name")
    if base.startswith(UPLOAD_TEMP_PREFIX):
        raise ValidationError("invalid upload file name")
    try:
        encoded = base.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValidationError("upload file name is not valid UTF-8") from e
    if len(encoded) > MAX_NAME_BYTES:
        stem, dot, ext = base.rpartition(".")
        if not dot or len(ext.encode()) > 16 or not stem:
            stem, ext, dot = base, "", ""
        budget = MAX_NAME_BYTES - len((dot + ext).encode())
        stem_b = stem.encode("utf-8")[:budget].decode("utf-8", "ignore")
        base = stem_b + dot + ext
    return validate_filename(base)


def _is_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def validate_volumes(volumes: Iterable[str]) -> list[str]:
    """Check the configured browse/share roots. Returns resolved absolute paths."""
    out: list[str] = []
    for raw in volumes:
        _no_control(raw, "volume path")
        if not raw.startswith("/"):
            raise ValidationError(f"volume {raw!r} must be an absolute path")
        real = os.path.realpath(raw)
        norm = os.path.normpath(raw)
        for candidate in (real, norm):
            if candidate in DENIED_VOLUMES:
                raise ValidationError(f"volume {raw!r} is a system path and not allowed")
            for tree in DENIED_VOLUME_TREES:
                if _is_within(candidate, tree):
                    raise ValidationError(f"volume {raw!r} is inside {tree} and not allowed")
        try:
            st_ = os.lstat(real)
        except OSError as e:
            raise ValidationError(f"volume {raw!r} does not exist") from e
        if not stat.S_ISDIR(st_.st_mode):
            raise ValidationError(f"volume {raw!r} is not a directory")
        out.append(real)
    for i, a in enumerate(out):
        for j, b in enumerate(out):
            if i != j and _is_within(a, b):
                raise ValidationError(f"volumes {a!r} and {b!r} overlap")
    return out


def validate_share_path(path: str, volumes: Iterable[str]) -> str:
    """An existing directory inside a configured volume. Returns the resolved path.

    The resolved path is what gets stored and rendered, so a symlink can never point a
    share outside its volume.
    """
    _no_control(path, "share path")
    if not path.startswith("/"):
        raise ValidationError("share path must be absolute")
    if path != path.strip():
        raise ValidationError("share path must not start or end with whitespace")
    real = os.path.realpath(path)
    for candidate in (path, real):
        for bad in _PATH_FORBIDDEN:
            if bad in candidate:
                raise ValidationError(f"share path must not contain {bad!r}")
        if has_control_chars(candidate):
            raise ValidationError("share path contains invalid characters")
        if any(part != part.strip() for part in candidate.split("/")):
            raise ValidationError("share path folders must not start or end with whitespace")
    roots = [os.path.realpath(v) for v in volumes]
    if not any(_is_within(real, root) for root in roots):
        raise ValidationError("share path is not inside a configured volume")
    if not os.path.isdir(real):
        raise ValidationError("share path is not an existing directory")
    return real


def validate_share(
    spec: ShareSpec, volumes: Iterable[str], known_users: Iterable[str]
) -> ShareSpec:
    """Validate a whole share. Requirement 3: a share nobody can reach is refused."""
    known = set(known_users)
    name = validate_share_name(spec.name)
    path = validate_share_path(spec.path, volumes)
    comment = validate_comment(spec.comment)
    members: dict[str, str] = {}
    for user, access in spec.members.items():
        validate_username(user)
        if access not in ACCESS_VALUES:
            raise ValidationError(f"access for {user!r} must be 'ro' or 'rw'")
        if user not in known:
            raise ValidationError(f"unknown SMB user {user!r}")
        members[user] = access
    if spec.all_users is not None and spec.all_users not in ACCESS_VALUES:
        raise ValidationError("all-users access must be 'ro', 'rw' or off")
    if not members and spec.all_users is None:
        raise ValidationError(
            "a share needs at least one member (or 'any SMB user' access); "
            "a share nobody can reach is not allowed"
        )
    return ShareSpec(
        name=name,
        path=path,
        comment=comment,
        members=dict(sorted(members.items())),
        all_users=spec.all_users,
        no_unix_perms=bool(spec.no_unix_perms),
    )
