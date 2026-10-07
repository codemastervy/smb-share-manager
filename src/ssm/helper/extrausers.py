"""SMB unix accounts in libnss-extrausers files (/data/extrausers/{passwd,group,shadow}).

Debian's useradd has no --extrausers option (that is an Ubuntu-only patch), and the
container's /etc is read-only, so the helper maintains these three files itself. The
format is fixed and every field is generated here from a validated username, so no
caller-supplied text other than the username ever reaches the files.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from ssm import validators as v

SHELL = "/usr/sbin/nologin"
HOME = "/nonexistent"
GROUP_NAME = "smbusers"


def _read(path: Path) -> list[str]:
    try:
        return [ln for ln in path.read_text().splitlines() if ln.strip()]
    except FileNotFoundError:
        return []


def _write_atomic(path: Path, lines: list[str], mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("".join(ln + "\n" for ln in lines))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read_users(directory: str) -> dict[str, int]:
    out = {}
    for ln in _read(Path(directory) / "passwd"):
        parts = ln.split(":")
        if len(parts) == 7 and parts[2].isdigit():
            out[parts[0]] = int(parts[2])
    return out


def _write_all(directory: str, users: dict[str, int], gid: int) -> None:
    d = Path(directory)
    for name in users:
        v.validate_username(name)  # defense in depth: never write anything else
    days = int(time.time() // 86400)
    ordered = sorted(users.items(), key=lambda kv: kv[1])
    passwd = [f"{n}:x:{uid}:{gid}::{HOME}:{SHELL}" for n, uid in ordered]
    shadow = [f"{n}:!*:{days}:0:99999:7:::" for n, _ in ordered]
    group = [f"{GROUP_NAME}:x:{gid}:{','.join(n for n, _ in ordered)}"]
    _write_atomic(d / "group", group, 0o644)
    _write_atomic(d / "shadow", shadow, 0o640)
    _write_atomic(d / "passwd", passwd, 0o644)


def ensure_files(directory: str, gid: int) -> None:
    _write_all(directory, read_users(directory), gid)


def add_user(directory: str, name: str, gid: int, uid_min: int) -> int:
    users = read_users(directory)
    if name in users:
        raise ValueError(f"user {name!r} already exists")
    # Never reuse a uid: files written by a deleted user must not become someone else's.
    hw_path = Path(directory) / "next_uid"
    try:
        high_water = int(hw_path.read_text().strip())
    except (FileNotFoundError, ValueError):
        high_water = uid_min
    uid = max([high_water, uid_min, *(u + 1 for u in users.values())])
    users[name] = uid
    _write_atomic(hw_path, [str(uid + 1)], 0o644)
    _write_all(directory, users, gid)
    return uid


def remove_user(directory: str, name: str, gid: int) -> None:
    users = read_users(directory)
    if name not in users:
        raise ValueError(f"{name!r} is not an SMB user managed here")
    del users[name]
    _write_all(directory, users, gid)
