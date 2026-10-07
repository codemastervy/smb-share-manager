"""Which filesystem a path lives on (from /proc/self/mountinfo)."""

from __future__ import annotations

import os

NO_UNIX_PERMS_FS = frozenset({"exfat", "vfat", "msdos", "fat", "ntfs", "ntfs3", "fuseblk"})
MOUNTINFO = "/proc/self/mountinfo"


def _unescape(s: str) -> str:
    # mountinfo escapes space, tab, newline and backslash as octal.
    return (
        s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
    )


def parse_mountinfo(text: str) -> list[tuple[str, str]]:
    """Return [(mount point, fs type)]."""
    out = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields = left.split()
        rfields = right.split()
        if len(fields) < 5 or not rfields:
            continue
        out.append((_unescape(fields[4]), rfields[0]))
    return out


def fs_type(path: str, mountinfo_text: str | None = None) -> str:
    if mountinfo_text is None:
        try:
            with open(MOUNTINFO) as f:
                mountinfo_text = f.read()
        except OSError:
            return "unknown"
    real = os.path.realpath(path)
    best, best_type = "", "unknown"
    for mp, typ in parse_mountinfo(mountinfo_text):
        if (real == mp or real.startswith(mp.rstrip("/") + "/") or mp == "/") and len(mp) >= len(
            best
        ):
            best, best_type = mp, typ
    return best_type


def lacks_unix_perms(path: str, mountinfo_text: str | None = None) -> bool:
    return fs_type(path, mountinfo_text) in NO_UNIX_PERMS_FS
