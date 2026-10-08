"""Virtual paths used by the UI: "/<volume name>/<path inside the volume>".

The volume name is the last component of the configured volume path, so /mnt/files
appears as "files". Mapping is purely lexical and strict; the file operations then walk
the real path without following symlinks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ssm import validators as v


class VPathError(ValueError):
    pass


@dataclass(frozen=True)
class Volume:
    name: str
    root: str


class VolumeMap:
    def __init__(self, roots: list[str]) -> None:
        vols: list[Volume] = []
        seen: set[str] = set()
        for root in roots:
            real = os.path.realpath(root)
            name = os.path.basename(real.rstrip("/"))
            if not name or name in seen:
                raise VPathError(f"volume names must be unique; {name!r} is used twice")
            seen.add(name)
            vols.append(Volume(name, real))
        self.volumes = vols

    def to_real(self, vpath: str) -> str:
        if not isinstance(vpath, str) or not vpath.startswith("/") or vpath == "/":
            raise VPathError("invalid path")
        if v.has_control_chars(vpath) or os.path.normpath(vpath) != vpath:
            raise VPathError("invalid path")
        name, _, rest = vpath[1:].partition("/")
        for vol in self.volumes:
            if vol.name == name:
                if not rest:
                    return vol.root
                for part in rest.split("/"):
                    try:
                        v.validate_filename(part)
                    except v.ValidationError as e:
                        raise VPathError(str(e)) from e
                return vol.root.rstrip("/") + "/" + rest
        raise VPathError("no such volume")

    def to_virtual(self, real: str) -> str:
        for vol in self.volumes:
            if real == vol.root:
                return "/" + vol.name
            prefix = vol.root.rstrip("/") + "/"
            if real.startswith(prefix):
                return "/" + vol.name + "/" + real[len(prefix) :]
        raise VPathError("path is not inside a volume")

    def volume_of(self, real: str) -> Volume:
        for vol in self.volumes:
            if real == vol.root or real.startswith(vol.root.rstrip("/") + "/"):
                return vol
        raise VPathError("path is not inside a volume")
