"""In-process harness for the WebDAV service: a temp volume with shares, an ACL snapshot,
a fake password verifier and a minimal WSGI client that builds environs the way cheroot
does (PATH_INFO as latin-1 decoded bytes)."""

from __future__ import annotations

import base64
import io
import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote_to_bytes

from ssm.dav.acl import AclStore
from ssm.dav.app import build_app
from ssm.dav.settings import DavSettings
from ssm.helper_client import HelperError

PROXY = "10.0.0.2"  # Traefik: in TRUSTED_PROXIES
CLIENT = "203.0.113.5"  # the real client behind it
HOST = "dav.example.org"
PW = {
    "alice": "alice-password-1234",
    "bob": "bob-password-12345",
    "carol": "carol-password-1234",
    "dave": "dave-password-12345",
    "erin": "erin-password-12345",
}
EXPOSED = ["Docs", "Photos", "Secret", "Empty", "Common"]


class FakeVerifier:
    def __init__(self) -> None:
        self.users = dict(PW)
        self.calls: list[str] = []
        self.down = False

    def verify(self, name: str, password: str) -> bool:
        self.calls.append(name)
        if self.down:
            raise HelperError("helper unavailable")
        return self.users.get(name) == password


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes
    header_list: list[tuple[str, str]] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def default_acl(vol: Path) -> dict[str, Any]:
    gen = 1000
    return {
        "format": 1,
        "volumes": [str(vol)],
        "users": {
            "alice": {"cred": gen, "remote": True},
            "bob": {"cred": gen, "remote": True},
            "carol": {"cred": gen, "remote": False},
            "dave": {"cred": gen, "remote": True},
            "erin": {"cred": gen, "remote": True},
        },
        "shares": [
            {
                "name": "Docs",
                "path": str(vol / "Docs"),
                "all_users": None,
                "members": {"alice": "rw", "bob": "ro", "carol": "rw"},
            },
            {
                "name": "Photos",
                "path": str(vol / "Photos"),
                "all_users": None,
                "members": {"alice": "ro", "bob": "rw"},
            },
            {
                "name": "Secret",
                "path": str(vol / "Secret"),
                "all_users": None,
                "members": {"dave": "rw"},
            },
            {"name": "Empty", "path": str(vol / "Empty"), "all_users": None, "members": {}},
            {"name": "Common", "path": str(vol / "Common"), "all_users": "ro", "members": {}},
            {
                "name": "Hidden",
                "path": str(vol / "Hidden"),
                "all_users": None,
                "members": {"alice": "rw"},
            },
            {"name": "Whole", "path": str(vol), "all_users": None, "members": {"alice": "rw"}},
        ],
    }


class Dav:
    def __init__(self, tmp: Path, **overrides: Any) -> None:
        self.tmp = tmp
        self.vol = tmp / "vol"
        for name in ("Docs", "Photos", "Secret", "Empty", "Common", "Hidden"):
            (self.vol / name).mkdir(parents=True)
        (self.vol / "Docs" / "readme.txt").write_bytes(b"hello docs\n")
        (self.vol / "Photos" / "cat.jpg").write_bytes(b"\xff\xd8 not really a jpeg")
        (self.vol / "Secret" / "plans.txt").write_bytes(b"secret plans")
        (self.vol / "Hidden" / "h.txt").write_bytes(b"hidden")
        (self.vol / "top-level.txt").write_bytes(b"volume root file")
        self.outside = tmp / "timenest"
        self.outside.mkdir()
        (self.outside / "backup.txt").write_bytes(b"time machine data")
        self.bridge = tmp / "bridge"
        self.bridge.mkdir()
        self.acl = default_acl(self.vol)
        self.write_acl()
        self.mounted = {s["path"] for s in self.acl["shares"] if s["path"] != str(self.vol)}
        self.verifier = FakeVerifier()
        self.clock = Clock()
        self.sent: list[dict[str, Any]] = []
        base = DavSettings(
            exposed_shares=list(EXPOSED),
            volumes=[str(self.vol)],
            trusted_proxies=["10.0.0.0/24"],
            max_upload_bytes=1024 * 1024,
            bridge_dir=str(self.bridge),
        )
        self.settings = replace(base, **overrides)
        self.build()

    def build(self) -> None:
        self.store = AclStore(
            str(self.bridge / "acl.json"),
            self.settings.exposed_shares,
            self.settings.volumes,
            is_mountpoint=lambda p: p in self.mounted,
        )
        self.app = build_app(
            self.settings,
            self.store,
            self.verifier,
            clock=self.clock,
            notify_sender=self.sent.append,
        )

    def write_acl(self) -> None:
        p = self.bridge / "acl.json"
        tmp = self.bridge / ".acl.tmp"
        tmp.write_text(json.dumps(self.acl))
        os.replace(tmp, p)

    def share(self, name: str) -> dict[str, Any]:
        return next(s for s in self.acl["shares"] if s["name"] == name)

    def req(
        self,
        method: str,
        path: str,
        user: str | None = "alice",
        password: str | None = None,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        peer: str = PROXY,
        client: str | None = CLIENT,
        proto: str | None = "https",
        raw_path: bool = False,
        authorization: str | None = None,
        chunked: bool = False,
    ) -> Resp:
        raw = path if raw_path else quote(path, safe="/")
        env: dict[str, Any] = {
            "REQUEST_METHOD": method,
            "SCRIPT_NAME": "",
            "PATH_INFO": unquote_to_bytes(raw).decode("latin-1"),
            "QUERY_STRING": "",
            "SERVER_NAME": HOST,
            "SERVER_PORT": "8094",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "REMOTE_ADDR": peer,
            "HTTP_HOST": HOST,
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.version": (1, 0),
            "wsgi.multithread": True,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        if chunked:
            env["HTTP_TRANSFER_ENCODING"] = "chunked"
        elif body or method in ("PUT", "PROPFIND", "PROPPATCH", "LOCK"):
            env["CONTENT_LENGTH"] = str(len(body))
        if proto is not None:
            env["HTTP_X_FORWARDED_PROTO"] = proto
        if client is not None:
            env["HTTP_X_FORWARDED_FOR"] = client
        if authorization is not None:
            env["HTTP_AUTHORIZATION"] = authorization
        elif user is not None:
            pw = PW.get(user, "x") if password is None else password
            tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
            env["HTTP_AUTHORIZATION"] = f"Basic {tok}"
        for k, val in (headers or {}).items():
            key = k.upper().replace("-", "_")
            if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                env[key] = val
            else:
                env["HTTP_" + key] = val
        status: list[str] = []
        hdrs: list[tuple[str, str]] = []

        def start_response(s: str, h: list[tuple[str, str]], exc_info: Any = None) -> Any:
            status[:] = [s]
            hdrs[:] = list(h)
            return lambda data: None

        it = self.app(env, start_response)
        try:
            out = b"".join(it)
        finally:
            close = getattr(it, "close", None)
            if close is not None:
                close()
        return Resp(int(status[0].split()[0]), {k.lower(): v for k, v in hdrs}, out, hdrs)


PROPFIND_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
)

LOCK_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
    b"<D:locktype><D:write/></D:locktype><D:owner>test</D:owner></D:lockinfo>"
)


def dest(path: str) -> str:
    return f"https://{HOST}{quote(path, safe='/')}"
