"""WebDAV service configuration from environment variables. Invalid values stop it."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from ssm import validators as v
from ssm.settings import ConfigError

REAL_IP_HEADERS = ("x-forwarded-for", "cf-connecting-ip")
LOOPBACK = ("127.0.0.1", "::1", "localhost")


@dataclass(frozen=True)
class DavSettings:
    exposed_shares: list[str]
    volumes: list[str]
    trusted_proxies: list[str] = field(default_factory=list)
    real_ip_header: str = "x-forwarded-for"
    max_upload_bytes: int = 4096 * 1024 * 1024
    max_body_bytes: int = 1024 * 1024  # PROPFIND, PROPPATCH, LOCK bodies
    auth_cache_s: float = 300.0
    allow_http: bool = False  # CI litmus run on loopback only
    bind_addr: str = "0.0.0.0"  # noqa: S104  # nosec B104 - the host side of the port mapping
    bridge_dir: str = "/run/ssm-dav"
    verify_socket: str = "/run/ssm-dav/verify.sock"
    ntfy_url: str | None = None
    ntfy_token: str | None = field(default=None, repr=False)
    puid: int = 1000
    port: int = 8094
    threads: int = 32
    socket_timeout: float = 60.0
    realm: str = "smb-share-manager"


def _list(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _volumes(raw: list[str]) -> list[str]:
    """Lexical checks only: in the WebDAV container a volume root is just the parent of
    the share mounts. It is used to refuse shares that cover a whole volume."""
    out = []
    for vol in raw:
        if v.has_control_chars(vol) or not vol.startswith("/") or os.path.normpath(vol) != vol:
            raise ConfigError(f"VOLUMES entry {vol!r} must be a normalised absolute path.")
        if vol in v.DENIED_VOLUMES or any(
            vol == t or vol.startswith(t + "/") for t in v.DENIED_VOLUME_TREES
        ):
            raise ConfigError(f"VOLUMES entry {vol!r} is a system path.")
        out.append(vol)
    return out


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, str(default)))
    except ValueError as e:
        raise ConfigError(f"{key} must be an integer.") from e


def load_dav_settings(env: Mapping[str, str]) -> DavSettings:
    exposed = _list(env.get("DAV_EXPOSED_SHARES"))
    for name in exposed:
        try:
            v.validate_share_name(name)
        except v.ValidationError as e:
            raise ConfigError(f"DAV_EXPOSED_SHARES entry {name!r}: {e}") from e
    volumes = _volumes(_list(env.get("VOLUMES")))

    proxies = _list(env.get("TRUSTED_PROXIES"))
    for p in proxies:
        try:
            ipaddress.ip_network(p, strict=False)
        except ValueError as e:
            raise ConfigError(f"TRUSTED_PROXIES entry {p!r} is not an IP or network.") from e

    header = env.get("DAV_REAL_IP_HEADER", "x-forwarded-for").strip().lower()
    if header not in REAL_IP_HEADERS:
        raise ConfigError("DAV_REAL_IP_HEADER must be x-forwarded-for or cf-connecting-ip.")

    max_mb = _int(env, "DAV_MAX_UPLOAD_MB", _int(env, "MAX_UPLOAD_MB", 4096))
    if not 0 < max_mb <= 1024 * 1024:
        raise ConfigError("DAV_MAX_UPLOAD_MB must be between 1 and 1048576.")

    cache = _int(env, "DAV_AUTH_CACHE_S", 300)
    if not 0 <= cache <= 3600:
        raise ConfigError("DAV_AUTH_CACHE_S must be between 0 and 3600.")

    bind = env.get("DAV_BIND_ADDR", "0.0.0.0").strip()  # noqa: S104  # nosec B104
    allow_http = env.get("DAV_ALLOW_HTTP", "false").strip().lower() == "true"
    if allow_http and bind not in LOOPBACK:
        raise ConfigError(
            "DAV_ALLOW_HTTP=true is for local testing only and needs DAV_BIND_ADDR=127.0.0.1."
        )

    ntfy_url = env.get("NTFY_URL", "").strip() or None
    if ntfy_url is not None and (
        not ntfy_url.startswith(("https://", "http://"))
        or v.has_control_chars(ntfy_url)
        or " " in ntfy_url
        or len(ntfy_url) > 512
    ):
        raise ConfigError("NTFY_URL must be an http(s) URL.")
    ntfy_token = env.get("NTFY_TOKEN", "").strip() or None
    if ntfy_token is not None and (v.has_control_chars(ntfy_token) or len(ntfy_token) > 256):
        raise ConfigError("NTFY_TOKEN contains invalid characters.")

    bridge = env.get("DAV_BRIDGE_DIR", "/run/ssm-dav")
    return DavSettings(
        exposed_shares=exposed,
        volumes=volumes,
        trusted_proxies=proxies,
        real_ip_header=header,
        max_upload_bytes=max_mb * 1024 * 1024,
        auth_cache_s=float(cache),
        allow_http=allow_http,
        bind_addr=bind,
        bridge_dir=bridge,
        verify_socket=env.get("DAV_VERIFY_SOCKET", bridge.rstrip("/") + "/verify.sock"),
        ntfy_url=ntfy_url,
        ntfy_token=ntfy_token,
        puid=_int(env, "PUID", 1000),
        threads=max(4, min(128, _int(env, "DAV_THREADS", 32))),
    )
