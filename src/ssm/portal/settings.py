"""Files portal configuration from environment variables. Invalid values stop it."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ssm import validators as v
from ssm.dav.settings import _int, _list, _volumes
from ssm.settings import ConfigError

SECRET_RE = re.compile(r"[A-Za-z0-9._~+/=-]{32,256}", re.ASCII)
HEADER_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}", re.ASCII)
HOST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    re.ASCII,
)


@dataclass(frozen=True)
class PortalSettings:
    hosts: list[str]
    exposed_shares: list[str]
    volumes: list[str]
    trusted_proxies: list[str]
    proxy_secret: str = field(default="", repr=False)
    identity_header: str = "remote-email"
    header_verified: bool = False
    max_upload_bytes: int = 4096 * 1024 * 1024
    max_json_bytes: int = 64 * 1024
    bridge_dir: str = "/run/ssm-dav"
    frontend_dir: str = "/opt/app/frontend"
    puid: int = 1000
    dav_uid: int = 2999
    port: int = 8096


def _bool(env: Mapping[str, str], key: str) -> bool:
    raw = env.get(key, "false").strip().lower()
    if raw not in ("true", "false", ""):
        raise ConfigError(f"{key} must be true or false.")
    return raw == "true"


def load_portal_settings(env: Mapping[str, str]) -> PortalSettings:
    hosts = [h.lower() for h in _list(env.get("PORTAL_HOSTS"))]
    if not hosts:
        raise ConfigError(
            "PORTAL_HOSTS is required: the portal's public host name, "
            "e.g. files.example.org (no scheme, no port)."
        )
    for h in hosts:
        if not HOST_RE.fullmatch(h):
            raise ConfigError(f"PORTAL_HOSTS entry {h!r} is not a host name.")

    exposed = _list(env.get("PORTAL_EXPOSED_SHARES", env.get("DAV_EXPOSED_SHARES", "")))
    for name in exposed:
        try:
            v.validate_share_name(name)
        except v.ValidationError as e:
            raise ConfigError(f"PORTAL_EXPOSED_SHARES entry {name!r}: {e}") from e

    proxies = _list(env.get("PORTAL_TRUSTED_PROXIES"))
    if not proxies:
        raise ConfigError(
            "PORTAL_TRUSTED_PROXIES is required: the address or network of the proxy that "
            "adds the identity header (Traefik/Pangolin). Nothing else is believed."
        )
    for p in proxies:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError as e:
            raise ConfigError(f"PORTAL_TRUSTED_PROXIES entry {p!r} is not an IP or network.") from e
        if net.prefixlen == 0:
            raise ConfigError("PORTAL_TRUSTED_PROXIES must not trust every address.")

    secret = env.get("PORTAL_PROXY_SECRET", "").strip()
    if not SECRET_RE.fullmatch(secret):
        raise ConfigError(
            "PORTAL_PROXY_SECRET is required: 32 or more random characters (letters, digits, "
            "._~+/=-), e.g. from `openssl rand -hex 32`. Pangolin sends it as the "
            "X-Portal-Proxy-Secret custom header, so nothing else can pose as the proxy."
        )

    header = env.get("PORTAL_IDENTITY_HEADER", "remote-email").strip().lower()
    if not HEADER_RE.fullmatch(header):
        raise ConfigError("PORTAL_IDENTITY_HEADER must be a header name like remote-email.")

    max_mb = _int(
        env,
        "PORTAL_MAX_UPLOAD_MB",
        _int(env, "DAV_MAX_UPLOAD_MB", _int(env, "MAX_UPLOAD_MB", 4096)),
    )
    if not 0 < max_mb <= 1024 * 1024:
        raise ConfigError("PORTAL_MAX_UPLOAD_MB must be between 1 and 1048576.")

    return PortalSettings(
        hosts=hosts,
        exposed_shares=exposed,
        volumes=_volumes(_list(env.get("VOLUMES"))),
        trusted_proxies=proxies,
        proxy_secret=secret,
        identity_header=header,
        header_verified=_bool(env, "PORTAL_HEADER_VERIFIED"),
        max_upload_bytes=max_mb * 1024 * 1024,
        bridge_dir=env.get("DAV_BRIDGE_DIR", "/run/ssm-dav"),
        frontend_dir=env.get("FRONTEND_DIR", "/opt/app/frontend"),
        puid=_int(env, "PUID", 1000),
        dav_uid=_int(env, "DAV_UID", 2999),
    )
