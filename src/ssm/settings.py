"""Configuration from environment variables. Invalid configuration stops the app."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ssm import validators as v


class ConfigError(Exception):
    """The app must not start with this configuration."""


HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*",
    re.ASCII,
)


@dataclass(frozen=True)
class Settings:
    admin_password: str | None = field(repr=False)
    admin_password_hash: str | None = field(repr=False)
    volumes: list[str]
    data_dir: str = "/data"
    trusted_proxies: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    cookie_secure: str = "auto"  # auto | true | false
    max_upload_bytes: int = 4096 * 1024 * 1024
    helper_socket: str = "/run/ssm/helper.sock"
    version: str = "dev"
    build_date: str = "unknown"
    import_dir: str = "/import"

    def check(self) -> None:
        if not self.admin_password and not self.admin_password_hash:
            raise ConfigError(
                "Neither ADMIN_PASSWORD nor ADMIN_PASSWORD_HASH is set; refusing to start."
            )
        if (
            self.admin_password is not None
            and self.admin_password_hash is None
            and len(self.admin_password) < v.MIN_PASSWORD_LEN
        ):
            raise ConfigError(f"ADMIN_PASSWORD must be at least {v.MIN_PASSWORD_LEN} characters.")
        if self.admin_password_hash is not None and not self.admin_password_hash.startswith(
            "$argon2id$"
        ):
            raise ConfigError("ADMIN_PASSWORD_HASH must be an argon2id hash ($argon2id$...).")
        if self.cookie_secure not in ("auto", "true", "false"):
            raise ConfigError("COOKIE_SECURE must be auto, true or false.")
        for p in self.trusted_proxies:
            try:
                ipaddress.ip_network(p, strict=False)
            except ValueError as e:
                raise ConfigError(f"TRUSTED_PROXIES entry {p!r} is not an IP or network.") from e
        for h in self.allowed_hosts:
            if not HOSTNAME_RE.fullmatch(h):
                raise ConfigError(f"ALLOWED_HOSTS entry {h!r} is not a valid host name.")
        if self.max_upload_bytes <= 0:
            raise ConfigError("MAX_UPLOAD_MB must be positive.")


def _list(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def load_settings(env: Mapping[str, str]) -> Settings:
    try:
        max_mb = int(env.get("MAX_UPLOAD_MB", "4096"))
    except ValueError as e:
        raise ConfigError("MAX_UPLOAD_MB must be an integer.") from e
    s = Settings(
        admin_password=env.get("ADMIN_PASSWORD") or None,
        admin_password_hash=env.get("ADMIN_PASSWORD_HASH") or None,
        volumes=_list(env.get("VOLUMES")),
        data_dir=env.get("DATA_DIR", "/data"),
        trusted_proxies=_list(env.get("TRUSTED_PROXIES")),
        allowed_hosts=[h.lower() for h in _list(env.get("ALLOWED_HOSTS"))],
        cookie_secure=env.get("COOKIE_SECURE", "auto").lower(),
        max_upload_bytes=max_mb * 1024 * 1024,
        helper_socket=env.get("HELPER_SOCKET", "/run/ssm/helper.sock"),
        version=env.get("APP_VERSION", "dev"),
        build_date=env.get("BUILD_DATE", "unknown"),
        import_dir=env.get("IMPORT_DIR", "/import"),
    )
    s.check()
    return s
