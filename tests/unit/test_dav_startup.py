"""WebDAV settings validation and the startup self-checks that keep the container
narrow: no root, not PUID, no capabilities, no whole volume, no /data or /mnt/timenest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ssm.dav.acl import AclStore, parse_mountinfo
from ssm.dav.main import StartupError, startup_checks
from ssm.dav.settings import load_dav_settings
from ssm.settings import ConfigError
from tests.unit.dav_harness import Dav

BASE_ENV = {
    "DAV_EXPOSED_SHARES": "Docs,Photos",
    "VOLUMES": "/mnt/files",
    "TRUSTED_PROXIES": "192.168.0.0/18",
    "PUID": "1000",
}


def test_settings_defaults() -> None:
    s = load_dav_settings(BASE_ENV)
    assert s.exposed_shares == ["Docs", "Photos"]
    assert s.trusted_proxies == ["192.168.0.0/18"]
    assert s.real_ip_header == "x-forwarded-for"
    assert s.allow_http is False
    assert s.ntfy_url is None
    assert s.max_upload_bytes == 4096 * 1024 * 1024
    assert s.auth_cache_s == 300


def test_settings_default_serves_nothing() -> None:
    s = load_dav_settings({**BASE_ENV, "DAV_EXPOSED_SHARES": ""})
    assert s.exposed_shares == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("DAV_EXPOSED_SHARES", "Docs,../etc"),
        ("DAV_EXPOSED_SHARES", "Bad\nName"),
        ("TRUSTED_PROXIES", "not-an-ip"),
        ("DAV_REAL_IP_HEADER", "x-real-ip"),
        ("DAV_MAX_UPLOAD_MB", "0"),
        ("DAV_MAX_UPLOAD_MB", "lots"),
        ("DAV_AUTH_CACHE_S", "-1"),
        ("DAV_AUTH_CACHE_S", "100000"),
        ("NTFY_URL", "ftp://ntfy.example.org/x"),
        ("NTFY_URL", "https://ntfy.example.org/x\nInjected: 1"),
        ("NTFY_TOKEN", "tok\r\nX: y"),
        ("VOLUMES", "/"),
        ("VOLUMES", "/etc"),
    ],
)
def test_settings_refuse_bad_values(key: str, value: str) -> None:
    with pytest.raises(ConfigError):
        load_dav_settings({**BASE_ENV, key: value})


def test_allow_http_only_on_loopback() -> None:
    with pytest.raises(ConfigError):
        load_dav_settings({**BASE_ENV, "DAV_ALLOW_HTTP": "true", "DAV_BIND_ADDR": "0.0.0.0"})
    s = load_dav_settings({**BASE_ENV, "DAV_ALLOW_HTTP": "true", "DAV_BIND_ADDR": "127.0.0.1"})
    assert s.allow_http is True


def test_ntfy_token_not_in_repr() -> None:
    s = load_dav_settings({**BASE_ENV, "NTFY_URL": "https://n.example/t", "NTFY_TOKEN": "tk_9"})
    assert "tk_9" not in repr(s)


def test_parse_mountinfo_unescapes() -> None:
    text = (
        "22 1 0:21 / / rw - overlay overlay rw\n"
        "30 22 8:1 /files/Docs /mnt/files/Docs rw - ext4 /dev/sda1 rw\n"
        "31 22 8:1 /x /mnt/files/My\\040Photos rw - ext4 /dev/sda1 rw\n"
    )
    assert parse_mountinfo(text) == {"/", "/mnt/files/Docs", "/mnt/files/My Photos"}


# --- startup checks ------------------------------------------------------------------------


def checks(dav: Dav, **kw: object) -> None:
    args: dict[str, object] = {
        "settings": dav.settings,
        "store": dav.store,
        "uid": 2999,
        "puid": 1000,
        "cap_eff": 0,
        "mounts": dav.mounted | {"/"},
        "exists": lambda p: False,
    }
    args.update(kw)
    startup_checks(**args)  # type: ignore[arg-type]


def test_startup_ok(tmp_path: Path) -> None:
    checks(Dav(tmp_path))


@pytest.mark.parametrize(
    ("kw", "msg"),
    [
        ({"uid": 0}, "root"),
        ({"uid": 1000}, "PUID"),
        ({"cap_eff": 0x20}, "capabilit"),
    ],
)
def test_startup_refuses_privilege(tmp_path: Path, kw: dict[str, object], msg: str) -> None:
    with pytest.raises(StartupError, match=msg):
        checks(Dav(tmp_path), **kw)


def test_startup_refuses_whole_volume_share(tmp_path: Path) -> None:
    d = Dav(tmp_path, exposed_shares=["Docs", "Whole"])
    d.build()
    with pytest.raises(StartupError, match="whole volume"):
        checks(d)


def test_startup_refuses_mounted_volume_root(tmp_path: Path) -> None:
    d = Dav(tmp_path)
    with pytest.raises(StartupError, match="volume"):
        checks(d, mounts=d.mounted | {"/", str(d.vol)})


@pytest.mark.parametrize("path", ["/data", "/mnt/timenest", "/run/ssm"])
def test_startup_refuses_forbidden_mounts(tmp_path: Path, path: str) -> None:
    d = Dav(tmp_path)
    with pytest.raises(StartupError, match="must not"):
        checks(d, mounts=d.mounted | {"/", path})
    with pytest.raises(StartupError, match="must not"):
        checks(d, exists=lambda p: p == path)


def test_reload_drops_share_that_became_whole_volume(tmp_path: Path) -> None:
    d = Dav(tmp_path)
    assert "docs" in d.store.current().served  # type: ignore[union-attr]
    d.share("Docs")["path"] = str(d.vol)
    d.mounted.add(str(d.vol))
    d.write_acl()
    snap = d.store.current()
    assert snap is not None and "docs" not in snap.served


def test_store_rejects_wrong_shapes(tmp_path: Path) -> None:
    p = tmp_path / "acl.json"
    store = AclStore(str(p), ["Docs"], ["/v"], is_mountpoint=lambda x: True)
    for bad in (
        [],
        {"format": 2, "users": {}, "shares": []},
        {"format": 1, "users": {"alice": {"cred": "1", "remote": True}}, "shares": []},
        {"format": 1, "users": {}, "shares": [{"name": "Docs"}]},
        {"format": 1, "users": {"Bad Name": {"cred": 1, "remote": True}}, "shares": []},
        {
            "format": 1,
            "users": {},
            "shares": [{"name": "Docs", "path": "relative", "all_users": None, "members": {}}],
        },
        {
            "format": 1,
            "users": {},
            "shares": [{"name": "Docs", "path": "/v/D", "all_users": "admin", "members": {}}],
        },
        {
            "format": 1,
            "users": {},
            "shares": [{"name": "Docs", "path": "/v/D", "all_users": None, "members": {"a": "x"}}],
        },
    ):
        p.write_text(json.dumps(bad))
        assert store.current() is None, bad
