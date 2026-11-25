"""The registry -> WebDAV ACL snapshot (/run/ssm-dav/acl.json).

WebDAV never reads the SQLite registry. Every registry change must reach the snapshot
before the next request, and the snapshot must hold nothing secret."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest

from ssm.acl_export import AclExporter, build_acl
from ssm.models import ShareSpec
from ssm.registry import Registry
from tests.conftest import Env, call, login, make_settings


def _reg(tmp_path: Path) -> Registry:
    return Registry(tmp_path / "r.db")


def test_every_mutation_calls_on_change(tmp_path: Path) -> None:
    r = _reg(tmp_path)
    hits: list[int] = []
    r.on_change = lambda: hits.append(1)
    r.add_user("alice", 1.0)
    r.add_user("bob", 1.0)
    r.set_display_name("alice", "Alice")
    r.save_share(ShareSpec(name="Docs", path="/v/Docs", members={"alice": "rw"}))
    r.save_share(ShareSpec(name="Docs2", path="/v/Docs", members={"alice": "ro"}), "Docs")
    r.bump_cred("alice")
    r.set_remote_access("alice", True)
    r.delete_share("Docs2")
    r.delete_user("bob")
    assert len(hits) == 9


def test_failed_mutation_does_not_need_to_notify(tmp_path: Path) -> None:
    r = _reg(tmp_path)
    r.add_user("alice", 1.0)
    hits: list[int] = []
    r.on_change = lambda: hits.append(1)
    with pytest.raises(Exception, match="already exists"):
        r.add_user("alice", 1.0)
    assert hits == []


def test_migration_is_additive_and_defaults_off(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE users (name TEXT PRIMARY KEY, created REAL NOT NULL);"
        "INSERT INTO users VALUES ('alice', 1.0);"
    )
    con.commit()
    con.close()
    r = Registry(db)
    flags = r.user_flags()
    assert flags["alice"][1] is False  # remote access off by default
    cols = {row[1] for row in sqlite3.connect(db).execute("PRAGMA table_info(users)")}
    assert {"name", "created", "display_name", "cred_gen", "remote_access"} <= cols


def test_cred_gen_increases_and_survives_recreate(tmp_path: Path) -> None:
    r = _reg(tmp_path)
    r.add_user("alice", 1.0)
    g0 = r.user_flags()["alice"][0]
    r.bump_cred("alice")
    g1 = r.user_flags()["alice"][0]
    assert g1 > g0
    r.delete_user("alice")
    r.add_user("alice", 2.0)
    # A re-created user must never reuse a generation a cached credential could hold.
    assert r.user_flags()["alice"][0] > g1


def test_build_acl_contents(tmp_path: Path) -> None:
    r = _reg(tmp_path)
    r.add_user("alice", 1.0)
    r.add_user("bob", 1.0)
    r.set_remote_access("alice", True)
    r.save_share(
        ShareSpec(name="Docs", path="/v/Docs", members={"alice": "rw", "bob": "ro"}),
    )
    r.save_share(ShareSpec(name="All", path="/v/All", all_users="ro"))
    acl = build_acl(r, ["/v"])
    assert acl["volumes"] == ["/v"]
    assert acl["users"]["alice"]["remote"] is True
    assert acl["users"]["bob"]["remote"] is False
    assert isinstance(acl["users"]["alice"]["cred"], int)
    shares = {s["name"]: s for s in acl["shares"]}
    assert shares["Docs"] == {
        "name": "Docs",
        "path": "/v/Docs",
        "all_users": None,
        "members": {"alice": "rw", "bob": "ro"},
    }
    assert shares["All"]["all_users"] == "ro"
    text = json.dumps(acl)
    for secret_word in ("session", "token", "csrf", "password", "hash"):
        assert secret_word not in text


def test_exporter_writes_atomically_with_mode_0640(tmp_path: Path) -> None:
    out = tmp_path / "bridge"
    out.mkdir()
    r = _reg(tmp_path)
    exp = AclExporter(r, str(out), ["/v"])
    r.on_change = exp
    r.add_user("alice", 1.0)
    p = out / "acl.json"
    assert json.loads(p.read_text())["users"]["alice"]["remote"] is False
    assert stat.S_IMODE(p.stat().st_mode) == 0o640
    r.set_remote_access("alice", True)
    assert json.loads(p.read_text())["users"]["alice"]["remote"] is True
    assert [x.name for x in out.iterdir()] == ["acl.json"]  # no temp files left


def test_exporter_skips_missing_dir_and_survives_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r = _reg(tmp_path)
    AclExporter(r, str(tmp_path / "missing"), ["/v"])()  # no bridge: WebDAV not used
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        AclExporter(r, str(ro), ["/v"])()  # must not raise
    finally:
        ro.chmod(0o700)
    assert "acl_export" in capsys.readouterr().out


# --- through the admin API ---------------------------------------------------------------


@pytest.fixture
def bridge_env(env: Env) -> Env:
    bridge = env.tmp / "bridge"
    bridge.mkdir()
    env.settings = make_settings(env.tmp, env.volume, dav_bridge_dir=str(bridge))
    env.extra["acl"] = bridge / "acl.json"
    return env


def _acl(env: Env) -> dict[str, Any]:
    return dict(json.loads(env.extra["acl"].read_text()))


def test_startup_writes_snapshot(bridge_env: Env) -> None:
    bridge_env.make_client(bridge_env.settings)
    assert _acl(bridge_env)["users"] == {}


def test_api_remote_access_flag(bridge_env: Env) -> None:
    c = bridge_env.make_client(bridge_env.settings)
    csrf = login(c)
    r = call(c, "post", "/api/users", csrf, json={"username": "alice", "password": "a" * 12})
    assert r.status_code == 201
    listed = c.get("/api/users").json()["users"][0]
    assert listed["remote_access"] is False
    assert _acl(bridge_env)["users"]["alice"]["remote"] is False
    r = call(c, "patch", "/api/users/alice", csrf, json={"remote_access": True})
    assert r.status_code == 200
    assert c.get("/api/users").json()["users"][0]["remote_access"] is True
    assert _acl(bridge_env)["users"]["alice"]["remote"] is True
    r = call(c, "patch", "/api/users/alice", csrf, json={"remote_access": "yes"})
    assert r.status_code == 422


def test_api_password_change_bumps_generation_first(bridge_env: Env) -> None:
    c = bridge_env.make_client(bridge_env.settings)
    csrf = login(c)
    call(c, "post", "/api/users", csrf, json={"username": "alice", "password": "a" * 12})
    g0 = _acl(bridge_env)["users"]["alice"]["cred"]
    # Even when the helper fails, the generation has moved: a stale cached credential
    # can only cause an extra check, never survive a password change.
    bridge_env.helper.fail_next = "user_set_password"
    r = call(c, "patch", "/api/users/alice", csrf, json={"password": "b" * 12})
    assert r.status_code == 502
    g1 = _acl(bridge_env)["users"]["alice"]["cred"]
    assert g1 > g0
    r = call(c, "patch", "/api/users/alice", csrf, json={"password": "c" * 12})
    assert r.status_code == 200
    assert _acl(bridge_env)["users"]["alice"]["cred"] > g1


def test_api_delete_and_membership_reach_snapshot(bridge_env: Env) -> None:
    c = bridge_env.make_client(bridge_env.settings)
    csrf = login(c)
    for u in ("alice", "bob"):
        call(c, "post", "/api/users", csrf, json={"username": u, "password": "a" * 12})
    (bridge_env.volume / "Docs").mkdir()
    r = call(
        c,
        "post",
        "/api/shares",
        csrf,
        json={
            "name": "Docs",
            "path": "/files/Docs",
            "members": [{"username": "alice", "access": "rw"}, {"username": "bob", "access": "ro"}],
        },
    )
    assert r.status_code in (200, 201), r.text
    assert _acl(bridge_env)["shares"][0]["members"] == {"alice": "rw", "bob": "ro"}
    call(c, "patch", "/api/users/bob", csrf, json={"remote_access": True})
    r = call(c, "delete", "/api/users/bob", csrf)
    assert r.status_code == 200
    acl = _acl(bridge_env)
    assert "bob" not in acl["users"]
    assert acl["shares"][0]["members"] == {"alice": "rw"}


def test_failed_delete_keeps_remote_flag(bridge_env: Env) -> None:
    c = bridge_env.make_client(bridge_env.settings)
    csrf = login(c)
    call(c, "post", "/api/users", csrf, json={"username": "bob", "password": "a" * 12})
    call(c, "patch", "/api/users/bob", csrf, json={"remote_access": True})
    bridge_env.helper.fail_next = "user_delete"
    r = call(c, "delete", "/api/users/bob", csrf)
    assert r.status_code == 502
    assert _acl(bridge_env)["users"]["bob"]["remote"] is True


def test_export_sets_group_for_the_dav_container(tmp_path: Path) -> None:
    import os

    reg = _reg(tmp_path)
    bridge = tmp_path / "bridge"
    bridge.mkdir()
    gid = os.getgroups()[-1]  # any group this test user belongs to
    AclExporter(reg, str(bridge), [], gid=gid)()
    assert (bridge / "acl.json").stat().st_gid == gid


def test_failed_export_removes_the_stale_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fail closed: a snapshot that may grant removed access must not stay behind."""
    reg = _reg(tmp_path)
    bridge = tmp_path / "bridge"
    bridge.mkdir()
    exp = AclExporter(reg, str(bridge), [])
    exp()
    assert (bridge / "acl.json").exists()

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("ssm.acl_export.tempfile.mkstemp", boom)
    exp()
    assert not (bridge / "acl.json").exists()
    assert '"acl_export", "ok": false' in capsys.readouterr().out


def test_settings_smb_gid() -> None:
    from ssm.settings import ConfigError, load_settings

    base = {"ADMIN_PASSWORD": "x" * 12}
    assert load_settings(base).dav_bridge_gid == 3000
    assert load_settings({**base, "SMB_GID": "4000"}).dav_bridge_gid == 4000
    for bad in ("0", "-1", "abc"):
        with pytest.raises(ConfigError):
            load_settings({**base, "SMB_GID": bad})
