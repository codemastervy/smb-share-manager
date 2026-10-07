"""End-to-end flows through the web app with a fake helper (requirements 3, 4, 9, 10, 11)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ORIGIN, Env, login, post

PW = "alice password 1"


def events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    return [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]


def mk_user(c: TestClient, csrf: str, name: str = "alice") -> None:
    r = post(c, "/users", csrf, {"name": name, "password": PW, "password2": PW})
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]


def mk_share(c: TestClient, csrf: str, env: Env, **kw: str) -> Any:
    (env.volume / "Photos").mkdir(exist_ok=True)
    data = {
        "name": "Photos",
        "path": str(env.volume / "Photos"),
        "comment": "",
        "all_users": "off",
        "access_alice": "rw",
    }
    data.update(kw)
    return post(c, "/shares", csrf, data)


def test_full_share_lifecycle_and_audit(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    assert mk_share(c, csrf, env).status_code == 303
    assert [s.name for s in env.helper.shares] == ["Photos"]
    assert env.helper.shares[0].members == {"alice": "rw"}
    r = post(
        c,
        "/shares/Photos",
        csrf,
        {
            "name": "Pictures",
            "path": str(env.volume / "Photos"),
            "all_users": "off",
            "access_alice": "ro",
        },
    )
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert env.helper.shares[0].name == "Pictures"
    assert env.helper.shares[0].members == {"alice": "ro"}
    assert post(c, "/shares/Pictures/delete", csrf).status_code == 303
    assert env.helper.shares == []
    assert (env.volume / "Photos").is_dir()  # unsharing never touches the folder
    kinds = [e["event"] for e in events(capsys)]
    for k in ("user_created", "share_created", "share_updated", "share_deleted"):
        assert k in kinds
    out = json.dumps(kinds)
    assert PW not in out


def test_zero_member_share_refused_over_http(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    r = mk_share(c, csrf, env, access_alice="none")
    assert r.status_code == 400
    assert "nobody can reach" in r.text
    assert env.helper.shares == []


def test_all_users_label_is_honest(env: Env) -> None:
    c = env.make_client()
    login(c)
    page = c.get("/shares/new").text
    assert "every SMB user of this server" in page
    assert "not anonymous guest access" in page
    assert "guest ok" not in page.lower()


def test_helper_failure_does_not_save_share(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    env.helper.fail_next = "apply_shares"
    r = mk_share(c, csrf, env)
    assert r.status_code == 400
    assert "Photos" not in c.get("/shares").text.split("<main>")[1].split("New share")[1]


def test_user_password_mismatch_and_min_length(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    r = post(c, "/users", csrf, {"name": "bob", "password": PW, "password2": PW + "x"})
    assert "err=" in r.headers["location"]
    r = post(c, "/users", csrf, {"name": "bob", "password": "short", "password2": "short"})
    assert "err=" in r.headers["location"]
    assert "bob" not in env.helper.users


def test_set_password_failure_rolls_back_user(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    env.helper.fail_next = "user_set_password"
    r = post(c, "/users", csrf, {"name": "bob", "password": PW, "password2": PW})
    assert "err=" in r.headers["location"]
    assert "bob" not in env.helper.users


def test_cannot_delete_sole_member(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    r = post(c, "/users/alice/delete", csrf)
    assert "only member" in r.headers["location"].replace("+", " ")
    assert "alice" in env.helper.users


def test_delete_user_removes_membership(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_user(c, csrf, "bob")
    mk_share(c, csrf, env, access_bob="ro")
    assert post(c, "/users/bob/delete", csrf).status_code == 303
    assert env.helper.shares[0].members == {"alice": "rw"}
    assert "bob" not in env.helper.users
    assert "user_deleted" in [e["event"] for e in events(capsys)]


# --- requirement 9 -------------------------------------------------------------------------


def test_permissions_require_tick(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    form = {"before_uid": "0", "before_gid": "0", "before_mode": "0755"}
    r = post(c, "/shares/Photos/permissions", csrf, form)
    assert "err=" in r.headers["location"]
    assert not [x for x in env.helper.calls if x[0] == "perm_apply"]
    r = post(c, "/shares/Photos/permissions", csrf, {**form, "fix_permissions": "yes"})
    assert "msg=" in r.headers["location"]
    applied = [x for x in env.helper.calls if x[0] == "perm_apply"]
    assert applied and applied[0][1]["expected_before"] == {"uid": 0, "gid": 0, "mode": "0755"}


def test_share_create_never_changes_permissions(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    c.get("/shares/Photos/edit")
    assert not [x for x in env.helper.calls if x[0] == "perm_apply"]


def test_edit_page_shows_planned_changes(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    env.helper.perm_state[str(env.volume / "Photos")] = {
        "path": str(env.volume / "Photos"),
        "applicable": True,
        "changes": ["mode: 0755 -> 2775 (group read/write + setgid)"],
        "before": {"uid": 0, "gid": 0, "mode": "0755"},
    }
    page = c.get("/shares/Photos/edit").text
    assert "0755 -&gt; 2775" in page
    assert "fix permissions" in page


# --- folder browser over HTTP (requirements 4, 10, 11) ---------------------------------------


def test_browser_ops_and_audit(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    v = str(env.volume)
    assert (
        "err=" not in post(c, "/browse/mkdir", csrf, {"path": v, "name": "New"}).headers["location"]
    )
    assert (env.volume / "New").is_dir()
    r = post(c, "/browse/rename", csrf, {"path": f"{v}/New", "new_name": "Renamed"})
    assert "err=" not in r.headers["location"]
    r = post(c, "/browse/delete", csrf, {"path": f"{v}/Renamed", "confirm": "wrong"})
    assert "err=" in r.headers["location"] and (env.volume / "Renamed").exists()
    r = post(c, "/browse/delete", csrf, {"path": f"{v}/Renamed", "confirm": "Renamed"})
    assert "err=" not in r.headers["location"] and not (env.volume / "Renamed").exists()
    assert "file_deleted" in [e["event"] for e in events(capsys)]


def test_volume_root_delete_refused_over_http(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    v = str(env.volume)
    r = post(c, "/browse/delete", csrf, {"path": v, "confirm": env.volume.name, "recursive": "yes"})
    assert "err=" in r.headers["location"]
    assert env.volume.is_dir()


def test_shared_folder_delete_refused_over_http(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    r = post(
        c,
        "/browse/delete",
        csrf,
        {"path": str(env.volume / "Photos"), "confirm": "Photos", "recursive": "yes"},
    )
    assert "err=" in r.headers["location"]
    assert (env.volume / "Photos").is_dir()


def test_upload_over_http(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    (env.volume / "a.txt").write_text("orig")
    hdr = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    r = c.put(
        "/browse/upload",
        params={"dir": str(env.volume), "name": "a.txt"},
        content=b"new",
        headers=hdr,
    )
    assert r.status_code == 201 and r.json()["name"] == "a (1).txt"
    assert (env.volume / "a.txt").read_text() == "orig"


def test_upload_requires_csrf_header(env: Env) -> None:
    c = env.make_client()
    login(c)
    r = c.put(
        "/browse/upload",
        params={"dir": str(env.volume), "name": "x.txt"},
        content=b"x",
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 403
    assert not (env.volume / "x.txt").exists()


def test_upload_size_limit_over_http(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    hdr = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    big = b"x" * (env.settings.max_upload_bytes + 1)
    r = c.put(
        "/browse/upload", params={"dir": str(env.volume), "name": "big"}, content=big, headers=hdr
    )
    assert r.status_code == 413
    assert list(Path(env.volume).iterdir()) == []

    def gen():  # type: ignore[no-untyped-def]  # chunked: no Content-Length up front
        for _ in range(3):
            yield b"x" * (env.settings.max_upload_bytes // 2)

    r = c.put(
        "/browse/upload",
        params={"dir": str(env.volume), "name": "big2"},
        content=gen(),
        headers=hdr,
    )
    assert r.status_code == 413
    assert list(Path(env.volume).iterdir()) == []


def test_browse_outside_volume_refused(env: Env) -> None:
    c = env.make_client()
    login(c)
    r = c.get("/browse", params={"path": "/etc"})
    assert r.status_code == 400
    r = c.get("/browse/download", params={"path": "/etc/passwd"})
    assert r.status_code == 303 and "err=" in r.headers["location"]


def test_footer_shows_version(env: Env) -> None:
    c = env.make_client()
    assert "test" in c.get("/login").text and "2026-10-08" in c.get("/login").text
