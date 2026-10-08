"""End-to-end API flows with a fake helper (requirements 3, 4, 9, 10, 11)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ORIGIN, Env, call, login

PW = "alice password 1"


def events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    return [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]


def mk_user(c: TestClient, csrf: str, name: str = "alice") -> None:
    r = call(
        c,
        "POST",
        "/api/users",
        csrf,
        json={"username": name, "password": PW, "display_name": name.title()},
    )
    assert r.status_code == 201, r.text


def mk_share(c: TestClient, csrf: str, env: Env, **kw: Any) -> Any:
    (env.volume / "Photos").mkdir(exist_ok=True)
    body = {
        "name": "Photos",
        "path": "/files/Photos",
        "comment": "",
        "all_users": None,
        "members": [{"username": "alice", "access": "rw"}],
    }
    body.update(kw)
    return call(c, "POST", "/api/shares", csrf, json=body)


# --- shares -----------------------------------------------------------------------------


def test_share_lifecycle_and_audit(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    r = mk_share(c, csrf, env)
    assert r.status_code == 201, r.text
    share = r.json()
    assert share["id"] == "Photos" and share["path"] == "/files/Photos"
    assert share["real_path"] == str(env.volume / "Photos")
    assert env.helper.shares[0].members == {"alice": "rw"}

    listing = c.get("/api/shares").json()
    assert [s["name"] for s in listing["shares"]] == ["Photos"]
    assert listing["status"]["running"] is True

    r = call(
        c,
        "PATCH",
        "/api/shares/Photos",
        csrf,
        json={"members": [{"username": "alice", "access": "ro"}], "comment": "Pics"},
    )
    assert r.status_code == 200, r.text
    assert env.helper.shares[0].members == {"alice": "ro"}
    assert env.helper.shares[0].comment == "Pics"

    entries = c.get("/api/files/list", params={"path": "/files"}).json()["entries"]
    assert next(e for e in entries if e["name"] == "Photos")["share"]["name"] == "Photos"

    assert call(c, "DELETE", "/api/shares/Photos", csrf).status_code == 200
    assert env.helper.shares == []
    assert (env.volume / "Photos").is_dir()
    kinds = [e["event"] for e in events(capsys)]
    for k in ("user_created", "share_created", "share_updated", "share_deleted"):
        assert k in kinds
    assert PW not in json.dumps(kinds)


def test_zero_member_share_refused(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    r = mk_share(c, csrf, env, members=[])
    assert r.status_code == 400 and "nobody can reach" in r.json()["detail"]
    assert env.helper.shares == []
    mk_share(c, csrf, env)
    r = call(c, "PATCH", "/api/shares/Photos", csrf, json={"members": [], "all_users": None})
    assert r.status_code == 400
    assert env.helper.shares[0].members == {"alice": "rw"}


def test_all_users_share(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    r = mk_share(c, csrf, env, members=[], all_users="ro")
    assert r.status_code == 201, r.text
    assert env.helper.shares[0].all_users == "ro"


@pytest.mark.parametrize(
    "body",
    [
        {"name": "x]\n[global"},
        {"name": "global"},
        {"path": "/files/../etc"},
        {"path": "/etc"},
        {"path": "/files/nope"},
        {"comment": "a\nb"},
        {"members": [{"username": "ghost", "access": "rw"}]},
        {"members": [{"username": "alice", "access": "admin"}]},
        {"all_users": "yes"},
        {"guest_ok": True},
    ],
)
def test_bad_share_input_refused(env: Env, body: dict[str, Any]) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    r = mk_share(c, csrf, env, **body)
    assert r.status_code in (400, 422), r.text
    assert env.helper.shares == []


def test_helper_failure_does_not_save_share(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    env.helper.fail_next = "apply_shares"
    assert mk_share(c, csrf, env).status_code == 502
    assert c.get("/api/shares").json()["shares"] == []


def test_exfat_flag_reported(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from ssm import fsinfo

    monkeypatch.setattr(fsinfo, "fs_type", lambda p, m=None: "exfat")
    monkeypatch.setattr(fsinfo, "lacks_unix_perms", lambda p, m=None: True)
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    listing = c.get("/api/files/list", params={"path": "/files"}).json()
    assert listing["fs_type"] == "exfat" and listing["no_unix_perms"] is True
    share = mk_share(c, csrf, env).json()
    assert share["no_unix_perms"] is True
    assert env.helper.shares[0].no_unix_perms is True


def test_config_and_status(env: Env) -> None:
    c = env.make_client()
    login(c)
    assert "content" in c.get("/api/shares/config").json()
    info = c.get("/api/info").json()
    assert info["version"] == "test" and info["server_name"] == "NAS"


# --- requirement 9: permissions -----------------------------------------------------------


def test_permissions_require_explicit_confirmation(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    plan = c.get("/api/shares/Photos/permissions").json()
    assert "changes" in plan and "before" in plan
    assert not [x for x in env.helper.calls if x[0] == "perm_apply"]
    r = call(
        c,
        "POST",
        "/api/shares/Photos/permissions",
        csrf,
        json={"fix_permissions": False, "before": plan["before"]},
    )
    assert r.status_code == 400
    assert not [x for x in env.helper.calls if x[0] == "perm_apply"]
    r = call(
        c,
        "POST",
        "/api/shares/Photos/permissions",
        csrf,
        json={"fix_permissions": True, "before": plan["before"]},
    )
    assert r.status_code == 200
    applied = [x for x in env.helper.calls if x[0] == "perm_apply"]
    assert applied[0][1]["expected_before"] == plan["before"]


# --- users --------------------------------------------------------------------------------


def test_user_validation(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    for body in (
        {"username": "bob", "password": "short", "display_name": ""},
        {"username": "Bob", "password": PW, "display_name": ""},
        {"username": "--help", "password": PW, "display_name": ""},
        {"username": "bob", "password": PW, "display_name": "a\nb"},
    ):
        assert call(c, "POST", "/api/users", csrf, json=body).status_code in (400, 422)
    assert env.helper.users == {}


def test_set_password_failure_rolls_back_user(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    env.helper.fail_next = "user_set_password"
    r = call(
        c, "POST", "/api/users", csrf, json={"username": "bob", "password": PW, "display_name": ""}
    )
    assert r.status_code == 502
    assert "bob" not in env.helper.users
    assert c.get("/api/users").json()["users"] == []


def test_update_user(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    r = call(
        c,
        "PATCH",
        "/api/users/alice",
        csrf,
        json={"display_name": "Alice B", "password": "new password 99"},
    )
    assert r.status_code == 200
    assert env.helper.users["alice"] == "new password 99"
    users = c.get("/api/users").json()["users"]
    assert users[0]["display_name"] == "Alice B"
    assert "new password 99" not in capsys.readouterr().out


def test_cannot_delete_sole_member(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    r = call(c, "DELETE", "/api/users/alice", csrf)
    assert r.status_code == 409 and "only member" in r.json()["detail"]
    assert "alice" in env.helper.users


def test_delete_user_removes_membership(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_user(c, csrf, "bob")
    mk_share(
        c,
        csrf,
        env,
        members=[{"username": "alice", "access": "rw"}, {"username": "bob", "access": "ro"}],
    )
    r = call(c, "DELETE", "/api/users/bob", csrf)
    assert r.status_code == 200 and r.json()["removed_from_shares"] == ["Photos"]
    assert env.helper.shares[0].members == {"alice": "rw"}
    assert "bob" not in env.helper.users


# --- files (requirements 4, 10, 11) -------------------------------------------------------


def test_volumes_and_list(env: Env) -> None:
    (env.volume / "a.txt").write_text("x")
    (env.volume / ".hidden").write_text("x")
    c = env.make_client()
    login(c)
    vols = c.get("/api/files/volumes").json()["volumes"]
    assert vols[0]["name"] == "files" and vols[0]["path"] == "/files"
    names = [
        e["name"] for e in c.get("/api/files/list", params={"path": "/files"}).json()["entries"]
    ]
    assert names == ["a.txt"]
    names = [
        e["name"]
        for e in c.get("/api/files/list", params={"path": "/files", "show_hidden": "true"}).json()[
            "entries"
        ]
    ]
    assert ".hidden" in names


@pytest.mark.parametrize("p", ["/etc", "/files/../files", "/", "files", "/files/a\nb"])
def test_paths_outside_refused(env: Env, p: str) -> None:
    c = env.make_client()
    login(c)
    assert c.get("/api/files/list", params={"path": p}).status_code in (400, 404)
    assert c.get("/api/files/download", params={"path": p}).status_code in (400, 404)


def test_file_ops_and_audit(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    c = env.make_client()
    csrf = login(c)
    assert (
        call(
            c, "POST", "/api/files/mkdir", csrf, json={"parent": "/files", "name": "New"}
        ).status_code
        == 200
    )
    assert (env.volume / "New").is_dir()
    r = call(
        c, "POST", "/api/files/rename", csrf, json={"path": "/files/New", "new_name": "Renamed"}
    )
    assert r.status_code == 200 and r.json()["path"] == "/files/Renamed"
    (env.volume / "Renamed" / "f.txt").write_text("F")
    (env.volume / "Dest").mkdir()
    r = call(
        c,
        "POST",
        "/api/files/copy",
        csrf,
        json={"sources": ["/files/Renamed/f.txt"], "destination": "/files/Dest"},
    )
    assert r.json()["failed"] == [] and (env.volume / "Dest" / "f.txt").read_text() == "F"
    r = call(
        c,
        "POST",
        "/api/files/copy",
        csrf,
        json={"sources": ["/files/Renamed/f.txt"], "destination": "/files/Dest"},
    )
    assert (env.volume / "Dest" / "f (1).txt").exists()
    r = call(
        c,
        "POST",
        "/api/files/move",
        csrf,
        json={"sources": ["/files/Renamed/f.txt"], "destination": "/files/Dest"},
    )
    assert r.json()["failed"][0]["error"].endswith("already exists in the destination")
    assert (env.volume / "Renamed" / "f.txt").exists()
    r = call(c, "POST", "/api/files/delete", csrf, json={"paths": ["/files/Renamed", "/files"]})
    assert r.json()["deleted"] == ["/files/Renamed"]
    assert len(r.json()["failed"]) == 1 and env.volume.is_dir()
    kinds = [e["event"] for e in events(capsys)]
    for k in ("folder_created", "file_renamed", "file_copied", "file_deleted"):
        assert k in kinds


def test_search(env: Env) -> None:
    (env.volume / "a" / "b").mkdir(parents=True)
    (env.volume / "a" / "b" / "Holiday.jpg").write_text("x")
    c = env.make_client()
    login(c)
    r = c.get("/api/files/search", params={"path": "/files", "q": "holi"}).json()
    assert [e["path"] for e in r["entries"]] == ["/files/a/b/Holiday.jpg"]
    assert c.get("/api/files/search", params={"path": "/files", "q": ""}).status_code == 400


def test_shared_folder_delete_and_move_refused(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    mk_user(c, csrf)
    mk_share(c, csrf, env)
    (env.volume / "Dest").mkdir()
    r = call(c, "POST", "/api/files/delete", csrf, json={"paths": ["/files/Photos"]})
    assert r.json()["deleted"] == []
    r = call(
        c,
        "POST",
        "/api/files/move",
        csrf,
        json={"sources": ["/files/Photos"], "destination": "/files/Dest"},
    )
    assert r.json()["moved"] == []
    assert (env.volume / "Photos").is_dir()


def test_upload(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    (env.volume / "a.txt").write_text("orig")
    r = call(
        c,
        "PUT",
        "/api/files/upload",
        csrf,
        params={"path": "/files", "name": "a.txt"},
        content=b"new",
    )
    assert r.status_code == 201 and r.json()["name"] == "a (1).txt"
    assert r.json()["path"] == "/files/a (1).txt"
    assert (env.volume / "a.txt").read_text() == "orig"


def test_upload_requires_csrf_header(env: Env) -> None:
    c = env.make_client()
    login(c)
    r = c.put(
        "/api/files/upload",
        params={"path": "/files", "name": "x.txt"},
        content=b"x",
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 403
    assert not (env.volume / "x.txt").exists()


def test_upload_size_limit(env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    big = b"x" * (env.settings.max_upload_bytes + 1)
    r = call(
        c, "PUT", "/api/files/upload", csrf, params={"path": "/files", "name": "big"}, content=big
    )
    assert r.status_code == 413
    assert list(env.volume.iterdir()) == []

    def gen():  # type: ignore[no-untyped-def]  # chunked: no Content-Length up front
        for _ in range(3):
            yield b"x" * (env.settings.max_upload_bytes // 2)

    r = call(
        c,
        "PUT",
        "/api/files/upload",
        csrf,
        params={"path": "/files", "name": "big2"},
        content=gen(),
    )
    assert r.status_code == 413
    assert list(env.volume.iterdir()) == []
