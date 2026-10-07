"""Requirements 7, 8 and 9: the root helper's fixed operations, tested with fake Samba
binaries that record their argv and stdin."""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import textwrap
import threading
from pathlib import Path
from typing import Any

import pytest

from ssm.helper import extrausers, ops
from ssm.helper.ops import HelperConfig, HelperOpError, HelperOps
from ssm.helper.server import HelperServer
from ssm.helper_client import HelperClient, HelperError

BASE_CONF = textwrap.dedent(
    """\
    [global]
    \tworkgroup = WORKGROUP
    \tinclude = {globals}
    \tinclude = {shares}
    """
)

FAKE = r"""#!/usr/bin/env python3
import json, os, re, sys
d = os.environ["FAKE_DIR"]
name = os.path.basename(sys.argv[0])
data = sys.stdin.read() if name in ("smbpasswd",) else ""
with open(os.path.join(d, "calls.jsonl"), "a") as f:
    f.write(json.dumps({"bin": name, "argv": sys.argv[1:]}) + "\n")
if data:
    with open(os.path.join(d, "stdin.log"), "a") as f:
        f.write(data)
if os.path.exists(os.path.join(d, "fail_" + name)):
    sys.stderr.write(name + " failed\n")
    sys.exit(1)
if name == "testparm":
    def inline(path, out):
        for line in open(path):
            m = re.match(r"\s*include\s*=\s*(\S+)", line)
            if m:
                if os.path.exists(m.group(1)):
                    inline(m.group(1), out)
            else:
                out.append(line.rstrip("\n"))
    out = []
    inline(sys.argv[-1], out)
    print("\n".join(out))
elif name == "pdbedit":
    users = [u for u in open(os.path.join(d, "pdb_users")).read().split() if u]
    if "-Lw" in sys.argv or ("-L" in sys.argv and "-w" in sys.argv):
        for i, u in enumerate(users):
            lm, nt = "X" * 32, "8846F7EAEE8FB117AD06BDD830B7586C"
            print(f"{u}:{3000+i}:{lm}:{nt}:[U          ]:LCT-00000000:")
    elif "-L" in sys.argv:
        for i, u in enumerate(users):
            print(f"{u}:{3000+i}:")
elif name == "id":
    target = sys.argv[-1]
    system = open(os.path.join(d, "system_users")).read().split()
    sys.exit(0 if target in system else 1)
"""


@pytest.fixture
def fake(tmp_path: Path) -> dict[str, Any]:
    fake_dir = tmp_path / "fake"
    bin_dir = fake_dir / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("testparm", "smbcontrol", "smbpasswd", "pdbedit", "id"):
        p = bin_dir / name
        p.write_text(FAKE)
        p.chmod(0o755)
    (fake_dir / "pdb_users").write_text("")
    (fake_dir / "system_users").write_text("root daemon www-data ubuntu")
    os.environ["FAKE_DIR"] = str(fake_dir)

    vol = tmp_path / "files"
    (vol / "Photos").mkdir(parents=True)
    (vol / "Docs").mkdir()
    samba = tmp_path / "data" / "samba"
    samba.mkdir(parents=True)
    etc = tmp_path / "etc"
    etc.mkdir()
    base = etc / "smb.conf"
    base.write_text(BASE_CONF.format(globals=samba / "globals.conf", shares=samba / "shares.conf"))
    cfg = HelperConfig(
        base_conf=str(base),
        shares_conf=str(samba / "shares.conf"),
        globals_conf=str(samba / "globals.conf"),
        extrausers_dir=str(tmp_path / "data" / "extrausers"),
        volumes=[str(vol)],
        import_dir=str(tmp_path / "import"),
        bin_dir=str(bin_dir),
        tmp_dir=str(tmp_path / "tmp"),
        smb_gid=os.getgid(),  # tests cannot chgrp to an arbitrary gid without root
        uid_min=3000,
    )
    return {"cfg": cfg, "dir": fake_dir, "vol": vol, "base": base, "ops": HelperOps(cfg)}


def calls(fake: dict[str, Any]) -> list[dict[str, Any]]:
    p = fake["dir"] / "calls.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def share(fake: dict[str, Any], **kw: Any) -> dict[str, Any]:
    d = {
        "name": "Photos",
        "path": str(fake["vol"] / "Photos"),
        "comment": "",
        "members": {"alice": "rw"},
        "all_users": None,
        "no_unix_perms": False,
    }
    d.update(kw)
    return d


def add_alice(fake: dict[str, Any]) -> None:
    fake["ops"].user_add("alice")


# --- argv discipline (requirement 7) -----------------------------------------------------


POSITIONAL_BINS = {"smbpasswd", "id"}


def assert_double_dash(fake: dict[str, Any]) -> None:
    for c in calls(fake):
        if c["bin"] in POSITIONAL_BINS:
            assert "--" in c["argv"], c
            idx = c["argv"].index("--")
            assert len(c["argv"]) == idx + 2, c  # exactly one positional, after --


def test_user_lifecycle_argv_and_stdin(fake: dict[str, Any]) -> None:
    o = fake["ops"]
    o.user_add("alice")
    o.user_set_password("alice", "s3cret password")
    o.user_delete("alice")
    assert_double_dash(fake)
    for c in calls(fake):
        assert "s3cret password" not in " ".join(c["argv"])
    assert (fake["dir"] / "stdin.log").read_text() == "s3cret password\ns3cret password\n"


def test_user_add_writes_extrausers(fake: dict[str, Any]) -> None:
    o = fake["ops"]
    o.user_add("alice")
    o.user_add("bob")
    d = Path(fake["cfg"].extrausers_dir)
    passwd = (d / "passwd").read_text().splitlines()
    assert passwd[0] == f"alice:x:3000:{fake['cfg'].smb_gid}::/nonexistent:/usr/sbin/nologin"
    assert passwd[1].startswith("bob:x:3001:")
    shadow = (d / "shadow").read_text().splitlines()
    assert shadow[0].startswith("alice:!*:")
    group = (d / "group").read_text().splitlines()
    assert group == [f"smbusers:x:{fake['cfg'].smb_gid}:alice,bob"]
    assert stat.S_IMODE((d / "shadow").stat().st_mode) == 0o640
    assert stat.S_IMODE((d / "passwd").stat().st_mode) == 0o644


def test_uid_reuse_after_delete_is_not_lower_than_max(fake: dict[str, Any]) -> None:
    o = fake["ops"]
    for u in ("a1", "a2", "a3"):
        o.user_add(u)
    o.user_delete("a2")
    o.user_add("a4")
    users = extrausers.read_users(fake["cfg"].extrausers_dir)
    assert users["a4"] == 3003


def test_system_account_collision_refused(fake: dict[str, Any]) -> None:
    with pytest.raises(HelperOpError, match="system account"):
        fake["ops"].user_add("ubuntu")
    assert (
        not Path(fake["cfg"].extrausers_dir, "passwd").exists()
        or "ubuntu" not in Path(fake["cfg"].extrausers_dir, "passwd").read_text()
    )


@pytest.mark.parametrize("bad", ["root", "Alice", "-rf", "--help", "a b", "a\nb", "x" * 40])
def test_bad_usernames_refused_before_any_command(fake: dict[str, Any], bad: str) -> None:
    with pytest.raises(HelperOpError):
        fake["ops"].user_add(bad)
    assert calls(fake) == []


def test_duplicate_user_refused(fake: dict[str, Any]) -> None:
    add_alice(fake)
    with pytest.raises(HelperOpError):
        fake["ops"].user_add("alice")


def test_delete_refuses_non_smb_user(fake: dict[str, Any]) -> None:
    with pytest.raises(HelperOpError):
        fake["ops"].user_delete("ubuntu")
    assert all(c["bin"] != "smbpasswd" for c in calls(fake))


@pytest.mark.parametrize("pw", ["short", "x" * 9, "has\nnewline pw", "nul\x00 password"])
def test_bad_passwords_refused(fake: dict[str, Any], pw: str) -> None:
    add_alice(fake)
    with pytest.raises(HelperOpError):
        fake["ops"].user_set_password("alice", pw)
    assert not (fake["dir"] / "stdin.log").exists()


def test_set_password_unknown_user(fake: dict[str, Any]) -> None:
    with pytest.raises(HelperOpError):
        fake["ops"].user_set_password("ghost", "long enough pw")


# --- config writes (requirement 8) -------------------------------------------------------


def test_apply_writes_validated_config_and_reloads(fake: dict[str, Any]) -> None:
    add_alice(fake)
    before = fake["base"].read_bytes()
    fake["ops"].apply_shares([share(fake)])
    text = Path(fake["cfg"].shares_conf).read_text()
    assert "[Photos]" in text and "valid users = alice" in text
    bins = [c["bin"] for c in calls(fake)]
    assert bins.index("testparm") < bins.index("smbcontrol")
    reload = next(c for c in calls(fake) if c["bin"] == "smbcontrol")
    assert reload["argv"] == ["smbd", "reload-config"]
    assert fake["base"].read_bytes() == before


def test_testparm_runs_on_temp_copy_not_live_file(fake: dict[str, Any]) -> None:
    add_alice(fake)
    fake["ops"].apply_shares([share(fake)])
    tp = next(c for c in calls(fake) if c["bin"] == "testparm")
    assert tp["argv"][-1] != fake["cfg"].base_conf
    assert not Path(tp["argv"][-1]).exists()  # temp copy cleaned up


def test_testparm_failure_keeps_old_config(fake: dict[str, Any]) -> None:
    add_alice(fake)
    fake["ops"].apply_shares([share(fake)])
    good = Path(fake["cfg"].shares_conf).read_text()
    (fake["dir"] / "fail_testparm").touch()
    with pytest.raises(HelperOpError):
        fake["ops"].apply_shares([share(fake, name="Other")])
    assert Path(fake["cfg"].shares_conf).read_text() == good


def test_reload_failure_rolls_back(fake: dict[str, Any]) -> None:
    add_alice(fake)
    fake["ops"].apply_shares([share(fake)])
    good = Path(fake["cfg"].shares_conf).read_text()
    (fake["dir"] / "fail_smbcontrol").touch()
    with pytest.raises(HelperOpError):
        fake["ops"].apply_shares([share(fake, name="Other")])
    assert Path(fake["cfg"].shares_conf).read_text() == good


def test_first_config_rolled_back_on_reload_failure(fake: dict[str, Any]) -> None:
    add_alice(fake)
    assert not Path(fake["cfg"].shares_conf).exists()
    (fake["dir"] / "fail_smbcontrol").touch()
    with pytest.raises(HelperOpError):
        fake["ops"].apply_shares([share(fake)])
    assert not Path(fake["cfg"].shares_conf).exists()


def test_first_config_rolled_back_on_testparm_failure(fake: dict[str, Any]) -> None:
    add_alice(fake)
    (fake["dir"] / "fail_testparm").touch()
    with pytest.raises(HelperOpError):
        fake["ops"].apply_shares([share(fake)])
    assert not Path(fake["cfg"].shares_conf).exists()


def test_testparm_output_must_match_intended_shares(
    fake: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    add_alice(fake)
    real = ops.HelperOps._testparm

    def evil(self: HelperOps, conf: str) -> str:
        return real(self, conf) + "\n[Injected]\n\tpath = /\n"

    monkeypatch.setattr(ops.HelperOps, "_testparm", evil)
    with pytest.raises(HelperOpError, match="unexpected"):
        fake["ops"].apply_shares([share(fake)])
    assert not Path(fake["cfg"].shares_conf).exists()


def test_apply_revalidates_everything(fake: dict[str, Any]) -> None:
    add_alice(fake)
    outside = fake["vol"].parent / "outside"
    outside.mkdir()
    bad = [
        share(fake, name="x]\n[global"),
        share(fake, path=str(outside)),
        share(fake, path=str(fake["vol"] / "missing")),
        share(fake, members={"ghost": "rw"}),
        share(fake, members={}),
        share(fake, comment="a\nb"),
        {**share(fake), "extra": 1},
    ]
    for b in bad:
        with pytest.raises(HelperOpError):
            fake["ops"].apply_shares([b])
    assert calls(fake) == [c for c in calls(fake) if c["bin"] == "id"]


def test_helper_recomputes_fs_type(fake: dict[str, Any]) -> None:
    add_alice(fake)
    fake["ops"].apply_shares([share(fake, no_unix_perms=True)])
    text = Path(fake["cfg"].shares_conf).read_text()
    assert "streams_xattr" in text  # tmp dir is not exFAT; client value ignored


def test_unshare_closes_removed_and_changed_shares(fake: dict[str, Any]) -> None:
    add_alice(fake)
    fake["ops"].user_add("bob")
    o = fake["ops"]
    o.apply_shares([share(fake), share(fake, name="Docs", path=str(fake["vol"] / "Docs"))])
    (fake["dir"] / "calls.jsonl").unlink()
    o.apply_shares([share(fake, members={"bob": "rw"})])
    sc = [c["argv"] for c in calls(fake) if c["bin"] == "smbcontrol"]
    assert ["smbd", "close-share", "Docs"] in sc
    assert ["smbd", "close-denied-share", "Photos"] in sc


def test_globals_written(fake: dict[str, Any]) -> None:
    fake["ops"].write_globals(["192.168.68.0/24"], "NAS", False)
    text = Path(fake["cfg"].globals_conf).read_text()
    assert "hosts allow = 127.0.0.1 ::1 192.168.68.0/24" in text


# --- permissions (requirement 9) ---------------------------------------------------------


def test_perm_plan_is_read_only(fake: dict[str, Any]) -> None:
    p = fake["vol"] / "Photos"
    p.chmod(0o755)
    before = p.stat()
    plan = fake["ops"].perm_plan(str(p))
    after = p.stat()
    assert (before.st_mode, before.st_uid, before.st_gid) == (
        after.st_mode,
        after.st_uid,
        after.st_gid,
    )
    assert plan["before"]["mode"] == "0755"
    assert any("2775" in c for c in plan["changes"])


def test_perm_apply_not_recursive(fake: dict[str, Any]) -> None:
    p = fake["vol"] / "Photos"
    child = p / "child"
    child.mkdir()
    child.chmod(0o700)
    p.chmod(0o755)
    plan = fake["ops"].perm_plan(str(p))
    fake["ops"].perm_apply(str(p), plan["before"])
    assert stat.S_IMODE(p.stat().st_mode) == 0o2775
    assert stat.S_IMODE(child.stat().st_mode) == 0o700


def test_perm_apply_refuses_stale_plan(fake: dict[str, Any]) -> None:
    p = fake["vol"] / "Photos"
    p.chmod(0o755)
    plan = fake["ops"].perm_plan(str(p))
    p.chmod(0o700)
    with pytest.raises(HelperOpError, match="changed"):
        fake["ops"].perm_apply(str(p), plan["before"])
    assert stat.S_IMODE(p.stat().st_mode) == 0o700


def test_perm_refuses_outside_volume_and_symlink(fake: dict[str, Any]) -> None:
    outside = fake["vol"].parent / "outside"
    outside.mkdir()
    with pytest.raises(HelperOpError):
        fake["ops"].perm_plan(str(outside))
    (fake["vol"] / "link").symlink_to(outside)
    with pytest.raises(HelperOpError):
        fake["ops"].perm_plan(str(fake["vol"] / "link"))
    with pytest.raises(HelperOpError):
        fake["ops"].perm_apply(str(fake["vol"] / "link"), {"uid": 0, "gid": 0, "mode": "0755"})


# --- import ------------------------------------------------------------------------------


def _passdb(fake: dict[str, Any], users: str) -> None:
    priv = Path(fake["cfg"].import_dir) / "var-lib-samba" / "private"
    priv.mkdir(parents=True)
    (priv / "passdb.tdb").write_bytes(b"TDB file")
    (fake["dir"] / "pdb_users").write_text(users)


def test_import_scan_lists_valid_users_only(fake: dict[str, Any]) -> None:
    _passdb(fake, "isherveer jagdev Bad-User root")
    res = fake["ops"].import_scan()
    assert res["users"] == ["isherveer", "jagdev"]
    assert sorted(res["skipped"]) == ["Bad-User", "root"]
    pdb = next(c for c in calls(fake) if c["bin"] == "pdbedit")
    src = Path(fake["cfg"].import_dir) / "var-lib-samba" / "private" / "passdb.tdb"
    assert str(src) not in " ".join(pdb["argv"])  # works on a copy, never the original


def test_import_user_sets_nt_hash_without_returning_it(fake: dict[str, Any]) -> None:
    _passdb(fake, "isherveer")
    res = fake["ops"].import_user("isherveer")
    assert "8846" not in json.dumps(res)
    set_hash = [c for c in calls(fake) if c["bin"] == "pdbedit" and "--set-nt-hash" in c["argv"]]
    assert set_hash and "--user=isherveer" in set_hash[0]["argv"]
    assert "isherveer" in extrausers.read_users(fake["cfg"].extrausers_dir)


def test_import_user_not_in_passdb(fake: dict[str, Any]) -> None:
    _passdb(fake, "isherveer")
    with pytest.raises(HelperOpError):
        fake["ops"].import_user("mallory")


# --- socket server -----------------------------------------------------------------------


@pytest.fixture
def server(fake: dict[str, Any]) -> Any:
    sock_path = Path(tempfile.mkdtemp(dir="/tmp")) / "h.sock"  # AF_UNIX paths are short
    srv = HelperServer(fake["ops"], str(sock_path), allowed_uid=os.getuid(), sock_gid=os.getgid())
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield str(sock_path), srv
    srv.shutdown()


def test_socket_permissions(server: Any) -> None:
    path, _ = server
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o660


def test_client_roundtrip_and_errors(server: Any, fake: dict[str, Any]) -> None:
    path, _ = server
    c = HelperClient(path)
    c.user_add("alice")
    assert "alice" in extrausers.read_users(fake["cfg"].extrausers_dir)
    with pytest.raises(HelperError, match="username"):
        c.user_add("Bad")


@pytest.mark.parametrize(
    "payload",
    [
        b'{"op": "run", "args": {"cmd": "id"}}\n',
        b'{"op": "user_add", "args": {"name": "x", "extra": 1}}\n',
        b'{"op": "user_add", "args": []}\n',
        b'{"op": "__init__", "args": {}}\n',
        b"not json\n",
        b'["user_add"]\n',
    ],
)
def test_server_rejects_unknown_ops_and_bad_args(server: Any, payload: bytes) -> None:
    path, _ = server
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        reply = json.loads(s.recv(65536))
    assert reply["ok"] is False


def test_server_rejects_other_uids(fake: dict[str, Any]) -> None:
    sock_path = Path(tempfile.mkdtemp(dir="/tmp")) / "h2.sock"
    srv = HelperServer(
        fake["ops"], str(sock_path), allowed_uid=os.getuid() + 12345, sock_gid=os.getgid()
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with pytest.raises(HelperError, match="not allowed"):
            HelperClient(str(sock_path)).user_list()
    finally:
        srv.shutdown()


def test_server_never_logs_password(server: Any, capsys: pytest.CaptureFixture[str]) -> None:
    path, _ = server
    c = HelperClient(path)
    c.user_add("alice")
    c.user_set_password("alice", "very secret pw 1")
    out = capsys.readouterr()
    assert "very secret pw 1" not in out.out + out.err
    assert "user_set_password" in out.out
