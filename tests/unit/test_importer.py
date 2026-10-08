"""One-time import from an old smb.conf (read-only parse; admin confirms each item)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ssm import importer
from tests.conftest import ORIGIN, Env, call, login

CASA_MAIN = """\
[global]
   workgroup = WORKGROUP
   server string = %h server (Samba, Ubuntu)
   map to guest = bad user
   usershare allow guests = yes
include=/etc/samba/smb.casa.conf
include = /etc/../etc/passwd
include = /root/evil.conf

[printers]
   comment = All Printers
   path = /var/spool/samba

[homes]
   comment = Home Directories
"""

CASA_SHARES = """\
[Files]
comment = CasaOS share Files
public = Yes
path = {vol}
browseable = Yes
read only = No
guest ok = Yes
create mask = 0777
directory mask = 0777
force user = root

[Isherveer]
comment = CasaOS share Isherveer
path = {vol}/Isherveer
valid users = isherveer
write list = isherveer
read only = yes

[Jagdev]
path = {vol}/Jagdev
valid users = jagdev, @family isherveer
read list = isherveer
writeable = yes

[Bad]Name]
path = {vol}

[Sandip]
path = /DATA/Sandip
valid users = sandip
writable = yes

[Weird]
path = {vol}/Weird
comment = 100% \\
  continued
valid users = jagdev
"""


@pytest.fixture
def imp(env: Env) -> Path:
    vol = env.volume
    for d in ("Isherveer", "Jagdev", "Weird"):
        (vol / d).mkdir()
    etc = Path(env.settings.import_dir) / "etc-samba"
    etc.mkdir(parents=True)
    (etc / "smb.conf").write_text(CASA_MAIN)
    (etc / "smb.casa.conf").write_text(CASA_SHARES.format(vol=vol))
    return etc


def by_name(shares: list[importer.ImportedShare]) -> dict[str, importer.ImportedShare]:
    return {s.name: s for s in shares}


def test_parse_follows_include_only_inside_import(imp: Path, env: Env) -> None:
    shares = importer.parse_import(env.settings.import_dir, env.settings.volumes)
    names = set(by_name(shares))
    assert names == {"Files", "Isherveer", "Jagdev", "Bad]Name", "Sandip", "Weird"}
    assert "printers" not in names and "homes" not in names


def test_guest_share_flagged_was_anonymous(imp: Path, env: Env) -> None:
    s = by_name(importer.parse_import(env.settings.import_dir, env.settings.volumes))["Files"]
    assert s.was_anonymous
    assert s.all_users == "rw"
    assert s.members == {}


def test_member_mapping(imp: Path, env: Env) -> None:
    shares = by_name(importer.parse_import(env.settings.import_dir, env.settings.volumes))
    assert shares["Isherveer"].members == {"isherveer": "rw"}
    assert shares["Isherveer"].all_users is None
    j = shares["Jagdev"]
    assert j.members == {"jagdev": "rw", "isherveer": "ro"}
    assert any("@family" in p for p in j.notes)


def test_problems_block_import(imp: Path, env: Env) -> None:
    shares = by_name(importer.parse_import(env.settings.import_dir, env.settings.volumes))
    assert shares["Bad]Name"].problems
    assert any("volume" in p for p in shares["Sandip"].problems)
    assert shares["Weird"].problems  # % in comment is refused, not escaped
    assert not shares["Isherveer"].problems


def test_parse_never_writes(imp: Path, env: Env) -> None:
    before = {p: p.read_bytes() for p in imp.iterdir()}
    mtimes = {p: p.stat().st_mtime_ns for p in imp.iterdir()}
    importer.parse_import(env.settings.import_dir, env.settings.volumes)
    assert {p: p.read_bytes() for p in imp.iterdir()} == before
    assert {p: p.stat().st_mtime_ns for p in imp.iterdir()} == mtimes


def test_missing_import_dir_is_empty(env: Env) -> None:
    assert importer.parse_import(str(env.tmp / "nope"), env.settings.volumes) == []


# --- routes -----------------------------------------------------------------------------


def test_import_page_and_banner(imp: Path, env: Env) -> None:
    env.helper.import_users = ["isherveer", "jagdev", "root"]
    c = env.make_client()
    login(c)
    data = c.get("/api/import").json()
    assert data["mounted"] is True
    names = {s["name"]: s for s in data["shares"]}
    assert names["Files"]["was_anonymous"] is True
    assert names["Isherveer"]["problems"] == []
    assert [u["username"] for u in data["users"]] == ["isherveer", "jagdev", "root"]
    assert c.get("/api/info").json()["import_mounted"] is True


def test_import_users_then_share(imp: Path, env: Env) -> None:
    env.helper.import_users = ["isherveer", "jagdev"]
    c = env.make_client()
    csrf = login(c)
    assert call(c, "POST", "/api/import/user", csrf, json={"username": "isherveer"}).status_code == 200
    assert "isherveer" in env.helper.users
    r = call(c, "POST", "/api/import/share", csrf, json={"name": "Isherveer"})
    assert r.status_code == 200, r.text
    assert [s.name for s in env.helper.shares] == ["Isherveer"]


def test_import_user_not_in_scan_refused(imp: Path, env: Env) -> None:
    env.helper.import_users = ["isherveer"]
    c = env.make_client()
    csrf = login(c)
    assert call(c, "POST", "/api/import/user", csrf, json={"username": "mallory"}).status_code == 400
    assert "mallory" not in env.helper.users


def test_import_anonymous_share_needs_ack(imp: Path, env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    assert call(c, "POST", "/api/import/share", csrf, json={"name": "Files"}).status_code == 400
    assert env.helper.shares == []
    r = call(c, "POST", "/api/import/share", csrf, json={"name": "Files", "ack_anonymous": True})
    assert r.status_code == 200, r.text
    assert env.helper.shares[0].all_users == "rw"


def test_import_share_with_problems_refused(imp: Path, env: Env) -> None:
    c = env.make_client()
    csrf = login(c)
    for name in ("Bad]Name", "Weird", "Sandip"):
        assert call(c, "POST", "/api/import/share", csrf, json={"name": name}).status_code == 400
    assert env.helper.shares == []


def test_import_share_path_override(imp: Path, env: Env) -> None:
    env.helper.import_users = ["sandip"]
    (env.volume / "Sandip").mkdir()
    c = env.make_client()
    csrf = login(c)
    call(c, "POST", "/api/import/user", csrf, json={"username": "sandip"})
    r = call(c, "POST", "/api/import/share", csrf, json={"name": "Sandip", "path": "/files/Sandip"})
    assert r.status_code == 200, r.text
    assert env.helper.shares[0].path == str(env.volume / "Sandip")


def test_import_audit(imp: Path, env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.helper.import_users = ["isherveer"]
    c = env.make_client()
    csrf = login(c)
    call(c, "POST", "/api/import/user", csrf, json={"username": "isherveer"})
    out = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    assert any(e["event"] == "user_imported" and e["user"] == "isherveer" for e in out)


def test_import_requires_csrf(imp: Path, env: Env) -> None:
    c = env.make_client()
    login(c)
    r = c.post("/api/import/user", json={"username": "x"}, headers={"Origin": ORIGIN})
    assert r.status_code == 403
