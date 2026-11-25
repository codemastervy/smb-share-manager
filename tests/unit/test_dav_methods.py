"""WebDAV methods: PUT (streamed, atomic, size-limited), GET with Range, MKCOL, DELETE,
COPY/MOVE and the overwrite rule, class 2 locking and request limits."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

from ssm.dav import provider
from tests.unit.dav_harness import LOCK_BODY, Dav, dest


@pytest.fixture
def dav(tmp_path: Path) -> Dav:
    return Dav(tmp_path)


def docs(dav: Dav) -> list[str]:
    return sorted(p.name for p in (dav.vol / "Docs").iterdir())


# --- PUT / GET ---------------------------------------------------------------------------


def test_put_new_then_get(dav: Dav) -> None:
    r = dav.req("PUT", "/Docs/new.bin", body=b"\x00\x01payload")
    assert r.status == 201
    assert (dav.vol / "Docs" / "new.bin").read_bytes() == b"\x00\x01payload"
    g = dav.req("GET", "/Docs/new.bin")
    assert g.status == 200 and g.body == b"\x00\x01payload"
    assert docs(dav) == ["new.bin", "readme.txt"]  # no temp files left


def test_put_unicode_name(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/Résumé ✓.txt", body=b"cv").status == 201
    assert (dav.vol / "Docs" / "Résumé ✓.txt").read_bytes() == b"cv"


def test_put_replaces_existing_file_atomically(dav: Dav) -> None:
    p = dav.vol / "Docs" / "readme.txt"
    ino = p.stat().st_ino
    r = dav.req("PUT", "/Docs/readme.txt", body=b"edited in place")
    assert r.status == 204
    assert p.read_bytes() == b"edited in place"
    assert p.stat().st_ino != ino  # a new file renamed over the old one
    assert docs(dav) == ["readme.txt"]


def test_put_onto_folder_refused(dav: Dav) -> None:
    (dav.vol / "Docs" / "dir").mkdir()
    assert dav.req("PUT", "/Docs/dir", body=b"x").status == 405
    assert (dav.vol / "Docs" / "dir").is_dir()


def test_put_into_missing_folder_conflict(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/nope/x.txt", body=b"x").status == 409


def test_max_upload_content_length(dav: Dav) -> None:
    r = dav.req("PUT", "/Docs/big.bin", body=b"x" * (1024 * 1024 + 1))
    assert r.status == 413
    assert docs(dav) == ["readme.txt"]


def test_max_upload_streamed_without_length(dav: Dav) -> None:
    r = dav.req("PUT", "/Docs/big.bin", body=b"x" * (1024 * 1024 + 10), chunked=True)
    assert r.status == 413
    assert docs(dav) == ["readme.txt"]  # temp file removed


def test_failed_replace_keeps_old_content(dav: Dav) -> None:
    r = dav.req("PUT", "/Docs/readme.txt", body=b"y" * (1024 * 1024 + 1), chunked=True)
    assert r.status == 413
    assert (dav.vol / "Docs" / "readme.txt").read_bytes() == b"hello docs\n"


def test_exactly_max_upload_allowed(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/max.bin", body=b"x" * (1024 * 1024)).status == 201


def test_non_put_body_limit(dav: Dav) -> None:
    r = dav.req(
        "PROPFIND", "/Docs", body=b"<a/>" + b" " * (1024 * 1024 + 1), headers={"Depth": "0"}
    )
    assert r.status == 413


def test_content_encoding_refused(dav: Dav) -> None:
    r = dav.req("PUT", "/Docs/x.gz", body=b"x", headers={"Content-Encoding": "gzip"})
    assert r.status in (415, 501)


def test_range_get(dav: Dav) -> None:
    r = dav.req("GET", "/Docs/readme.txt", headers={"Range": "bytes=6-9"})
    assert r.status == 206
    assert r.body == b"docs"
    assert r.headers["content-range"] == "bytes 6-9/11"


def test_head(dav: Dav) -> None:
    r = dav.req("HEAD", "/Docs/readme.txt")
    assert r.status == 200 and r.body == b""
    assert r.headers["content-length"] == "11"


def test_etag_changes_on_write(dav: Dav) -> None:
    a = dav.req("HEAD", "/Docs/readme.txt").headers["etag"]
    dav.req("PUT", "/Docs/readme.txt", body=b"changed")
    assert dav.req("HEAD", "/Docs/readme.txt").headers["etag"] != a


# --- MKCOL / DELETE -------------------------------------------------------------------


def test_mkcol(dav: Dav) -> None:
    assert dav.req("MKCOL", "/Docs/new").status == 201
    assert (dav.vol / "Docs" / "new").is_dir()
    assert dav.req("MKCOL", "/Docs/new").status == 405
    assert dav.req("MKCOL", "/Docs/a/b").status == 409


def test_delete_file_and_tree(dav: Dav) -> None:
    (dav.vol / "Docs" / "t" / "u").mkdir(parents=True)
    (dav.vol / "Docs" / "t" / "u" / "f.txt").write_bytes(b"f")
    assert dav.req("DELETE", "/Docs/readme.txt").status == 204
    assert dav.req("DELETE", "/Docs/t").status == 204
    assert docs(dav) == []


def test_delete_does_not_follow_links_inside_tree(dav: Dav) -> None:
    (dav.vol / "Docs" / "t").mkdir()
    os.symlink(dav.vol / "Secret", dav.vol / "Docs" / "t" / "link")
    dav.req("DELETE", "/Docs/t")
    assert (dav.vol / "Secret" / "plans.txt").exists()


# --- COPY / MOVE and the overwrite rule -------------------------------------------------


def mv(dav: Dav, src: str, dst: str, overwrite: str | None = None, method: str = "MOVE") -> int:
    h = {"Destination": dest(dst)}
    if overwrite is not None:
        h["Overwrite"] = overwrite
    return dav.req(method, src, headers=h).status


def test_move_rename(dav: Dav) -> None:
    assert mv(dav, "/Docs/readme.txt", "/Docs/renamed.txt") == 201
    assert docs(dav) == ["renamed.txt"]


def test_copy_file_and_folder(dav: Dav) -> None:
    (dav.vol / "Docs" / "d").mkdir()
    (dav.vol / "Docs" / "d" / "f.txt").write_bytes(b"f")
    assert mv(dav, "/Docs/readme.txt", "/Docs/copy.txt", method="COPY") == 201
    assert mv(dav, "/Docs/d", "/Docs/d2", method="COPY") == 201
    assert (dav.vol / "Docs" / "d2" / "f.txt").read_bytes() == b"f"
    assert (dav.vol / "Docs" / "copy.txt").read_bytes() == b"hello docs\n"
    assert not [n for n in docs(dav) if n.startswith(".ssm-")]


def test_missing_overwrite_header_means_f(dav: Dav) -> None:
    (dav.vol / "Docs" / "other.txt").write_bytes(b"keep me")
    assert mv(dav, "/Docs/readme.txt", "/Docs/other.txt") == 412
    assert mv(dav, "/Docs/readme.txt", "/Docs/other.txt", method="COPY") == 412
    assert (dav.vol / "Docs" / "other.txt").read_bytes() == b"keep me"
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_overwrite_f_never_replaces(dav: Dav) -> None:
    (dav.vol / "Docs" / "other.txt").write_bytes(b"keep me")
    assert mv(dav, "/Docs/readme.txt", "/Docs/other.txt", "F") == 412
    assert (dav.vol / "Docs" / "other.txt").read_bytes() == b"keep me"


def test_overwrite_t_file_onto_file(dav: Dav) -> None:
    # The "save to temp, then MOVE over the original" pattern of editors.
    (dav.vol / "Docs" / ".tmp-save").write_bytes(b"new version")
    assert mv(dav, "/Docs/.tmp-save", "/Docs/readme.txt", "T") == 204
    assert (dav.vol / "Docs" / "readme.txt").read_bytes() == b"new version"
    assert not (dav.vol / "Docs" / ".tmp-save").exists()
    (dav.vol / "Docs" / "src.txt").write_bytes(b"copy src")
    assert mv(dav, "/Docs/src.txt", "/Docs/readme.txt", "T", method="COPY") == 204
    assert (dav.vol / "Docs" / "readme.txt").read_bytes() == b"copy src"
    assert (dav.vol / "Docs" / "src.txt").exists()


def test_overwrite_t_never_replaces_a_folder(dav: Dav) -> None:
    (dav.vol / "Docs" / "dir").mkdir()
    (dav.vol / "Docs" / "dir" / "precious.txt").write_bytes(b"precious")
    assert mv(dav, "/Docs/readme.txt", "/Docs/dir", "T") == 403
    assert mv(dav, "/Docs/readme.txt", "/Docs/dir", "T", method="COPY") == 403
    assert (dav.vol / "Docs" / "dir" / "precious.txt").read_bytes() == b"precious"


def test_overwrite_t_folder_never_replaces_anything(dav: Dav) -> None:
    (dav.vol / "Docs" / "a").mkdir()
    (dav.vol / "Docs" / "b").mkdir()
    (dav.vol / "Docs" / "b" / "keep.txt").write_bytes(b"keep")
    assert mv(dav, "/Docs/a", "/Docs/b", "T") == 403
    assert mv(dav, "/Docs/a", "/Docs/readme.txt", "T") == 403
    assert mv(dav, "/Docs/a", "/Docs/b", "T", method="COPY") == 403
    assert (dav.vol / "Docs" / "b" / "keep.txt").exists()
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_invalid_overwrite_header(dav: Dav) -> None:
    assert mv(dav, "/Docs/readme.txt", "/Docs/x.txt", "yes") == 400


def test_move_onto_or_into_itself_refused(dav: Dav) -> None:
    (dav.vol / "Docs" / "a").mkdir()
    assert mv(dav, "/Docs/a", "/Docs/a", "T") == 403
    assert mv(dav, "/Docs/a", "/Docs/a/inside", "T") == 403
    assert mv(dav, "/Docs/readme.txt", "/Docs/readme.txt", "T") == 403
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_move_across_shares_requires_rw_on_both(dav: Dav) -> None:
    # bob: Docs ro, Photos rw.
    r = dav.req(
        "MOVE", "/Docs/readme.txt", user="bob", headers={"Destination": dest("/Photos/readme.txt")}
    )
    assert r.status == 403
    r = dav.req(
        "COPY", "/Docs/readme.txt", user="bob", headers={"Destination": dest("/Photos/readme.txt")}
    )
    assert r.status in (201, 204)
    assert (dav.vol / "Docs" / "readme.txt").exists()


def test_cross_device_move_copies_before_deleting(
    dav: Dav, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ssm.dav import provider

    monkeypatch.setattr(provider, "FORCE_CROSS_DEVICE", True)
    (dav.vol / "Docs" / "d").mkdir()
    (dav.vol / "Docs" / "d" / "f.txt").write_bytes(b"f")
    assert mv(dav, "/Docs/d", "/Docs/e") == 201
    assert (dav.vol / "Docs" / "e" / "f.txt").read_bytes() == b"f"
    assert not (dav.vol / "Docs" / "d").exists()
    calls: list[str] = []
    real_copy = provider._copy_file

    def failing_copy(*a: object, **kw: object) -> None:
        calls.append("x")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(provider, "_copy_file", failing_copy)
    assert mv(dav, "/Docs/readme.txt", "/Docs/moved.txt") >= 400
    assert (dav.vol / "Docs" / "readme.txt").read_bytes() == b"hello docs\n"  # source kept
    assert not [n for n in docs(dav) if n.startswith(".ssm-")]
    assert calls and real_copy is not None


# --- locking ---------------------------------------------------------------------------


def lock(dav: Dav, path: str, user: str = "alice", timeout: str = "Second-60") -> object:
    return dav.req(
        "LOCK", path, user=user, body=LOCK_BODY, headers={"Timeout": timeout, "Depth": "0"}
    )


def token(r: object) -> str:
    return r.headers["lock-token"].strip("<>")  # type: ignore[attr-defined]


def test_options_advertises_class_2(dav: Dav) -> None:
    r = dav.req("OPTIONS", "/Docs/")
    assert r.status == 200
    assert "2" in [x.strip() for x in r.headers["dav"].split(",")]


def test_lock_blocks_other_users_and_owner_unlocks(dav: Dav) -> None:
    r = lock(dav, "/Docs/readme.txt")
    assert r.status == 200  # type: ignore[attr-defined]
    t = token(r)
    # carol is rw on Docs but has no remote access; use another rw member: give bob rw.
    dav.share("Docs")["members"]["bob"] = "rw"
    dav.write_acl()
    assert dav.req("PUT", "/Docs/readme.txt", user="bob", body=b"x").status == 423
    assert dav.req("DELETE", "/Docs/readme.txt", user="bob").status == 423
    # Without the token even the owner can't write.
    assert dav.req("PUT", "/Docs/readme.txt", body=b"x").status == 423
    ok = dav.req("PUT", "/Docs/readme.txt", body=b"mine", headers={"If": f"(<{t}>)"})
    assert ok.status == 204
    # Only the owner can unlock.
    assert dav.req(
        "UNLOCK", "/Docs/readme.txt", user="bob", headers={"Lock-Token": f"<{t}>"}
    ).status in (403, 409)
    assert dav.req("UNLOCK", "/Docs/readme.txt", headers={"Lock-Token": f"<{t}>"}).status == 204
    assert dav.req("PUT", "/Docs/readme.txt", user="bob", body=b"bob").status == 204


def test_lock_null_creates_empty_file(dav: Dav) -> None:
    r = lock(dav, "/Docs/new-locked.txt")
    assert r.status in (200, 201)  # type: ignore[attr-defined]
    assert (dav.vol / "Docs" / "new-locked.txt").read_bytes() == b""


def test_lock_timeout_capped(dav: Dav) -> None:
    for t in ("Infinite", "Second-999999999"):
        r = lock(dav, "/Docs/readme.txt", timeout=t)
        assert r.status == 200  # type: ignore[attr-defined]
        found = re.findall(r"Second-(\d+)", r.text)  # type: ignore[attr-defined]
        assert found and all(int(x) <= 3600 for x in found)
        dav.req("UNLOCK", "/Docs/readme.txt", headers={"Lock-Token": f"<{token(r)}>"})


def test_lock_count_per_user_bounded(dav: Dav) -> None:
    from ssm.dav import provider

    for i in range(provider.MAX_LOCKS_PER_USER):
        assert lock(dav, f"/Docs/f{i}.txt").status in (200, 201)  # type: ignore[attr-defined]
    assert lock(dav, "/Docs/one-too-many.txt").status == 507  # type: ignore[attr-defined]


def test_locks_of_removed_user_are_released(dav: Dav) -> None:
    r = lock(dav, "/Docs/readme.txt")
    assert r.status == 200  # type: ignore[attr-defined]
    del dav.acl["users"]["alice"]
    del dav.share("Docs")["members"]["alice"]
    dav.share("Docs")["members"]["bob"] = "rw"
    dav.write_acl()
    assert dav.req("PUT", "/Docs/readme.txt", user="bob", body=b"bob").status == 204


def test_lock_token_does_not_grant_access(dav: Dav) -> None:
    r = lock(dav, "/Docs/readme.txt")
    t = token(r)
    # erin is not a member of Docs: the token alone gives her nothing.
    assert (
        dav.req(
            "PUT", "/Docs/readme.txt", user="erin", body=b"x", headers={"If": f"(<{t}>)"}
        ).status
        == 404
    )
    assert (
        dav.req("UNLOCK", "/Docs/readme.txt", user="erin", headers={"Lock-Token": f"<{t}>"}).status
        == 404
    )


def test_proppatch_dead_property_roundtrip(dav: Dav) -> None:
    body = (
        b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:z">'
        b"<D:set><D:prop><Z:color>blue</Z:color></D:prop></D:set></D:propertyupdate>"
    )
    r = dav.req(
        "PROPPATCH", "/Docs/readme.txt", body=body, headers={"Content-Type": "application/xml"}
    )
    assert r.status == 207
    assert b"200" in r.body


def test_server_body_limit_maps_to_413() -> None:
    """cheroot raises its own MaxSizeExceeded on chunked bodies; that must be a 413."""
    from cheroot.errors import MaxSizeExceeded
    from wsgidav.dav_error import DAVError

    from ssm.dav.app import _LimitedInput

    class Raising:
        def read(self, size: int = -1) -> bytes:
            raise MaxSizeExceeded

        readline = read

    inp = _LimitedInput(Raising(), 10)
    for fn in (inp.read, inp.readline):
        with pytest.raises(DAVError) as e:
            fn(5)
        assert e.value.value == 413


def _proppatch(dav: Dav, value: bytes, name: bytes = b"color") -> Any:
    body = (
        b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:z">'
        b"<D:set><D:prop><Z:" + name + b">" + value + b"</Z:" + name + b"></D:prop></D:set>"
        b"</D:propertyupdate>"
    )
    return dav.req(
        "PROPPATCH", "/Docs/readme.txt", body=body, headers={"Content-Type": "application/xml"}
    )


def test_dead_property_size_is_bounded(dav: Dav, monkeypatch: pytest.MonkeyPatch) -> None:
    # One oversized value is refused...
    r = _proppatch(dav, b"x" * (provider.MAX_DEAD_PROP_VALUE + 10))
    assert r.status == 207 and b"507" in r.body
    # ...and so is anything past the total budget.
    monkeypatch.setattr(provider, "MAX_DEAD_PROP_BYTES", 2000)
    assert b"200" in _proppatch(dav, b"y" * 900, b"a").body
    assert b"200" in _proppatch(dav, b"y" * 900, b"b").body
    r = _proppatch(dav, b"y" * 900, b"c")
    assert b"507" in r.body


def test_xml_body_limit(dav: Dav) -> None:
    r = _proppatch(dav, b"z" * (dav.settings.max_body_bytes + 1))
    assert r.status == 413
