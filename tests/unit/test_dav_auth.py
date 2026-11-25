"""WebDAV authentication: HTTPS-only Basic, the remote-access flag, throttling on the real
client IP, the credential cache, registry changes, audit lines and ntfy notifications."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tests.unit.dav_harness import CLIENT, PROPFIND_BODY, PW, Dav


@pytest.fixture
def dav(tmp_path: Path) -> Dav:
    return Dav(tmp_path)


def propfind(dav: Dav, path: str = "/", **kw: object) -> object:
    return dav.req("PROPFIND", path, body=PROPFIND_BODY, headers={"Depth": "1"}, **kw)  # type: ignore[arg-type]


def audit_lines(out: str) -> list[dict[str, object]]:
    return [json.loads(x) for x in out.splitlines() if x.startswith("{")]


# --- HTTPS -------------------------------------------------------------------------------


def test_plain_http_refused_before_reading_credentials(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/", proto=None, headers={"Depth": "0"})
    assert r.status == 403
    assert "www-authenticate" not in r.headers
    assert r.headers["content-type"].startswith("text/plain")
    assert dav.verifier.calls == []


def test_forwarded_proto_from_untrusted_peer_ignored(dav: Dav) -> None:
    # A LAN device talking to :8094 directly cannot claim HTTPS.
    r = dav.req("PROPFIND", "/", peer="192.168.68.20", headers={"Depth": "0"})
    assert r.status == 403
    assert dav.verifier.calls == []


def test_forwarded_proto_http_from_trusted_peer_refused(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/", proto="http", headers={"Depth": "0"})
    assert r.status == 403


def test_https_from_trusted_proxy_accepted(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/", headers={"Depth": "0"})
    assert r.status == 207


def test_default_trusts_no_proxy(tmp_path: Path) -> None:
    d = Dav(tmp_path, trusted_proxies=[])
    r = d.req("PROPFIND", "/", headers={"Depth": "0"})
    assert r.status == 403


# --- Basic credentials -------------------------------------------------------------------


def test_missing_credentials_401(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/", user=None, headers={"Depth": "0"})
    assert r.status == 401
    assert r.headers["www-authenticate"].startswith('Basic realm="')
    assert 'charset="UTF-8"' in r.headers["www-authenticate"]
    assert r.headers["content-type"].startswith("text/plain")


def test_wrong_password_generic_401(dav: Dav) -> None:
    bad = dav.req("PROPFIND", "/", password="wrong-password-xx", headers={"Depth": "0"})
    unknown = dav.req("PROPFIND", "/", user="zed", headers={"Depth": "0"})
    assert bad.status == unknown.status == 401
    assert bad.body == unknown.body


@pytest.mark.parametrize(
    "authz",
    [
        "Basic !!!notbase64",
        "Basic " + base64.b64encode(b"no-colon").decode(),
        "Basic " + base64.b64encode(b"alice:" + b"x" * 600).decode(),
        "Basic " + base64.b64encode(b"ali\nce:pw").decode(),
        "Basic " + base64.b64encode(b"alice:pw\x00").decode(),
        "Basic " + base64.b64encode(b"\xff\xfe:pw").decode(),
        "Digest username=alice",
        "Bearer abc",
    ],
)
def test_malformed_authorization_401_without_helper_call(dav: Dav, authz: str) -> None:
    r = dav.req("PROPFIND", "/", authorization=authz, headers={"Depth": "0"})
    assert r.status == 401
    assert dav.verifier.calls == []


def test_not_remote_user_refused_without_helper_call(dav: Dav) -> None:
    # carol has the right password but no remote-access flag.
    r = dav.req("PROPFIND", "/", user="carol", headers={"Depth": "0"})
    assert r.status == 401
    assert dav.verifier.calls == []


def test_helper_down_is_503_and_not_a_failure(dav: Dav) -> None:
    dav.verifier.down = True
    for _ in range(8):
        r = dav.req("PROPFIND", "/", headers={"Depth": "0"})
        assert r.status == 503
    dav.verifier.down = False
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207


# --- throttle ----------------------------------------------------------------------------


def _fail(dav: Dav, user: str = "alice", client: str = CLIENT) -> int:
    return dav.req(
        "PROPFIND",
        "/",
        user=user,
        password="wrong-password-x",
        client=client,
        headers={"Depth": "0"},
    ).status


def test_user_lockout_after_five_failures(dav: Dav) -> None:
    # Spread over many IPs so the per-IP throttle never triggers.
    for i in range(5):
        assert _fail(dav, client=f"198.51.100.{i + 1}") == 401
        dav.clock.advance(60)
    calls = len(dav.verifier.calls)
    assert _fail(dav, client="198.51.100.50") == 401
    # Locked: the correct password is refused and not even checked.
    r = dav.req("PROPFIND", "/", client="198.51.100.51", headers={"Depth": "0"})
    assert r.status == 401
    assert "retry-after" in r.headers
    assert len(dav.verifier.calls) == calls + 1  # the 6th attempt was checked, not the 7th
    dav.clock.advance(901)
    assert dav.req("PROPFIND", "/", client="198.51.100.52", headers={"Depth": "0"}).status == 207


def test_peer_backoff_from_first_failure(dav: Dav) -> None:
    assert _fail(dav, user="bob") == 401
    calls = len(dav.verifier.calls)
    # Same IP, another user, correct password: still backing off (1 s).
    r = dav.req("PROPFIND", "/", user="dave", headers={"Depth": "0"})
    assert r.status == 401
    assert len(dav.verifier.calls) == calls
    dav.clock.advance(1.1)
    assert dav.req("PROPFIND", "/", user="dave", headers={"Depth": "0"}).status == 207


def test_throttle_keys_on_real_client_ip_not_proxy(dav: Dav) -> None:
    # Attacker A hammers through the trusted proxy; family member B behind the same
    # proxy must not be locked out.
    for _ in range(3):
        _fail(dav, user="zed", client="198.51.100.66")
        dav.clock.advance(0.1)
    r = dav.req("PROPFIND", "/", user="bob", client="192.0.2.10", headers={"Depth": "0"})
    assert r.status == 207


def test_spoofed_forwarded_for_from_untrusted_peer_ignored(tmp_path: Path) -> None:
    d = Dav(tmp_path, allow_http=True, bind_addr="127.0.0.1")
    # An untrusted peer rotates X-Forwarded-For: it is still throttled as itself.
    d.req(
        "PROPFIND",
        "/",
        password="wrong-pw-1234",
        peer="192.168.68.20",
        client="1.1.1.1",
        proto=None,
        headers={"Depth": "0"},
    )
    calls = len(d.verifier.calls)
    r = d.req(
        "PROPFIND", "/", peer="192.168.68.20", client="2.2.2.2", proto=None, headers={"Depth": "0"}
    )
    assert r.status == 401
    assert len(d.verifier.calls) == calls


def test_prepended_fake_xff_entries_do_not_change_key(dav: Dav) -> None:
    _fail(dav, user="zed", client=f"9.9.9.9, {CLIENT}")
    calls = len(dav.verifier.calls)
    r = dav.req("PROPFIND", "/", client=f"8.8.8.8, {CLIENT}", headers={"Depth": "0"})
    assert r.status == 401  # same real client (right-most untrusted entry): backing off
    assert len(dav.verifier.calls) == calls


def test_trusted_proxy_without_client_header_refused(dav: Dav) -> None:
    r = dav.req("PROPFIND", "/", client=None, headers={"Depth": "0"})
    assert r.status == 400
    assert dav.verifier.calls == []


def test_cf_connecting_ip_only_when_configured_and_trusted(tmp_path: Path) -> None:
    d = Dav(tmp_path, real_ip_header="cf-connecting-ip")
    _ = d.req(
        "PROPFIND",
        "/",
        password="wrong-pw-1234",
        client=None,
        headers={"Depth": "0", "CF-Connecting-IP": "198.51.100.7"},
    )
    r = d.req(
        "PROPFIND",
        "/",
        user="bob",
        client=None,
        headers={"Depth": "0", "CF-Connecting-IP": "198.51.100.8"},
    )
    assert r.status == 207  # a different real client
    r = d.req(
        "PROPFIND",
        "/",
        user="dave",
        client=None,
        headers={"Depth": "0", "CF-Connecting-IP": "198.51.100.7"},
    )
    assert r.status == 401  # the failing one is backing off
    # Without the configured header from the trusted proxy: refused.
    assert d.req("PROPFIND", "/", client="198.51.100.9", headers={"Depth": "0"}).status == 400


def test_throttle_memory_bounded(dav: Dav) -> None:
    from ssm.dav.app import DavGuard

    guard = dav.app
    assert isinstance(guard, DavGuard)
    for i in range(5000):
        _fail(dav, user=f"u{i}", client=f"203.0.{(i >> 8) & 255}.{i & 255}")
    assert len(guard.auth.peer_throttle) <= 4096
    assert len(guard.auth.user_throttle) <= 4096


# --- cache and registry changes ----------------------------------------------------------


def test_cache_avoids_repeated_helper_calls(dav: Dav) -> None:
    for _ in range(20):
        assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    assert dav.verifier.calls == ["alice"]
    dav.clock.advance(301)
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    assert dav.verifier.calls == ["alice", "alice"]


def test_cached_credential_survives_lockout_by_attacker(dav: Dav) -> None:
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    for i in range(10):
        _fail(dav, client=f"198.51.100.{i + 1}")
        dav.clock.advance(1)
    # alice's own client (already verified) keeps working during the lockout.
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207


def test_password_change_invalidates_cache_immediately(dav: Dav) -> None:
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    dav.verifier.users["alice"] = "new-alice-password-1"
    dav.acl["users"]["alice"]["cred"] += 1
    dav.write_acl()
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 401
    r = dav.req(
        "PROPFIND",
        "/",
        password="new-alice-password-1",
        client="192.0.2.99",
        headers={"Depth": "0"},
    )
    assert r.status == 207


def test_user_removed_takes_effect_on_next_request(dav: Dav) -> None:
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    del dav.acl["users"]["alice"]
    for s in dav.acl["shares"]:
        s["members"].pop("alice", None)
    dav.write_acl()
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 401


def test_remote_flag_off_takes_effect_on_next_request(dav: Dav) -> None:
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 207
    dav.acl["users"]["alice"]["remote"] = False
    dav.write_acl()
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 401


def test_membership_change_takes_effect_on_next_request(dav: Dav) -> None:
    assert dav.req("PUT", "/Docs/a.txt", body=b"1").status == 201
    dav.share("Docs")["members"]["alice"] = "ro"
    dav.write_acl()
    assert dav.req("PUT", "/Docs/b.txt", body=b"1").status == 403
    del dav.share("Docs")["members"]["alice"]
    dav.write_acl()
    assert dav.req("GET", "/Docs/a.txt").status == 404


def test_missing_or_invalid_snapshot_refuses_everything(dav: Dav) -> None:
    (dav.bridge / "acl.json").write_text("{not json")
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 503
    (dav.bridge / "acl.json").unlink()
    assert dav.req("PROPFIND", "/", headers={"Depth": "0"}).status == 503


# --- audit -------------------------------------------------------------------------------


def test_audit_lines_never_contain_password(dav: Dav, capsys: pytest.CaptureFixture[str]) -> None:
    dav.req("PROPFIND", "/", headers={"Depth": "0"})
    dav.req(
        "PROPFIND",
        "/",
        user="bob",
        password="bad-guess-1234",
        headers={"Depth": "0"},
        client="192.0.2.1",
    )
    dav.req("PROPFIND", "/", user="carol", headers={"Depth": "0"}, client="192.0.2.2")
    dav.req("PROPFIND", "/", user="Evil Name", headers={"Depth": "0"}, client="192.0.2.3")
    out = capsys.readouterr().out
    for pw in PW.values():
        assert pw not in out
    assert "bad-guess-1234" not in out
    events = [e for e in audit_lines(out) if e["event"] == "dav_auth"]
    assert {"result": "ok", "user": "alice"}.items() <= events[0].items()
    assert events[0]["client"] == CLIENT
    assert any(e["result"] == "fail" and e.get("reason") == "bad_password" for e in events)
    assert any(e.get("reason") == "not_remote" for e in events)
    assert any(e["user"] == "<invalid>" for e in events)
    assert all("Evil" not in str(e) for e in events)


# --- ntfy --------------------------------------------------------------------------------


def test_ntfy_off_by_default(dav: Dav) -> None:
    for i in range(7):
        _fail(dav, client=f"198.51.100.{i + 1}")
        dav.clock.advance(30)
    assert dav.sent == []


def test_ntfy_once_when_lockout_starts_and_rate_limited(tmp_path: Path) -> None:
    d = Dav(tmp_path, ntfy_url="https://ntfy.example.org/family-nas")
    for i in range(12):
        _fail(d, client=f"198.51.100.{i + 1}")
        d.clock.advance(61)  # past each short backoff, so failures keep counting
    assert len(d.sent) == 1  # at most one per user per hour
    msg = d.sent[0]
    assert msg["url"] == "https://ntfy.example.org/family-nas"
    assert "alice" in msg["body"]
    assert "wrong-password" not in msg["body"]
    d.clock.advance(3601)
    for i in range(6):
        _fail(d, client=f"198.51.101.{i + 1}")
        d.clock.advance(60)
    assert len(d.sent) == 2


def test_ntfy_global_cap(tmp_path: Path) -> None:
    d = Dav(tmp_path, ntfy_url="https://ntfy.example.org/t")
    for u in range(15):
        d.verifier.users[f"user{u}"] = "x"
        d.acl["users"][f"user{u}"] = {"cred": 1, "remote": True}
    d.write_acl()
    for u in range(15):
        for i in range(6):
            _fail(d, user=f"user{u}", client=f"198.51.{u}.{i + 1}")
    assert len(d.sent) == 10


def test_ntfy_send_failure_is_harmless(tmp_path: Path) -> None:
    d = Dav(tmp_path, ntfy_url="https://ntfy.example.org/t")

    def boom(msg: dict[str, object]) -> None:
        raise OSError("network down")

    d.app.auth.notifier.sender = boom  # type: ignore[attr-defined]
    for i in range(7):
        assert _fail(d, client=f"198.51.100.{i + 1}") == 401


def test_sprayed_unknown_names_cannot_evict_a_real_lockout(dav: Dav) -> None:
    """Unknown names count against the client IP only, so a botnet spraying junk names
    can't push a real user's lockout out of the bounded per-user table."""
    for i in range(6):
        dav.req(
            "PROPFIND",
            "/",
            password="wrong-pw-1234",
            client=f"198.51.100.{i}",
            headers={"Depth": "0"},
        )
    assert dav.app.auth.user_throttle.retry_after("alice", dav.clock()) > 0
    for i in range(50):
        r = dav.req(
            "PROPFIND",
            "/",
            user=f"junk{i}",
            password="x" * 12,
            client=f"203.0.113.{i}",
            headers={"Depth": "0"},
        )
        assert r.status == 401
    assert set(dav.app.auth.user_throttle._entries) == {"alice"}
    assert dav.app.auth.user_throttle.retry_after("alice", dav.clock()) > 0
