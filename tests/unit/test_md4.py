"""MD4 (RFC 1320) and the Samba NT hash built on it."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ssm.helper.md4 import md4, nt_hash

RFC1320 = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "043f8582f241db351ce627e153e7f0e4",
    ),
    (b"1234567890" * 8, "e33b4ddc9c38f2199c3e7b164fcc0536"),
]


@pytest.mark.parametrize(("data", "digest"), RFC1320)
def test_rfc1320_vectors(data: bytes, digest: str) -> None:
    assert md4(data).hex() == digest


def test_block_boundaries() -> None:
    # 55/56/63/64/65 bytes exercise every padding branch; all must be distinct.
    seen = {md4(b"x" * n) for n in (55, 56, 63, 64, 65, 119, 120)}
    assert len(seen) == 7


def test_nt_hash_known_values() -> None:
    # The NT hash of "password" (as stored by Samba, e.g. pdbedit -w).
    assert nt_hash("password") == "8846F7EAEE8FB117AD06BDD830B7586C"
    assert nt_hash("") == "31D6CFE0D16AE931B73C59D7E0C089C0"


def test_nt_hash_is_utf16le_not_utf8() -> None:
    assert nt_hash("é") == md4("é".encode("utf-16-le")).hex().upper()
    assert nt_hash("é") != md4("é".encode()).hex().upper()


@given(st.binary(max_size=300))
def test_md4_is_deterministic_and_16_bytes(data: bytes) -> None:
    assert md4(data) == md4(data)
    assert len(md4(data)) == 16
