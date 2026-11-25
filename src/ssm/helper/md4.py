"""MD4 (RFC 1320), used only to compute Samba NT hashes for password verification.

OpenSSL 3 (Debian trixie) no longer provides MD4 through hashlib, so it is implemented
here. MD4 is broken as a general hash; it is used only because the NT hash Samba stores
is MD4(UTF-16LE(password)) and we must compare against that. It never protects new data.
"""

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def md4(data: bytes) -> bytes:
    msg = bytes(data)
    bit_len = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg += b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off : off + 64])
        aa, bb, cc, dd = a, b, c, d

        def f(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (~x_ & z)

        def g(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (x_ & z) | (y & z)

        def h(x_: int, y: int, z: int) -> int:
            return x_ ^ y ^ z

        for i in (0, 4, 8, 12):
            a = _rotl(a + f(b, c, d) + x[i], 3)
            d = _rotl(d + f(a, b, c) + x[i + 1], 7)
            c = _rotl(c + f(d, a, b) + x[i + 2], 11)
            b = _rotl(b + f(c, d, a) + x[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _rotl(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = _rotl(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = _rotl(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = _rotl(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = _rotl(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = _rotl(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = _rotl(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = _rotl(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK
    return struct.pack("<4I", a, b, c, d)


def nt_hash(password: str) -> str:
    """Samba's NT hash: upper-case hex MD4 of the UTF-16LE password."""
    return md4(password.encode("utf-16-le")).hex().upper()
