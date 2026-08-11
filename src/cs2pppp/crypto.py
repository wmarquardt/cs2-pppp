"""CS2 PPPP wire crypto helpers.

Two things live here:

1. **Session crypto** required by a live session: ``prop_enc`` / ``prop_dec``
   (the CS2 session table cipher) used for the encrypted
   ``MSG_REPORT_SESSION_RDY`` (0xF9) handshake, keyed by the universal,
   hardcoded ``SSD@cs2-network.`` key. This is a *protocol constant*, not a
   secret — it is the same in every CS2 app.

2. **Research helpers** for the weak PPPP transport obfuscation: the
   repeating-XOR model (``derive_key``/``xor_apply``/``recover_key``/
   ``crack_key``) and the stateful ``crc_enc``/``crc_dec`` keystream. These are
   **not** needed for the high-level Device API; they exist so researchers can
   analyse captures.

Nothing here touches the network — it transforms bytes only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ._tables import get_table

# PPPP framing magic — first *plaintext* byte of every transport packet.
PPPP_MAGIC = 0xF1

# --- session table cipher (session-ready handshake) ------------------------

# Universal hardcoded CS2 key for MSG_REPORT_SESSION_RDY. Same in every app;
# a protocol constant, not a per-user secret.
CS2_SESSION_KEY = b"SSD@cs2-network."

# The 256-byte S-box is NOT bundled. It is resolved at call time from a
# caller-supplied table (env CS2PPPP_PROP_TABLE or configure_tables()).


def prop_select4key(key: bytes) -> Tuple[int, int, int, int]:
    """Mash a key string into the 4 effective state bytes."""
    if not key:
        return 0, 0, 0, 0
    s = n = x = 0
    for b in key:
        s = (s + b) & 0xFF
        n = (n - b) & 0xFF
        x ^= b
    t = 0
    for b in key:
        t = (t + ((b * 0xAB) >> 9)) & 0xFF
    return s, n, t, x & 0xFF


def prop_enc(
    data: bytes, key: bytes = CS2_SESSION_KEY, *, table: Optional[bytes] = None
) -> bytes:
    """CS2 session table cipher (encrypt). An empty/NUL key is a memcpy.

    ``table`` is the 256-byte S-box; if omitted it is resolved from the
    caller-supplied table registry (env / :func:`configure_tables`).
    """
    if not key or not key[0:1] or key[0] == 0:
        return bytes(data)
    if not data:
        return b""
    t = table if table is not None else get_table("prop_table")
    k = prop_select4key(key)
    out = bytearray(len(data))
    out[0] = t[k[0]] ^ data[0]
    for i in range(1, len(data)):
        prev = out[i - 1]
        out[i] = t[(k[prev & 3] + prev) & 0xFF] ^ data[i]
    return bytes(out)


def prop_dec(
    data: bytes, key: bytes = CS2_SESSION_KEY, *, table: Optional[bytes] = None
) -> bytes:
    """Inverse of :func:`prop_enc`."""
    if not key or not key[0:1] or key[0] == 0:
        return bytes(data)
    if not data:
        return b""
    t = table if table is not None else get_table("prop_table")
    k = prop_select4key(key)
    out = bytearray(len(data))
    out[0] = t[k[0]] ^ data[0]
    for i in range(1, len(data)):
        prev = data[i - 1]
        out[i] = t[(k[prev & 3] + prev) & 0xFF] ^ data[i]
    return bytes(out)


# --- weak transport XOR model (research) ------------------------------------


@dataclass(frozen=True)
class PpppKey:
    """The 4 effective XOR key bytes of a PPPP session."""

    k1: int
    k2: int
    k3: int
    k4: int

    def __post_init__(self) -> None:
        for name in ("k1", "k2", "k3", "k4"):
            v = getattr(self, name)
            if not 0 <= v <= 0xFF:
                raise ValueError(f"{name}={v!r} out of byte range")

    @property
    def bytes4(self) -> bytes:
        return bytes((self.k1, self.k2, self.k3, self.k4))

    def relation_ok(self) -> bool:
        return self.k2 == ((-self.k1) & 0xFF) and (self.k4 & 1) == (self.k1 & 1)


def derive_key(init_bytes: bytes) -> PpppKey:
    """Compute the effective XOR key from init-string bytes."""
    if not init_bytes:
        raise ValueError("init_bytes is empty")
    total = sum(init_bytes)
    k1 = total & 0xFF
    k2 = (-total) & 0xFF
    k3 = sum(b // 3 for b in init_bytes) & 0xFF
    k4 = 0
    for b in init_bytes:
        k4 ^= b
    return PpppKey(k1, k2, k3, k4 & 0xFF)


def xor_apply(data: bytes, key: PpppKey, *, offset: int = 0) -> bytes:
    """Apply the repeating 4-byte XOR keystream (encrypt == decrypt)."""
    ks = key.bytes4
    return bytes(b ^ ks[(offset + i) & 3] for i, b in enumerate(data))


pppp_decrypt = xor_apply
pppp_encrypt = xor_apply


def is_encrypted(packet: bytes) -> bool:
    """Heuristic: a cleartext PPPP packet starts with 0xF1; encrypted does not."""
    return bool(packet) and packet[0] != PPPP_MAGIC


def recover_key(
    ciphertext: bytes, known_plaintext: bytes = bytes([PPPP_MAGIC])
) -> PpppKey:
    """Recover the XOR key from known plaintext at the start of ``ciphertext``."""
    if not ciphertext:
        raise ValueError("empty ciphertext")
    if not known_plaintext or known_plaintext[0] != PPPP_MAGIC:
        raise ValueError("known_plaintext must start with the 0xF1 magic byte")
    n = min(len(known_plaintext), len(ciphertext), 4)
    kb = [None, None, None, None]  # type: list[Optional[int]]
    for i in range(n):
        kb[i] = ciphertext[i] ^ known_plaintext[i]
    k1 = kb[0]
    assert k1 is not None
    if kb[1] is None:
        kb[1] = (-k1) & 0xFF
    if kb[2] is None or kb[3] is None:
        raise ValueError("need >=4 known plaintext bytes to fix k3/k4; use crack_key()")
    return PpppKey(k1, kb[1], kb[2], kb[3])


def crack_key(
    ciphertext: bytes,
    *,
    validate: Optional[Callable[[bytes], bool]] = None,
) -> Optional[PpppKey]:
    """Recover the XOR key from an encrypted packet using only the 0xF1 magic."""
    if not ciphertext:
        return None
    k1 = ciphertext[0] ^ PPPP_MAGIC
    k2 = (-k1) & 0xFF

    def default_validate(pt: bytes) -> bool:
        if len(pt) < 4 or pt[0] != PPPP_MAGIC:
            return False
        declared = (pt[2] << 8) | pt[3]
        return declared == len(pt) - 4

    check = validate or default_validate
    for k3 in range(256):
        for k4 in range(k1 & 1, 256, 2):
            key = PpppKey(k1, k2, k3, k4)
            if check(xor_apply(ciphertext, key)):
                return key
    return None


# --- CRC stream cipher (stateful keystream; research) -----------------------
#
# The 64-byte CRC table is NOT bundled; it is resolved from the caller-supplied
# table registry (env CS2PPPP_CRC_TABLE or configure_tables()).

_CRC_DEFAULT_SEED = (1, 3, 5, 7)  # keyless default (CS2/mykj use this)


def _crc_m(x: int, y: int) -> int:
    return x if y == 0 else x % y


def _crc_cell(table: bytes, col: int, row: int) -> int:
    return table[(col & 7) + (row & 7) * 8]


def _crc_evolve(
    table: bytes, a: int, b: int, c: int, d: int, o: int
) -> Tuple[int, int, int, int]:
    m = _crc_m
    return (
        _crc_cell(table, o + m(c, d), m(o, a) + b),
        _crc_cell(table, m(d, a) + o, m(o, b) + c),
        _crc_cell(table, m(a, b) + o, m(o, c) + d),
        _crc_cell(table, m(b, c) + o, m(o, d) + a),
    )


def _crc_init(key: Optional[bytes]) -> Tuple[int, int, int, int]:
    if not key or key[0] == 0:
        return _CRC_DEFAULT_SEED
    raise NotImplementedError(
        "keyed CRC seed unsupported (CS2/mykj uses the keyless default)"
    )


def crc_enc(data: bytes, key: Optional[bytes] = None, *, table: Optional[bytes] = None) -> bytes:
    """CS2 CRC stream cipher (encrypt) — ciphertext + 4-byte 0x43 trailer.

    ``table`` is the 64-byte CRC table; if omitted it is resolved from the
    caller-supplied table registry.
    """
    t = table if table is not None else get_table("crc_table")
    a, b, c, d = _crc_init(key)
    out = bytearray()
    for pt in data:
        o = a ^ b ^ c ^ d ^ pt
        out.append(o)
        a, b, c, d = _crc_evolve(t, a, b, c, d, o)
    for _ in range(4):
        o = a ^ b ^ c ^ d ^ 0x43
        out.append(o)
        a, b, c, d = _crc_evolve(t, a, b, c, d, o)
    return bytes(out)


def crc_dec(data: bytes, key: Optional[bytes] = None, *, table: Optional[bytes] = None) -> Optional[bytes]:
    """CS2 CRC stream cipher (decrypt) — plaintext, or None if the trailer fails."""
    if len(data) < 4:
        return None
    t = table if table is not None else get_table("crc_table")
    a, b, c, d = _crc_init(key)
    out = bytearray()
    for ct in data:
        out.append(a ^ b ^ c ^ d ^ ct)
        a, b, c, d = _crc_evolve(t, a, b, c, d, ct)
    if any(x != 0x43 for x in out[-4:]):
        return None
    return bytes(out[:-4])


__all__ = [
    "PPPP_MAGIC",
    "CS2_SESSION_KEY",
    "prop_select4key",
    "prop_enc",
    "prop_dec",
    "PpppKey",
    "derive_key",
    "xor_apply",
    "pppp_encrypt",
    "pppp_decrypt",
    "is_encrypted",
    "recover_key",
    "crack_key",
    "crc_enc",
    "crc_dec",
]
