"""Decode a user-supplied CS2/PPPP InitString into a directory server list.

The library ships **no** InitString presets and **no** directory IPs. This
module only knows the *algorithm*: given a blob the caller already possesses
(e.g. read from their own app configuration), turn it into a ``servers`` tuple.

Algorithm: nibble + 54-byte LUT XOR obfuscation. The decoded text is a
comma-separated host list ending in a trailing comma, i.e. ``ip1,ip2,ip3,``
(three directory servers).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from ._tables import get_table

# The 54-byte decode LUT is NOT bundled. It is resolved from the
# caller-supplied table registry (env CS2PPPP_LUT or configure_tables()).


@dataclass(frozen=True)
class DecodedInit:
    """Result of :func:`decode_init_string`."""

    servers: Tuple[str, ...]
    key: Optional[str]
    raw: str
    lib_ok: bool = True  # CheckIfValidInitString would accept it


def extract_init_string(blob: str) -> str:
    """Return the inner InitString value from a JSON wrapper or raw letters."""
    s = blob.strip()
    if s.startswith("{"):
        try:
            data = json.loads(s)
            val = data.get("InitString") or data.get("initString")
            if isinstance(val, str):
                return val
        except json.JSONDecodeError:
            pass
        m = re.search(r'"InitString"\s*:\s*"([A-Za-z:]+)"', s)
        if m:
            return m.group(1)
    return s


def check_if_valid_init_string(
    encoded: str,
    decoded: str,
    *,
    bufsize: int = 0x400,
) -> bool:
    """CS2 ``CheckIfValidInitString`` (True when the runtime would accept it).

    Rules: encoded length (before ``:key``) is even; decoded chars are only
    ``A-Z a-z 0-9 . - _ ,``; exactly 3 commas; last content char is ``,``.
    """
    enc = extract_init_string(encoded).strip()
    if ":" in enc:
        enc = enc.split(":", 1)[0]
    enc = enc.upper()
    if (len(enc) & 1) != 0 or bufsize == 0:
        return False

    buf = bytearray(bufsize)
    raw_bytes = decoded.encode("latin-1", errors="replace")
    buf[: min(len(raw_bytes), bufsize)] = raw_bytes[:bufsize]

    def u32(n: int) -> int:
        return n & 0xFFFFFFFF

    commas = 0
    i = 0
    end = bufsize
    while True:
        b = buf[i]
        if u32(b - 0x2D) > 1 and b != 0x5F:
            if b == 0x2C:  # ','
                commas += 1
            elif u32(b - 0x30) > 9 and u32((b & 0xDF) - 0x41) > 0x19:
                if i == 0 or b != 0:
                    return False
                end = i
                if commas != 3:
                    return False
                break
        i += 1
        if i == end:
            if bufsize != 0 and commas == 3:
                break
            return False

    return buf[end - 1] == ord(",")


def decode_init_string(encoded: str, lut: Optional[bytes] = None) -> DecodedInit:
    """Decode an obfuscated InitString to a ``servers`` tuple (+ optional key).

    ``encoded`` may be raw A-P letters, a ``letters:key`` form, or a JSON blob
    wrapping ``InitString``. ``lut`` is the 54-byte decode table; if
    omitted it is resolved from the caller-supplied table registry (env
    ``CS2PPPP_LUT`` or :func:`configure_tables`). Raises :class:`ValueError`
    on malformed input.
    """
    if lut is None:
        lut = get_table("lut")
    if len(lut) != 0x36:
        raise ValueError("LUT must be 54 bytes")

    raw = extract_init_string(encoded).strip()
    key: Optional[str] = None
    if ":" in raw:
        raw, key = raw.split(":", 1)

    raw = raw.upper()
    if len(raw) % 2 != 0:
        raise ValueError("InitString length must be even (A-P pairs)")

    out = bytearray()
    for i in range(len(raw) // 2):
        running = 0x39
        for j in range(i):
            running ^= out[j]
        raw_n = (ord(raw[2 * i + 1]) + (ord(raw[2 * i]) << 4) + 0xAF) & 0xFF
        out.append((lut[i % 0x36] ^ running ^ raw_n) & 0xFF)

    text = out.decode("ascii", errors="replace")
    parts = [p.strip() for p in text.split(",") if p.strip()]
    servers = tuple(parts)
    enc_for_check = extract_init_string(encoded).strip()
    lib_ok = check_if_valid_init_string(enc_for_check, text)
    return DecodedInit(servers=servers, key=key, raw=text, lib_ok=lib_ok)


__all__ = [
    "DecodedInit",
    "decode_init_string",
    "check_if_valid_init_string",
    "extract_init_string",
]
