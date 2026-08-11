"""Device ID (DID) format helpers: parse, normalize, virtual<->real.

This is *identity format* only — no generation, no check-digit synthesis, and
no claim that any DID will be accepted by a directory server. The wire UID
needs the *real* form (``PREFIX-serial-check``), so callers that hold a virtual
form (``G100000ZKMNP``) convert with :func:`virtual_to_real`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional

# CS2 virtual first-char -> real platform prefix. Protocol identity data,
# not a server list: the wire UID prefix is derived from this map.
PREFIX_MAP: Dict[str, str] = {
    "9": "AHCC",
    "B": "BHCC",
    "C": "CHCC",
    "F": "FHBB",
    "G": "GHBB",
    "H": "HHBB",
    "I": "IHBB",
    "J": "JHBB",
    "K": "KHBB",
    "T": "THBB",
    "X": "XHBB",
}
REAL_TO_VIRTUAL = {v: k for k, v in PREFIX_MAP.items()}
MYKJ_REAL_PREFIXES = frozenset(
    {"FHBB", "GHBB", "HHBB", "IHBB", "JHBB", "KHBB", "THBB", "XHBB"}
)

_REAL_DID = re.compile(r"^([A-Z0-9]{3,8})-(\d{1,8})-([A-Za-z0-9]{3,8})$")


@dataclass(frozen=True)
class Did:
    """Normalized device identity."""

    input: str
    virtual: str
    real: str
    network: str  # hekai | mykj | ppcs | rtos | unknown
    lib_ok: bool
    convertible: bool

    @property
    def is_mykj(self) -> bool:
        return self.network == "mykj"


@dataclass(frozen=True)
class LibDidParts:
    prefix: str
    serial: int  # atoi of middle segment (leading zeros dropped)
    check: str
    formatted: str


# --- canonical DID format gate (format + validity) -------------------------


def _u_in_range(value: int, base: int, width: int) -> bool:
    return ((value - base) & 0xFFFFFFFF) < width


def lib_did_format(device_id: Optional[str]) -> str:
    """Canonical format: uppercase, strip hyphens, reinsert at letter/digit edges."""
    if not device_id:
        return ""
    out = []
    letter_mode = True
    for ch in device_id[:64]:
        o = ord(ch)
        if _u_in_range(o, 0x30, 10):  # 0-9
            if letter_mode:
                out.append("-")
                letter_mode = False
            out.append(ch)
        elif _u_in_range(o, 0x61, 0x1A):  # a-z
            if not letter_mode:
                out.append("-")
                letter_mode = True
            out.append(chr(o - 0x20))
        elif _u_in_range(o, 0x41, 0x1A):  # A-Z
            if not letter_mode:
                out.append("-")
                letter_mode = True
            out.append(ch)
        elif o == 0x2D:  # '-'
            continue
        else:
            break
    return "".join(out)


def lib_check_valid_did(device_id: Optional[str]) -> bool:
    """Validity check: first char A-Z, only [A-Z0-9-], exactly 2 hyphens."""
    if not device_id:
        return False
    if not (0x41 <= ord(device_id[0]) <= 0x5A):
        return False
    hyphens = 0
    for ch in device_id[:64]:
        o = ord(ch)
        if o == 0x2D:
            hyphens += 1
        elif o == 0:
            break
        elif not _u_in_range(o, 0x41, 0x1A) and not _u_in_range(o, 0x30, 10):
            break
    return hyphens == 2


def lib_parse_did(device_id: Optional[str]) -> Optional[LibDidParts]:
    """Format + validate + split like the lib's connect path."""
    if not device_id:
        return None
    formatted = lib_did_format(device_id)
    if not lib_check_valid_did(formatted):
        return None
    parts = formatted.split("-")
    if len(parts) != 3:
        return None
    prefix, serial_s, check = parts
    if not serial_s or not serial_s.isdigit():
        return None
    return LibDidParts(prefix, int(serial_s), check, formatted)


def lib_accepts(device_id: Optional[str]) -> bool:
    return lib_parse_did(device_id) is not None


# --- CS2 virtual <-> real conversion ------------------------------------


def virtual_to_real(device_id: str) -> str:
    """``G100000ZKMNP`` -> ``GHBB-100000-ZKMNP``. Input uppercased."""
    s = device_id.strip().upper()
    if not s:
        return ""
    if s.startswith(("PPCS-", "RTOS-")):
        return s
    real_prefix = PREFIX_MAP.get(s[0], "")
    if not real_prefix:
        return ""
    if len(s) < 7:
        return s
    return f"{real_prefix}-{s[1:7]}-{s[7:]}"


def real_to_virtual(device_id: str) -> str:
    """``GHBB-100000-ZKMNP`` -> ``G100000ZKMNP``. Input uppercased."""
    s = device_id.strip().upper()
    if not s:
        return ""
    if s.startswith(("PPCS-", "RTOS-")):
        return s
    parts = s.split("-")
    if len(parts) != 3:
        return s
    virtual_prefix = REAL_TO_VIRTUAL.get(parts[0])
    if virtual_prefix is None:
        return s
    return f"{virtual_prefix}{parts[1]}{parts[2]}"


def to_real(device_id: str) -> str:
    """Normalize any CS2-style DID to real wire form (uppercased)."""
    s = device_id.strip().upper()
    if not s:
        return ""
    if s.startswith(("PPCS-", "RTOS-")):
        return s
    parts = s.split("-")
    if len(parts) == 3 and (parts[0] in REAL_TO_VIRTUAL or parts[0].startswith(("PPCS", "RTOS"))):
        return s
    return virtual_to_real(s)


# Public alias: the wire form the session/probe needs.
normalize_did = to_real


def network_for_real(real: str) -> str:
    if not real:
        return "unknown"
    if real.startswith("PPCS"):
        return "ppcs"
    if real.startswith("RTOS"):
        return "rtos"
    if any(real.startswith(p) for p in MYKJ_REAL_PREFIXES):
        return "mykj"
    if real.split("-", 1)[0] in {"AHCC", "BHCC", "CHCC"}:
        return "hekai"
    return "unknown"


def parse_did(device_id: str) -> Did:
    """Parse any CS2-style DID into a :class:`Did` (best-effort)."""
    s = device_id.strip().upper()
    real = to_real(s)
    virtual = real_to_virtual(real) if real else s
    return Did(
        input=device_id,
        virtual=virtual,
        real=real,
        network=network_for_real(real),
        lib_ok=lib_accepts(real),
        convertible=bool(real) and "-" in real,
    )


__all__ = [
    "PREFIX_MAP",
    "REAL_TO_VIRTUAL",
    "MYKJ_REAL_PREFIXES",
    "Did",
    "LibDidParts",
    "parse_did",
    "normalize_did",
    "virtual_to_real",
    "real_to_virtual",
    "to_real",
    "network_for_real",
    "lib_did_format",
    "lib_check_valid_did",
    "lib_parse_did",
    "lib_accepts",
]
