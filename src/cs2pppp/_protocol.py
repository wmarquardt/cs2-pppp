"""CS2 PPPP wire-protocol constants and low-level packers.

Frame format for every directory/session packet::

    F1 | type(1) | length(u16 big-endian) | body

``length`` is the size of ``body`` only. See module functions for the
UID and sockaddr layouts, which have vendor-specific endianness quirks.
"""

from __future__ import annotations

import socket
import struct

# --- framing ---------------------------------------------------------------

MAGIC = 0xF1  # frame magic byte
DIR_PORT = 32100  # default directory / relay UDP port

# --- message types ---------------------------------------------------------

MSG_HELLO = 0x00
MSG_HELLO_ACK = 0x01
MSG_P2P_REQ = 0x20
MSG_P2P_REQ_ACK = 0x21
MSG_PUNCH_TO = 0x40
MSG_PUNCH_PKT = 0x41
MSG_P2P_RDY = 0x42
MSG_LIST_REQ1 = 0x67
MSG_LIST_REQ = 0x68
MSG_LIST_REQ_ACK = 0x69
MSG_RLY_HELLO = 0x70
MSG_RLY_PORT = 0x72
MSG_RLY_PORT_ACK = 0x73
MSG_RLY_REQ = 0x80
MSG_RLY_REQ_ACK = 0x81
MSG_RLY_TO = 0x82
MSG_RLY_PKT = 0x83
MSG_RLY_RDY = 0x84
MSG_DRW = 0xD0
MSG_DRW_ACK = 0xD1
MSG_ALIVE = 0xE0
MSG_ALIVE_ACK = 0xE1
MSG_CLOSE = 0xF0
MSG_REPORT_SESSION_RDY = 0xF9  # encrypted body (see crypto.CS2_SESSION_KEY)

DRW_MAGIC = 0xD1  # DRW sub-header magic byte
SESSION_RDY_BODY_LEN = 0x54  # 84 bytes, plaintext ReportSessionRdy body

# --- frame header ----------------------------------------------------------


def header(msg_type: int, body_len: int) -> bytes:
    """Build the 4-byte frame header ``F1 | type | u16_be body_len``."""
    return struct.pack(">BBH", MAGIC, msg_type, body_len)


# --- sockaddr_in (session dialect) -----------------------------------------
#
# CS2 directory sockaddr quirk: family big-endian, port little-endian,
# IPv4 octets reversed. 16 bytes total (8 meaningful + 8 pad).


def pack_sockaddr(ip: str, port: int) -> bytes:
    fam = struct.pack(">H", 2)
    p = struct.pack("<H", port & 0xFFFF)
    addr = socket.inet_aton(ip)[::-1]
    return fam + p + addr + b"\x00" * 8


def parse_sockaddr(body: bytes) -> "tuple[str, int]":
    if len(body) < 8:
        raise ValueError("sockaddr too short")
    port = struct.unpack("<H", body[2:4])[0]
    ip = socket.inet_ntoa(body[4:8][::-1])
    return ip, port


# --- UID (20-byte device identity on the wire) -----------------------------
#
# Layout: 8-byte ASCII prefix (null-padded) + u32_be serial + 8-byte
# ASCII check (null-padded). Input is the *real* DID "PREFIX-serial-check".


def pack_uid(real_did: str) -> bytes:
    parts = real_did.split("-")
    if len(parts) != 3:
        raise ValueError(f"real DID must be PREFIX-serial-check, got {real_did!r}")
    prefix, serial, check = parts
    prefix_b = prefix.encode("ascii")[:8].ljust(8, b"\x00")
    check_b = check.encode("ascii")[:8].ljust(8, b"\x00")
    return prefix_b + struct.pack(">I", int(serial)) + check_b


__all__ = [
    "MAGIC",
    "DIR_PORT",
    "DRW_MAGIC",
    "SESSION_RDY_BODY_LEN",
    "header",
    "pack_sockaddr",
    "parse_sockaddr",
    "pack_uid",
]
