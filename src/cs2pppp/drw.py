"""DRW (data read/write) sub-header pack/unpack.

A DRW packet on the wire is::

    F1 D0 <u16 body_len>            # PPPP frame header (see _protocol.header)
    D1 <channel> <u16 index BE>     # DRW sub-header (this module)
    <app-channel blob>              # framing.encode_json output

Commands use channel 1; media (e.g. HEVC) arrives on channel 0. ``index`` is a
wrapping u16 sequence number.
"""

from __future__ import annotations

import struct
from typing import Tuple

from ._protocol import DRW_MAGIC, MSG_DRW, MSG_DRW_ACK, header


def pack_drw(payload: bytes, *, channel: int, index: int) -> bytes:
    """Build a full DRW packet (PPPP header + sub-header + payload)."""
    sub = bytes([DRW_MAGIC, channel & 0xFF]) + struct.pack(">H", index & 0xFFFF)
    body = sub + payload
    return header(MSG_DRW, len(body)) + body


def unpack_drw(data: bytes) -> Tuple[int, int, bytes]:
    """Parse a received DRW frame into ``(channel, index, payload)``.

    ``data`` is the whole datagram starting at the PPPP magic. Raises
    :class:`ValueError` if it is not a well-formed DRW frame.
    """
    if len(data) < 8 or data[1] != MSG_DRW:
        raise ValueError("not a DRW frame")
    channel = data[5]
    index = struct.unpack_from(">H", data, 6)[0]
    return channel, index, data[8:]


def pack_drw_ack(channel: int, index: int) -> bytes:
    """Build the transport-level DRW_ACK for a received (channel, index)."""
    return (
        header(MSG_DRW_ACK, 6)
        + bytes([DRW_MAGIC, channel & 0xFF, 0x00, 0x01])
        + struct.pack(">H", index & 0xFFFF)
    )


__all__ = ["pack_drw", "unpack_drw", "pack_drw_ack"]
