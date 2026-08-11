"""CS2 application-channel JSON framing (the payload carried over DRW).

Layout (total = 26 + len(json) + 4)::

    0..3   magic LE  A0 AF AF AF   (u32 0xAFAFAFA0)
    4      0x00
    5      timezone offset hours (signed byte)
    6..13  timestamp LE i64: time(NULL) + timezoneHours * 3600
    14..21 zero pad
    22..25 JSON body length LE u32
    26..   UTF-8 JSON body
    end    trailer LE  F4 F3 F2 F1  (u32 0xF1F2F3F4)
"""

from __future__ import annotations

import struct
import time
from typing import Dict, Iterable, List, Tuple, Union

MAGIC = 0xAFAFAFA0
TRAILER = 0xF1F2F3F4
HEADER_LEN = 0x1A  # 26
TRAILER_LEN = 4


def encode_json(json_text: Union[str, bytes], *, timezone_hours: int = 0) -> bytes:
    """Frame a JSON string/bytes into a CS2 app-channel blob."""
    body = (
        json_text.encode("utf-8") if isinstance(json_text, str) else bytes(json_text)
    )
    n = len(body)
    out = bytearray(HEADER_LEN + n + TRAILER_LEN)
    struct.pack_into("<I", out, 0, MAGIC)
    out[4] = 0
    out[5] = timezone_hours & 0xFF
    ts = int(time.time()) + int(timezone_hours) * 3600
    struct.pack_into("<q", out, 6, ts)
    struct.pack_into("<I", out, 0x16, n)
    out[HEADER_LEN : HEADER_LEN + n] = body
    struct.pack_into("<I", out, HEADER_LEN + n, TRAILER)
    return bytes(out)


def try_decode_frame(buf: bytes) -> List[Tuple[bytes, Dict[str, int]]]:
    """Extract zero or more framed JSON bodies from a read buffer.

    Returns a list of ``(raw_json_bytes, meta)`` where ``meta`` carries
    ``timezone_hours``, ``timestamp``, ``offset``, ``length``.
    """
    found: List[Tuple[bytes, Dict[str, int]]] = []
    i = 0
    while i + HEADER_LEN + TRAILER_LEN <= len(buf):
        if struct.unpack_from("<I", buf, i)[0] != MAGIC:
            i += 1
            continue
        tz = buf[i + 5]
        if tz >= 128:
            tz -= 256
        ts = struct.unpack_from("<q", buf, i + 6)[0]
        n = struct.unpack_from("<I", buf, i + 0x16)[0]
        end = i + HEADER_LEN + n + TRAILER_LEN
        if n > 1_000_000 or end > len(buf):
            i += 1
            continue
        if struct.unpack_from("<I", buf, i + HEADER_LEN + n)[0] != TRAILER:
            i += 1
            continue
        body = bytes(buf[i + HEADER_LEN : i + HEADER_LEN + n])
        found.append(
            (body, {"timezone_hours": tz, "timestamp": ts, "offset": i, "length": n})
        )
        i = end
    return found


def extract_json_strings(buf: bytes) -> List[str]:
    """Best-effort: framed bodies first, else brace-scan UTF-8 JSON objects."""
    out: List[str] = []
    for body, _ in try_decode_frame(buf):
        out.append(body.decode("utf-8", errors="replace"))
    if out:
        return out
    text = buf.decode("utf-8", errors="ignore")
    start = None
    depth = 0
    for idx, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start : idx + 1])
                start = None
    return out


def local_timezone_hours() -> int:
    """Signed whole-hour UTC offset of the local zone (app convention)."""
    lt = time.localtime()
    off = getattr(lt, "tm_gmtoff", None)
    if off is None:
        off = -time.timezone if not time.daylight else -time.altzone
    return int(off // 3600)


def iter_json_blobs(chunks: Iterable[bytes]) -> List[str]:
    return extract_json_strings(b"".join(chunks))


__all__ = [
    "MAGIC",
    "TRAILER",
    "HEADER_LEN",
    "TRAILER_LEN",
    "encode_json",
    "try_decode_frame",
    "extract_json_strings",
    "local_timezone_hours",
    "iter_json_blobs",
]
