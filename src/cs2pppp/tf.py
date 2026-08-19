"""TF/SD card video list + file download over CS2 PPPP app channels.

Wire protocol (CS2-style app JSON, observed on live devices):

* **List** — ``GetTfVideoList`` with ``page`` (usually **1-based**) and
  ``count``. Many firmwares stream **bare** JSON objects per file
  (``name``, ``patch``, ``size``, ``time``) without a wrapping
  ``cmd=GetTfVideoList`` envelope. Some envelopes put the array under
  ``value`` (not ``items``). Do **not** filter replies with
  ``expect_cmd="GetTfVideoList"`` or bare items are discarded.

* **Download** — ``DownloadFile`` JSON on DRW **channel 1**, then file
  bytes on DRW **channel 3**. Fields: ``pwd``, ``userid``, ``patch``,
  ``pos`` (resume offset), ``state`` (1=start, 0=stop).

* **Playback / preview** — ``PlaybackFile`` JSON on channel 1
  (``pwd``, ``userid``, ``state``, ``pos``, ``patch``); media stream on
  DRW **channel 0** (same path as live OpenVideo). ``tf_preview_frame``
  collects a short ch0 burst and decodes one JPEG via system ``ffmpeg``.

This module is protocol-only: no directory presets, no CLI, no download
filters (min-size / globs). Callers supply an open :class:`PpppSession`.
"""

from __future__ import annotations

import json
import random
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ._protocol import DRW_MAGIC, MAGIC, header
from .errors import SessionError
from .framing import encode_json, extract_json_strings, local_timezone_hours
from .session import (
    MSG_ALIVE,
    MSG_ALIVE_ACK,
    MSG_CLOSE,
    MSG_DRW,
    MSG_DRW_ACK,
    MSG_P2P_RDY,
    MSG_PUNCH_PKT,
    MSG_RLY_PKT,
    MSG_RLY_RDY,
    PeerEndpoint,
    PpppSession,
)

CHANNEL_CMD = 1
CHANNEL_STREAM = 0
CHANNEL_DOWNLOAD = 3
NO_DATA_TIMEOUT_S = 12.0
_HEVC_VPS = b"\x00\x00\x00\x01\x40"
# Channel-3 DownloadFile wraps the MOV in fixed frames:
#   a0 af af af | type/seq/… (25 bytes total header) | file bytes
_DOWNLOAD_FRAME_MAGIC = b"\xa0\xaf\xaf\xaf"
_DOWNLOAD_FRAME_HDR = 25

ProgressCb = Callable[[int, int, float], None]  # written, total, rate_bps


@dataclass
class TfVideoItem:
    """One recording on the device TF/SD card."""

    name: str
    patch: str  # remote path (protocol field is misspelled "patch")
    size_bytes: int
    time_seconds: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "patch": self.patch,
            "size": self.size_bytes,
            "time": self.time_seconds,
        }


@dataclass
class TfDownloadResult:
    """Outcome of one :func:`download_tf_file` call."""

    item: TfVideoItem
    action: str  # downloaded | resumed | skipped | failed
    path: Optional[str] = None
    bytes_written: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = self.item.to_dict()
        d["action"] = self.action
        if self.path:
            d["path"] = self.path
        d["bytes_written"] = self.bytes_written
        if self.error:
            d["error"] = self.error
        return d


def _as_int(v: Any, default: int = 0) -> int:
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default


def _item_from_dict(raw: Dict[str, Any]) -> Optional[TfVideoItem]:
    name = str(raw.get("name") or "").strip()
    patch = str(raw.get("patch") or raw.get("path") or "").strip()
    if not name and patch:
        name = Path(patch.replace("\\", "/")).name
    if not patch and name:
        patch = name
    if not name and not patch:
        return None
    has_size = "size" in raw or "sizeBytes" in raw
    has_path = bool(patch) and (
        "/" in patch or patch.lower().endswith((".mov", ".mp4", ".avi"))
    )
    if not has_size and not has_path and "time" not in raw:
        return None
    size = _as_int(raw.get("size") if "size" in raw else raw.get("sizeBytes"), 0)
    tsec = _as_int(raw.get("time") if "time" in raw else raw.get("timeSeconds"), 0)
    if not name:
        name = Path(patch.replace("\\", "/")).name or "video.bin"
    return TfVideoItem(
        name=name,
        patch=patch or name,
        size_bytes=max(0, size),
        time_seconds=max(0, tsec),
    )


def parse_tf_list_payload(
    obj: Dict[str, Any],
) -> Tuple[List[TfVideoItem], Optional[int]]:
    """Parse one JSON object into items + optional ``allCount``.

    Accepts bare firmware items or envelopes with ``value`` / ``items``.
    """
    out: List[TfVideoItem] = []
    cmd = obj.get("cmd")
    if not cmd:
        it = _item_from_dict(obj)
        if it is not None:
            out.append(it)
            return out, None

    items_raw = None
    for key in ("value", "items", "list", "files", "videoList"):
        cand = obj.get(key)
        if isinstance(cand, list):
            items_raw = cand
            break
    if items_raw is None:
        items_raw = []

    for raw in items_raw:
        if not isinstance(raw, dict):
            continue
        it = _item_from_dict(raw)
        if it is not None:
            out.append(it)

    all_count: Optional[int] = None
    for key in ("allCount", "allcount", "total", "totalCount"):
        if key in obj and obj[key] is not None and obj[key] != "":
            all_count = _as_int(obj[key], 0)
            break
    return out, all_count


def parse_tf_list_replies(
    replies: List[str],
) -> Tuple[List[TfVideoItem], Optional[int]]:
    """Merge items from JSON reply strings (envelope and/or bare items)."""
    merged: List[TfVideoItem] = []
    seen: set = set()
    all_count: Optional[int] = None
    for r in replies:
        try:
            obj = json.loads(r)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        cmd = obj.get("cmd")
        if cmd and cmd not in ("GetTfVideoList", "getTfVideoList"):
            if not any(k in obj for k in ("value", "items", "allCount")):
                continue
        items, ac = parse_tf_list_payload(obj)
        if ac is not None:
            all_count = ac
        for it in items:
            key = (it.patch, it.name, it.size_bytes)
            if key in seen:
                continue
            seen.add(key)
            merged.append(it)
    return merged, all_count


def _send_json(sess: PpppSession, obj: Dict[str, Any], *, channel: int = CHANNEL_CMD) -> None:
    sess.send_json(obj, channel=channel)


def collect_tf_list_page(
    sess: PpppSession,
    page: int,
    page_size: int,
    *,
    read_timeout: float = 12.0,
) -> Tuple[List[TfVideoItem], Optional[int], List[str]]:
    """Send one ``GetTfVideoList`` and collect replies without ``expect_cmd``.

    Bare item streams must not be filtered by command name.
    """
    if not sess.sock or not sess.peer:
        raise SessionError("session not open")

    req = {"cmd": "GetTfVideoList", "page": int(page), "count": int(page_size)}
    text = json.dumps(req, separators=(",", ":"), ensure_ascii=False)
    framed = encode_json(text, timezone_hours=local_timezone_hours())
    idx = sess.drw_index & 0xFFFF
    sess.drw_index = (sess.drw_index + 1) & 0xFFFF
    pkt = sess._drw_packet(framed, channel=CHANNEL_CMD, idx=idx)  # noqa: SLF001
    sess._send(pkt, (sess.peer.ip, sess.peer.port))  # noqa: SLF001

    replies: List[str] = []
    deadline = time.time() + max(read_timeout, 2.0)
    last_retx = time.time()
    last_item_at = 0.0
    idle_after_item = 1.2

    while time.time() < deadline:
        now = time.time()
        if last_item_at == 0.0 and now - last_retx > 0.7:
            sess._send(pkt, (sess.peer.ip, sess.peer.port))  # noqa: SLF001
            last_retx = now
        sess._send(header(MSG_ALIVE, 0), (sess.peer.ip, sess.peer.port))  # noqa: SLF001
        for data, addr in sess._recv(0.4):  # noqa: SLF001
            if len(data) < 2 or data[0] != MAGIC:
                continue
            t = data[1]
            if t == MSG_ALIVE:
                sess._send(header(MSG_ALIVE_ACK, 0), addr)  # noqa: SLF001
                continue
            if t in (
                MSG_ALIVE_ACK,
                MSG_RLY_RDY,
                MSG_RLY_PKT,
                MSG_P2P_RDY,
                MSG_PUNCH_PKT,
                MSG_DRW_ACK,
            ):
                continue
            if t == MSG_DRW and len(data) >= 8:
                sess.peer = PeerEndpoint(addr[0], addr[1])
                ch = data[5]
                di = struct.unpack_from(">H", data, 6)[0]
                ack = (
                    header(MSG_DRW_ACK, 6)
                    + bytes([DRW_MAGIC, ch, 0x00, 0x01])
                    + struct.pack(">H", di)
                )
                sess._send(ack, addr)  # noqa: SLF001
                payload = data[8:]
                for j in extract_json_strings(payload):
                    if j in replies or j.strip() == text:
                        continue
                    replies.append(j)
                    try:
                        obj = json.loads(j)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict):
                        items, _ = parse_tf_list_payload(obj)
                        if items:
                            last_item_at = time.time()
            elif t == MSG_CLOSE:
                break
        if last_item_at and (time.time() - last_item_at) >= idle_after_item:
            break

    items, all_count = parse_tf_list_replies(replies)
    return items, all_count, replies


def list_tf_videos(
    sess: PpppSession,
    *,
    page_size: int = 30,
    read_timeout: float = 12.0,
    max_pages: int = 200,
    start_page: int = 1,
) -> List[TfVideoItem]:
    """Paginate ``GetTfVideoList`` (apps typically use page starting at **1**)."""
    page_size = max(1, min(int(page_size), 200))
    page = max(1, int(start_page))
    all_items: List[TfVideoItem] = []
    seen: set = set()
    expected_total: Optional[int] = None

    for _ in range(max_pages):
        items, all_count, _raw = collect_tf_list_page(
            sess, page, page_size, read_timeout=read_timeout
        )
        if all_count is not None:
            expected_total = all_count
        if not items:
            if page == 1 and not all_items:
                items0, ac0, _ = collect_tf_list_page(
                    sess, 0, page_size, read_timeout=max(read_timeout, 15.0)
                )
                if ac0 is not None:
                    expected_total = ac0
                items = items0
            if not items:
                break

        new = 0
        for it in items:
            key = (it.patch, it.name, it.size_bytes)
            if key in seen:
                continue
            seen.add(key)
            all_items.append(it)
            new += 1
        if new == 0:
            break
        if expected_total is not None and len(all_items) >= expected_total:
            break
        if len(items) < page_size:
            break
        page += 1

    return all_items


def _download_frame_payload(frame: bytes) -> Optional[Tuple[int, bytes]]:
    """Parse one ``a0afafaf`` download frame → ``(seq, file_bytes)`` or None."""
    if len(frame) <= _DOWNLOAD_FRAME_HDR:
        return None
    if not frame.startswith(_DOWNLOAD_FRAME_MAGIC):
        # tolerate leading junk before magic
        j = frame.find(_DOWNLOAD_FRAME_MAGIC)
        if j < 0:
            return None
        frame = frame[j:]
        if len(frame) <= _DOWNLOAD_FRAME_HDR:
            return None
    seq = struct.unpack_from("<I", frame, 8)[0]
    return seq, frame[_DOWNLOAD_FRAME_HDR:]


def download_tf_file(
    sess: PpppSession,
    item: TfVideoItem,
    dest: Path,
    *,
    password: str = "",
    user_id: Optional[int] = None,
    no_data_timeout: float = NO_DATA_TIMEOUT_S,
    progress: Optional[ProgressCb] = None,
    progress_interval: float = 0.4,
    pos: int = 0,
    max_bytes: Optional[int] = None,
) -> TfDownloadResult:
    """Download one TF file via ``DownloadFile`` + DRW channel 3.

    Channel-3 payloads are CS2-framed (``a0afafaf`` + 25-byte header + chunk).
    This strips the framing and reassembles by sequence so the written file is
    a real MOV (with ``moov``).

    ``pos``: byte offset in the remote file (resume / range start).
    ``max_bytes``: stop after this many **stripped** bytes (preview head/tail).
    When set, does **not** wait for the full ``item.size_bytes``.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    start_pos = max(0, int(pos))
    cap = int(max_bytes) if max_bytes is not None and max_bytes > 0 else None

    if (
        cap is None
        and start_pos == 0
        and dest.is_file()
        and dest.stat().st_size > 32
    ):
        head = dest.read_bytes()[:12]
        if (
            item.size_bytes > 0
            and dest.stat().st_size >= item.size_bytes
            and head[4:8] == b"ftyp"
        ):
            return TfDownloadResult(
                item=item,
                action="skipped",
                path=str(dest.resolve()),
                bytes_written=dest.stat().st_size,
            )
        # stale framed/partial downloads — start clean
        try:
            dest.unlink()
        except OSError:
            pass
    elif dest.is_file() and (cap is not None or start_pos > 0):
        try:
            dest.unlink()
        except OSError:
            pass

    uid = int(user_id) if user_id is not None else random.randint(1, 100)
    pwd = password if password is not None else ""

    start_req = {
        "cmd": "DownloadFile",
        "pwd": pwd,
        "userid": uid,
        "patch": item.patch,
        "pos": int(start_pos),
        "state": 1,
    }
    stop_req = {
        "cmd": "DownloadFile",
        "pwd": pwd,
        "userid": uid,
        "patch": item.patch,
        "pos": 0,
        "state": 0,
    }

    if not sess.sock or not sess.peer:
        return TfDownloadResult(item=item, action="failed", error="session not open")

    _send_json(sess, start_req)
    time.sleep(0.15)
    _send_json(sess, start_req)

    # seq -> payload (keep longest copy for retransmits). For small
    # preview ranges we also append in arrival order as a fallback stream
    # because mid-file seeks sometimes renumber seqs non-monotonically.
    chunks: Dict[int, bytes] = {}
    ordered: List[bytes] = []
    seen_seq: set = set()
    # progress total: remaining file or cap
    if cap is not None:
        total = cap
    elif item.size_bytes > 0 and start_pos < item.size_bytes:
        total = item.size_bytes - start_pos
    elif item.size_bytes > 0:
        total = item.size_bytes
    else:
        total = 0
    t0 = time.time()
    last_data = t0
    last_prog = 0.0
    err: Optional[str] = None
    # reassembly buffer for partial DRW payloads
    rx_buf = bytearray()

    def stripped_size() -> int:
        if cap is not None:
            return sum(len(v) for v in ordered)
        return sum(len(v) for v in chunks.values())

    try:
        while True:
            now = time.time()
            have = stripped_size()
            # preview / range: enough stripped bytes
            if cap is not None and have >= cap:
                break
            if now - last_data > no_data_timeout:
                if have > 0:
                    # idle after progress: accept if we have enough or no total
                    if cap is not None or total <= 0 or have >= total * 0.98:
                        break
                    err = (
                        f"no channel-3 data for {no_data_timeout:.0f}s "
                        f"(have {have}/{total or '?'} bytes stripped)"
                    )
                else:
                    err = (
                        f"no channel-3 data for {no_data_timeout:.0f}s "
                        "(DownloadFile may need password or path invalid)"
                    )
                break
            # complete: stripped file reached declared size (full download)
            if cap is None and total > 0 and have >= total:
                break
            # hard cap from size (~25 KiB/s floor on bad relays) + slack
            if cap is not None:
                max_time = max(45.0, (cap / 20_000.0) + 30.0)
            elif total > 0:
                max_time = max(180.0, (total / 25_000.0) + 90.0)
            else:
                max_time = max(no_data_timeout * 30, 300.0)
            if (now - t0) > max_time:
                if have > 0:
                    break
                err = f"download timed out after {now - t0:.0f}s"
                break

            if now - last_prog >= progress_interval and progress is not None:
                elapsed = max(now - t0, 1e-3)
                progress(have, total, have / elapsed)
                last_prog = now

            sess._send(header(MSG_ALIVE, 0), (sess.peer.ip, sess.peer.port))  # noqa: SLF001
            for data, addr in sess._recv(0.35):  # noqa: SLF001
                if len(data) < 2 or data[0] != MAGIC:
                    continue
                t = data[1]
                if t == MSG_ALIVE:
                    sess._send(header(MSG_ALIVE_ACK, 0), addr)  # noqa: SLF001
                    continue
                if t == MSG_ALIVE_ACK:
                    continue
                if t in (
                    MSG_RLY_RDY,
                    MSG_RLY_PKT,
                    MSG_P2P_RDY,
                    MSG_PUNCH_PKT,
                    MSG_DRW_ACK,
                ):
                    continue
                if t == MSG_DRW and len(data) >= 8:
                    sess.peer = PeerEndpoint(addr[0], addr[1])
                    ch = data[5]
                    di = struct.unpack_from(">H", data, 6)[0]
                    ack = (
                        header(MSG_DRW_ACK, 6)
                        + bytes([DRW_MAGIC, ch, 0x00, 0x01])
                        + struct.pack(">H", di)
                    )
                    sess._send(ack, addr)  # noqa: SLF001
                    payload = data[8:]
                    if ch == CHANNEL_DOWNLOAD and payload:
                        rx_buf += payload
                        # peel complete a0-frames from buffer
                        while True:
                            if len(rx_buf) < 4:
                                break
                            if not rx_buf.startswith(_DOWNLOAD_FRAME_MAGIC):
                                j = bytes(rx_buf).find(_DOWNLOAD_FRAME_MAGIC)
                                if j < 0:
                                    # keep last 3 bytes (partial magic)
                                    del rx_buf[: max(0, len(rx_buf) - 3)]
                                    break
                                del rx_buf[:j]
                            # need next magic or enough bytes to guess frame end
                            nxt = bytes(rx_buf).find(
                                _DOWNLOAD_FRAME_MAGIC, 4
                            )
                            if nxt < 0:
                                # wait for more unless buffer is huge
                                if len(rx_buf) < 7000:
                                    break
                                # treat whole buffer as one frame
                                frame = bytes(rx_buf)
                                rx_buf.clear()
                            else:
                                frame = bytes(rx_buf[:nxt])
                                del rx_buf[:nxt]
                            parsed = _download_frame_payload(frame)
                            if not parsed:
                                continue
                            seq, body = parsed
                            if not body:
                                continue
                            prev = chunks.get(seq)
                            if prev is None or len(body) > len(prev):
                                chunks[seq] = body
                            # arrival-order stream (preview ranges / flaky seq)
                            if seq not in seen_seq:
                                seen_seq.add(seq)
                                ordered.append(body)
                                last_data = time.time()
                            elif len(body) > len(prev or b""):
                                last_data = time.time()
                    else:
                        for j in extract_json_strings(payload):
                            try:
                                jo = json.loads(j)
                            except json.JSONDecodeError:
                                continue
                            if (
                                isinstance(jo, dict)
                                and jo.get("cmd") == "DownloadFile"
                            ):
                                st = jo.get("state")
                                try:
                                    si = int(st) if st is not None else 0
                                except (TypeError, ValueError):
                                    si = 0
                                if si < 0 and not chunks:
                                    err = f"DownloadFile state={si}"
                                    last_data = 0
                elif t == MSG_CLOSE:
                    err = err or "session closed by peer"
                    last_data = 0
                    break
            if err and not chunks:
                break
    except OSError as e:
        err = f"write failed: {e}"
    finally:
        try:
            _send_json(sess, stop_req)
        except Exception:
            pass
        # flush trailing buffer as last frame
        if rx_buf.startswith(_DOWNLOAD_FRAME_MAGIC):
            parsed = _download_frame_payload(bytes(rx_buf))
            if parsed:
                seq, body = parsed
                prev = chunks.get(seq)
                if body and (prev is None or len(body) > len(prev)):
                    chunks[seq] = body
                if body and seq not in seen_seq:
                    seen_seq.add(seq)
                    ordered.append(body)

    written = stripped_size()
    if progress is not None:
        elapsed = max(time.time() - t0, 1e-3)
        progress(written, total, written / elapsed)

    if not chunks and not ordered:
        if dest.is_file():
            try:
                dest.unlink()
            except OSError:
                pass
        return TfDownloadResult(
            item=item,
            action="failed",
            path=None,
            error=err or "no download frames received",
        )

    # Preview ranges: prefer arrival order (stable for mid-file seeks).
    # Full download: sort by sequence for retransmit resilience.
    if cap is not None and ordered:
        blob = b"".join(ordered)
    else:
        blob = b"".join(chunks[s] for s in sorted(chunks))
    try:
        dest.write_bytes(blob)
    except OSError as e:
        return TfDownloadResult(
            item=item, action="failed", path=None, error=f"write failed: {e}"
        )

    written = len(blob)
    # Range/preview cap: any non-empty stripped payload is success.
    if cap is not None:
        if written < min(cap, 500) and err:
            return TfDownloadResult(
                item=item,
                action="failed",
                path=str(dest.resolve()) if written else None,
                bytes_written=written,
                error=err,
            )
        return TfDownloadResult(
            item=item,
            action="downloaded",
            path=str(dest.resolve()),
            bytes_written=written,
            error=None,
        )

    # Full download: need moov (or nearly full size).
    has_moov = b"moov" in blob
    has_ftyp = b"ftyp" in blob[:64]
    complete_enough = (
        (total > 0 and written >= total * 0.98)
        or (has_ftyp and has_moov and written > 10_000)
    )

    if not complete_enough:
        msg = err or f"incomplete {written}/{total or '?'} bytes (stripped)"
        if not has_moov:
            msg += "; no moov atom (transfer cut short)"
        return TfDownloadResult(
            item=item,
            action="failed",
            path=str(dest.resolve()),
            bytes_written=written,
            error=msg,
        )

    return TfDownloadResult(
        item=item,
        action="downloaded",
        path=str(dest.resolve()),
        bytes_written=written,
        error=None,
    )


def _iter_mp4_atoms(
    data: bytes, start: int = 0, end: Optional[int] = None
) -> List[Tuple[int, bytes, int, int]]:
    """Return list of (offset, type4, header_len, size) for top-level atoms."""
    end = len(data) if end is None else end
    out: List[Tuple[int, bytes, int, int]] = []
    off = start
    while off + 8 <= end:
        size = struct.unpack_from(">I", data, off)[0]
        typ = data[off + 4 : off + 8]
        hdr = 8
        if size == 1 and off + 16 <= end:
            size = struct.unpack_from(">Q", data, off + 8)[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr or off + size > end + 0:
            # truncated atom — still yield remaining as best-effort
            if size < hdr:
                break
            size = min(size, end - off)
        out.append((off, typ, hdr, size))
        off += size
        if size == 0:
            break
    return out


def _find_atom_payload(
    data: bytes, name: bytes, *, start: int = 0, end: Optional[int] = None
) -> Optional[Tuple[int, bytes]]:
    """Depth-first search for atom ``name``; return (payload_abs_off, payload)."""
    end = len(data) if end is None else end
    for off, typ, hdr, size in _iter_mp4_atoms(data, start, end):
        payload_off = off + hdr
        payload = data[payload_off : off + size]
        if typ == name:
            return payload_off, payload
        # container atoms
        if typ in (
            b"moov",
            b"trak",
            b"mdia",
            b"minf",
            b"stbl",
            b"stsd",
            b"udta",
            b"mvex",
        ):
            # stsd has a 8-byte preamble before sample entries
            sub_start = 0
            if typ == b"stsd" and len(payload) >= 8:
                sub_start = 8
            # sample entry (avc1/hvc1/…) has 78-byte visual sample entry header-ish;
            # walk nested by searching child atoms from sub_start
            nested = _find_atom_payload(
                payload, name, start=sub_start, end=len(payload)
            )
            if nested:
                return payload_off + nested[0], nested[1]
            # also try inside sample entries: skip 8 (stsd) + entry headers
            if typ == b"stsd":
                # brute: search for name anywhere as atom type
                idx = 8
                while idx + 8 <= len(payload):
                    esize = struct.unpack_from(">I", payload, idx)[0]
                    etyp = payload[idx + 4 : idx + 8]
                    if esize < 8 or idx + esize > len(payload):
                        break
                    # inside visual sample entry, atoms start after ~86 bytes
                    for skip in (8, 78, 86, 100):
                        if skip < esize:
                            nested = _find_atom_payload(
                                payload[idx : idx + esize],
                                name,
                                start=skip,
                                end=esize,
                            )
                            if nested:
                                return (
                                    payload_off + idx + nested[0],
                                    nested[1],
                                )
                    idx += esize
    return None


def _extract_moov_atom(blob: bytes) -> Optional[bytes]:
    """Full ``moov`` atom (size+type+body), even mid-buffer after mdat."""
    i = 0
    while True:
        j = blob.find(b"moov", i)
        if j < 4:
            return None
        size = struct.unpack_from(">I", blob, j - 4)[0]
        start = j - 4
        if 16 <= size <= len(blob) - start and size < 8_000_000:
            atom = blob[start : start + size]
            if b"mvhd" in atom or b"trak" in atom:
                return atom
        i = j + 4


def _extract_moov_payload(blob: bytes) -> Optional[bytes]:
    """Find a ``moov`` atom body even when it sits mid-buffer."""
    found = _find_atom_payload(blob, b"moov")
    if found:
        return found[1]
    atom = _extract_moov_atom(blob)
    if atom and len(atom) > 8:
        return atom[8:]
    return None


def _build_preview_mp4(head: bytes, moov_atom: bytes) -> Optional[bytes]:
    """ftyp+partial mdat from head, then full moov — stco still valid in head."""
    if len(head) < 40 or not moov_atom or len(moov_atom) < 16:
        return None
    if head[4:8] != b"ftyp":
        return None
    out = bytearray(head)
    # Shrink mdat size to the bytes we actually have so the parser finds moov next.
    if len(out) >= 40 and out[28:32] == b"mdat":
        sz32 = struct.unpack_from(">I", out, 24)[0]
        if sz32 == 1:
            # largesize at offset 32
            struct.pack_into(">Q", out, 32, len(out) - 24)
        else:
            struct.pack_into(">I", out, 24, len(out) - 24)
    elif len(out) >= 32 and out[24:28] == b"mdat":
        struct.pack_into(">I", out, 20, len(out) - 20)
    out += moov_atom
    return bytes(out)


def _mp4_first_sample_annexb(
    head: bytes, tail: bytes, file_size: int
) -> Optional[Tuple[bytes, str]]:
    """Build annex-B keyframe from preview head+tail ranges (moov often at end).

    Returns ``(annexb, codec)`` or None.
    """
    moov = _extract_moov_payload(tail) or _extract_moov_payload(head)
    if not moov:
        return None

    def _atom_body(buf: bytes, name: bytes) -> Optional[bytes]:
        j = 0
        while True:
            i = buf.find(name, j)
            if i < 4:
                return None
            sz = struct.unpack_from(">I", buf, i - 4)[0]
            start = i - 4
            if 8 <= sz <= len(buf) - start:
                return buf[i + 4 : start + sz]
            j = i + 4

    stsz_p = _atom_body(moov, b"stsz")
    stco_p = _atom_body(moov, b"stco")
    co64_p = _atom_body(moov, b"co64")
    stss_p = _atom_body(moov, b"stss")
    if not stsz_p or (not stco_p and not co64_p):
        return None
    if len(stsz_p) < 12:
        return None
    sample_size = struct.unpack_from(">I", stsz_p, 4)[0]
    sample_count = struct.unpack_from(">I", stsz_p, 8)[0]
    if sample_count < 1:
        return None

    def _sample_size_at(i0: int) -> int:
        if sample_size != 0:
            return sample_size
        o = 12 + 4 * i0
        if o + 4 > len(stsz_p):
            return 0
        return struct.unpack_from(">I", stsz_p, o)[0]

    # First sync sample (1-based); default to 1.
    key_1based = 1
    if stss_p and len(stss_p) >= 12:
        n_sync = struct.unpack_from(">I", stss_p, 4)[0]
        if n_sync >= 1:
            key_1based = struct.unpack_from(">I", stss_p, 8)[0]

    key_i = max(0, min(sample_count - 1, key_1based - 1))

    # Chunk offsets — many cams use 1 sample per chunk.
    if stco_p:
        n_chunk = struct.unpack_from(">I", stco_p, 4)[0] if len(stco_p) >= 8 else 0
        if n_chunk < 1 or len(stco_p) < 8 + 4 * n_chunk:
            return None
        # If one entry per sample, index by key; else use first chunk.
        if n_chunk >= sample_count:
            first_off = struct.unpack_from(">I", stco_p, 8 + 4 * key_i)[0]
        else:
            first_off = struct.unpack_from(">I", stco_p, 8)[0]
            # advance by sample sizes for keys before key_i (single-chunk case)
            for i in range(0, key_i):
                first_off += _sample_size_at(i)
    else:
        assert co64_p is not None
        n_chunk = struct.unpack_from(">I", co64_p, 4)[0] if len(co64_p) >= 8 else 0
        if n_chunk < 1 or len(co64_p) < 8 + 8 * n_chunk:
            return None
        if n_chunk >= sample_count:
            first_off = struct.unpack_from(">Q", co64_p, 8 + 8 * key_i)[0]
        else:
            first_off = struct.unpack_from(">Q", co64_p, 8)[0]
            for i in range(0, key_i):
                first_off += _sample_size_at(i)

    if first_off < 0 or first_off >= len(head):
        return None

    # Pull from keyframe through as much of the head as we have.
    # Multi-slice HEVC IDRs often span many samples; truncating early → green.
    want = 0
    for i in range(key_i, min(sample_count, key_i + 64)):
        want += _sample_size_at(i)
        if want >= 2_000_000:
            break
    if want < 100_000:
        want = 1_000_000
    # Prefer all remaining head bytes after the keyframe start.
    take = min(len(head) - first_off, max(want, 500_000))
    sample = head[first_off : first_off + take]
    if len(sample) < 8:
        return None

    # parameter sets from decoder config
    codec = "hevc"
    params = b""
    hvcc = _atom_body(moov, b"hvcC")
    avcc = _atom_body(moov, b"avcC")
    if hvcc:
        params = _hvcc_to_annexb(hvcc)
        codec = "hevc"
    elif avcc:
        params = _avcc_to_annexb(avcc)
        codec = "h264"
    else:
        codec = "hevc" if (sample[4] >> 1) & 0x3F >= 16 else "h264"

    # try length-size 4 then 2
    annex_sample = _mp4_length_pref_to_annexb(sample, 4)
    if not annex_sample or len(annex_sample) < 16:
        annex_sample = _mp4_length_pref_to_annexb(sample, 2)
    if not annex_sample:
        return None
    return params + annex_sample, codec


def _mp4_length_pref_to_annexb(sample: bytes, length_size: int = 4) -> bytes:
    out = bytearray()
    i = 0
    while i + length_size <= len(sample):
        if length_size == 4:
            n = struct.unpack_from(">I", sample, i)[0]
        elif length_size == 2:
            n = struct.unpack_from(">H", sample, i)[0]
        else:
            n = sample[i]
        i += length_size
        if n <= 0 or i + n > len(sample):
            break
        out += b"\x00\x00\x00\x01" + sample[i : i + n]
        i += n
    return bytes(out)


def _avcc_to_annexb(avcc: bytes) -> bytes:
    if len(avcc) < 7:
        return b""
    out = bytearray()
    nalu_len = (avcc[4] & 3) + 1  # unused here
    _ = nalu_len
    n_sps = avcc[5] & 0x1F
    o = 6
    for _ in range(n_sps):
        if o + 2 > len(avcc):
            break
        ln = struct.unpack_from(">H", avcc, o)[0]
        o += 2
        out += b"\x00\x00\x00\x01" + avcc[o : o + ln]
        o += ln
    if o >= len(avcc):
        return bytes(out)
    n_pps = avcc[o]
    o += 1
    for _ in range(n_pps):
        if o + 2 > len(avcc):
            break
        ln = struct.unpack_from(">H", avcc, o)[0]
        o += 2
        out += b"\x00\x00\x00\x01" + avcc[o : o + ln]
        o += ln
    return bytes(out)


def _hvcc_to_annexb(hvcc: bytes) -> bytes:
    """Extract VPS/SPS/PPS NALs from HEVCDecoderConfigurationRecord."""
    if len(hvcc) < 23:
        return b""
    out = bytearray()
    # numOfArrays at offset 22
    n_arrays = hvcc[22]
    o = 23
    for _ in range(n_arrays):
        if o + 3 > len(hvcc):
            break
        # array_completeness(1) | reserved(1) | NAL_unit_type(6)
        o += 1
        n_nalus = struct.unpack_from(">H", hvcc, o)[0]
        o += 2
        for _ in range(n_nalus):
            if o + 2 > len(hvcc):
                return bytes(out)
            ln = struct.unpack_from(">H", hvcc, o)[0]
            o += 2
            if o + ln > len(hvcc):
                return bytes(out)
            out += b"\x00\x00\x00\x01" + hvcc[o : o + ln]
            o += ln
    return bytes(out)


# --- Playback / preview (channel 0) ---------------------------------------


def playback_tf_file(
    sess: PpppSession,
    patch: str,
    *,
    password: str = "",
    user_id: int = 1,
    pos: int = 0,
    state: int = 1,
) -> None:
    """Send ``PlaybackFile`` (start ``state=1``, stop ``state=0``). No wait."""
    if not sess.sock or not sess.peer:
        raise SessionError("session not open")
    _send_json(
        sess,
        {
            "cmd": "PlaybackFile",
            "pwd": password if password is not None else "",
            "userid": int(user_id),
            "state": int(state),
            "pos": int(pos),
            "patch": patch,
        },
    )


def drain_stream_channel(
    sess: PpppSession,
    *,
    channel: int = CHANNEL_STREAM,
    seconds: float = 0.8,
) -> int:
    """ACK and discard payloads on a channel (clear residual after PlaybackFile stop)."""
    raw, _j, n = collect_stream_channel(
        sess, channel=channel, seconds=seconds, stop_on_keyframe=False
    )
    return n + len(raw) * 0  # n_drw; keep API simple


def collect_stream_channel(
    sess: PpppSession,
    *,
    channel: int = CHANNEL_STREAM,
    seconds: float = 4.0,
    stop_on_keyframe: bool = False,
    give_up_no_keyframe_after: Optional[float] = None,
    min_keyframe_bytes: int = 24_000,
) -> Tuple[bytes, List[str], int]:
    """ACK DRW and accumulate payloads for one channel for ``seconds``.

    If ``stop_on_keyframe``, return early once a full HEVC VPS+SPS+PPS+IDR AU
    is present (after media-header strip) **and** AU size has stopped growing
    (multi-slice frames need a short settle window — otherwise only the top
    of the picture decodes).

    If ``give_up_no_keyframe_after`` is set and that much time has passed with
    stream data but still no keyframe AU, return early (fail-fast for previews).
    """
    if not sess.sock or not sess.peer:
        raise SessionError("session not open")
    blobs: List[bytes] = []
    jsons: List[str] = []
    n_drw = 0
    t0 = time.time()
    deadline = t0 + max(seconds, 0.5)
    last_alive = 0.0
    au_len = 0
    au_stable_deadline: Optional[float] = None
    while time.time() < deadline:
        now = time.time()
        if now - last_alive > 0.8:
            sess._send(header(MSG_ALIVE, 0), (sess.peer.ip, sess.peer.port))  # noqa: SLF001
            last_alive = now
        for data, addr in sess._recv(0.25):  # noqa: SLF001
            if len(data) < 2 or data[0] != MAGIC:
                continue
            t = data[1]
            if t == MSG_ALIVE:
                sess._send(header(MSG_ALIVE_ACK, 0), addr)  # noqa: SLF001
                continue
            if t in (
                MSG_ALIVE_ACK,
                MSG_RLY_RDY,
                MSG_RLY_PKT,
                MSG_P2P_RDY,
                MSG_PUNCH_PKT,
                MSG_DRW_ACK,
            ):
                continue
            if t == MSG_DRW and len(data) >= 8:
                n_drw += 1
                sess.peer = PeerEndpoint(addr[0], addr[1])
                ch = data[5]
                di = struct.unpack_from(">H", data, 6)[0]
                ack = (
                    header(MSG_DRW_ACK, 6)
                    + bytes([DRW_MAGIC, ch, 0x00, 0x01])
                    + struct.pack(">H", di)
                )
                sess._send(ack, addr)  # noqa: SLF001
                payload = data[8:]
                if ch == (channel & 0xFF) and payload:
                    blobs.append(payload)
                for j in extract_json_strings(payload):
                    if j not in jsons:
                        jsons.append(j)
            elif t == MSG_CLOSE:
                break
        if stop_on_keyframe and blobs:
            joined = b"".join(blobs)
            au = extract_hevc_keyframe_au(joined)
            if au and len(au) >= min_keyframe_bytes:
                if len(au) > au_len:
                    au_len = len(au)
                    # keep collecting briefly — multi-slice IDR trails arrive late
                    au_stable_deadline = time.time() + 0.40
                elif (
                    au_stable_deadline is not None
                    and time.time() >= au_stable_deadline
                ):
                    break
            elif (
                give_up_no_keyframe_after is not None
                and (time.time() - t0) >= give_up_no_keyframe_after
                and len(joined) > 8000
            ):
                # stream is flowing but not a clean keyframe AU — bail early
                break
    return b"".join(blobs), jsons, n_drw


def sniff_annexb_codec(buf: bytes) -> Optional[str]:
    """Return ``hevc`` / ``h264`` if annex-B NAL markers found, else None."""
    i, n = 0, len(buf)
    while i < n - 4:
        if buf[i] == 0 and buf[i + 1] == 0:
            if buf[i + 2] == 1:
                hdr, j = buf[i + 3], i + 3
            elif buf[i + 2] == 0 and buf[i + 3] == 1:
                hdr = buf[i + 4] if i + 4 < n else None
                j = i + 4
            else:
                i += 1
                continue
            if hdr is None:
                return None
            if (hdr >> 1) & 0x3F in (32, 33, 34):
                return "hevc"
            if hdr & 0x1F in (7, 5, 1):
                return "h264"
            i = j
        else:
            i += 1
    return None


_MEDIA_FRAME_MAGIC = b"\x01\xaf\xaf\xaf"


def strip_media_frame_headers(data: bytes) -> bytes:
    """Remove CS2-style media frame wrappers (``01 AF AF AF`` …).

    Some firmwares interleave these headers with annex-B on the stream
    channel. Feeding the raw mix to ffmpeg yields corrupt frames.
    """
    if not data:
        return b""
    if _MEDIA_FRAME_MAGIC not in data:
        return data
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        j = data.find(_MEDIA_FRAME_MAGIC, pos)
        if j < 0:
            # trailing payload after last magic (unusual)
            if pos == 0:
                return data
            break
        # payload of this frame starts at first annex-B start code after magic
        search_from = j + 4
        next_magic = data.find(_MEDIA_FRAME_MAGIC, search_from)
        end = next_magic if next_magic >= 0 else n
        body = data[search_from:end]
        sc = body.find(b"\x00\x00\x00\x01")
        if sc < 0:
            sc = body.find(b"\x00\x00\x01")
        if sc >= 0:
            out += body[sc:]
        pos = end
    return bytes(out) if out else data


def _iter_annexb_nals(data: bytes) -> List[Tuple[int, int, int]]:
    """Return list of (start_offset, nal_type, end_offset) for annex-B NALs."""
    nals: List[Tuple[int, int, int]] = []
    i = 0
    n = len(data)
    starts: List[Tuple[int, int]] = []  # (offset of NAL body, sc_len)
    while i < n - 3:
        if data[i : i + 4] == b"\x00\x00\x00\x01":
            starts.append((i + 4, 4))
            i += 4
        elif data[i : i + 3] == b"\x00\x00\x01":
            starts.append((i + 3, 3))
            i += 3
        else:
            i += 1
    for k, (body_off, sc_len) in enumerate(starts):
        start_sc = body_off - sc_len
        end = starts[k + 1][0] - starts[k + 1][1] if k + 1 < len(starts) else n
        if body_off >= n:
            continue
        # HEVC: nal_unit_type = (first_byte >> 1) & 0x3f
        # H264: nal_unit_type = first_byte & 0x1f  (we return HEVC-style; callers check)
        nal_type = (data[body_off] >> 1) & 0x3F
        nals.append((start_sc, nal_type, end))
    return nals


def extract_hevc_annexb(data: bytes) -> bytes:
    """Best-effort HEVC annex-B from a mixed stream (strip media headers first)."""
    clean = strip_media_frame_headers(data)
    au = extract_hevc_keyframe_au(clean)
    if au:
        return au
    # fallback: from first VPS for a bounded stretch
    j = clean.find(_HEVC_VPS)
    if j < 0:
        return b""
    return clean[j : min(len(clean), j + 200_000)]


def extract_hevc_keyframe_au(data: bytes) -> bytes:
    """Extract one HEVC access unit: VPS+SPS+PPS (+SEI) + full keyframe picture.

    Prefer the **latest** complete parameter set + keyframe in the buffer so
    we decode a real picture instead of a lone VPS / mid-stream P-slice
    (green/corrupt JPEGs).

    After the first IDR/CRA NAL, include **all consecutive VCL slices** of the
    same picture (multi-slice / tiled HEVC). Stopping at the first IDR NAL
    yields half-frame white-bottom artifacts on many cameras.
    """
    clean = strip_media_frame_headers(data)
    nals = _iter_annexb_nals(clean)
    if not nals:
        return b""

    # HEVC: 32 VPS, 33 SPS, 34 PPS, 39/40 SEI; VCL 0–31; KEY 19/20 IDR, 21 CRA
    KEY = {19, 20, 21}
    best: Optional[bytes] = None
    i = 0
    while i < len(nals):
        _, t, _ = nals[i]
        if t != 32:  # need VPS start for a clean AU
            i += 1
            continue
        # gather param sets from this VPS
        vps_i = i
        has_sps = has_pps = False
        j = i
        while j < len(nals) and nals[j][1] in (32, 33, 34, 39, 40):
            if nals[j][1] == 33:
                has_sps = True
            if nals[j][1] == 34:
                has_pps = True
            j += 1
        # find keyframe after params
        k = j
        while k < len(nals) and nals[k][1] not in KEY:
            # skip non-VCL; stop if another VPS begins a new sequence without IDR
            if nals[k][1] == 32:
                break
            k += 1
        if has_sps and has_pps and k < len(nals) and nals[k][1] in KEY:
            start = nals[vps_i][0]
            # multi-slice: keep trailing VCL NALs of this picture
            end_i = k
            m = k + 1
            while m < len(nals) and nals[m][1] <= 31:
                end_i = m
                m += 1
            end = nals[end_i][2]
            best = clean[start:end]
            i = end_i + 1
            continue
        i += 1
    return best or b""


def find_ffmpeg() -> Optional[str]:
    which = shutil.which("ffmpeg")
    if which:
        return which
    try:
        import imageio_ffmpeg  # type: ignore

        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None


def stream_to_jpeg(
    stream: bytes,
    out_jpg: Path,
    *,
    ffmpeg: Optional[str] = None,
    codec: Optional[str] = None,
) -> None:
    """Decode first frame from annex-B stream to JPEG via ffmpeg.

    Feeds the **whole** stripped burst. Cutting to the first IDR NAL
    (``extract_hevc_keyframe_au``) yields a half-picture when the
    firmware repeats VPS/SPS/PPS before every slice of a tiled frame.
    """
    ff = ffmpeg or find_ffmpeg()
    if not ff:
        raise SessionError(
            "ffmpeg not found (install on PATH, or: pip install imageio-ffmpeg)"
        )
    if not stream:
        raise SessionError("empty stream")
    clean = strip_media_frame_headers(stream)
    c = codec or sniff_annexb_codec(clean) or sniff_annexb_codec(stream)
    if c not in ("h264", "hevc"):
        if b"\x00\x00\x00\x01" in clean[:64] or b"\x00\x00\x01" in clean[:32]:
            c = "hevc"
        else:
            raise SessionError("no H.264/HEVC start codes in stream")
    payload, fmt = clean, c

    if len(payload) < 64:
        raise SessionError("stream too short after strip")

    out_jpg = Path(out_jpg)
    out_jpg.parent.mkdir(parents=True, exist_ok=True)
    # -fflags +genpts discardcorrupt: tolerate partial TF playback bursts
    cmd = [
        ff,
        "-y",
        "-hide_banner",
        "-loglevel",
        "error",
        "-fflags",
        "+genpts+discardcorrupt",
        "-f",
        fmt,
        "-i",
        "pipe:0",
        "-frames:v",
        "1",
        "-q:v",
        "2",
        str(out_jpg),
    ]
    r = subprocess.run(cmd, input=payload, capture_output=True, timeout=45, check=False)
    if r.returncode != 0 or not out_jpg.is_file() or out_jpg.stat().st_size < 200:
        err = (r.stderr or b"").decode("utf-8", errors="replace")[:400]
        raise SessionError(
            f"ffmpeg failed (rc={r.returncode}): {err or 'no jpeg written'}"
        )


@dataclass
class TfPreviewResult:
    item: TfVideoItem
    action: str  # previewed | skipped | failed
    path: Optional[str] = None
    bytes_stream: int = 0
    codec: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = self.item.to_dict()
        d["action"] = self.action
        if self.path:
            d["path"] = self.path
        d["bytes_stream"] = self.bytes_stream
        if self.codec:
            d["codec"] = self.codec
        if self.error:
            d["error"] = self.error
        return d


def _jpeg_from_downloaded_file(
    path: Path,
    dest_jpg: Path,
    *,
    ffmpeg: Optional[str] = None,
) -> None:
    """Extract first video frame from a local MOV/MP4 via ffmpeg."""
    ff = ffmpeg or find_ffmpeg()
    if not ff:
        raise SessionError("ffmpeg not found")
    dest_jpg = Path(dest_jpg)
    dest_jpg.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        ff,
        "-y",
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(path),
        "-frames:v",
        "1",
        "-q:v",
        "2",
        str(dest_jpg),
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
    if r.returncode != 0 or not dest_jpg.is_file() or dest_jpg.stat().st_size < 200:
        err = (r.stderr or b"").decode("utf-8", errors="replace")[:400]
        raise SessionError(f"ffmpeg thumbnail failed: {err or 'no jpeg'}")


def _jpeg_rgb_sample(
    path: Path,
    *,
    ffmpeg: Optional[str] = None,
) -> Optional[bytes]:
    ff = ffmpeg or find_ffmpeg()
    if not ff or not Path(path).is_file() or Path(path).stat().st_size < 200:
        return None
    # Scale down for fast band stats (full 1080p RGB is heavy).
    cmd = [
        ff,
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(path),
        "-frames:v",
        "1",
        "-vf",
        "scale=160:90",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "pipe:1",
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
    rgb = r.stdout or b""
    if r.returncode != 0 or len(rgb) < 160 * 90 * 3:
        return None
    return rgb[: 160 * 90 * 3]


def jpeg_looks_corrupt(
    path: Path,
    *,
    ffmpeg: Optional[str] = None,
    green_ratio: float = 0.28,
    sample_stride: int = 1,
) -> bool:
    """Return True if JPEG looks like a green/corrupt/half-frame decode artifact.

    Detects:
      * green-dominant garbage (classic missing-ref HEVC)
      * almost all dark
      * bottom half flat (white/pink void) while top has real content —
        incomplete multi-slice IDR (only top of picture decoded)
    """
    rgb = _jpeg_rgb_sample(path, ffmpeg=ffmpeg)
    if rgb is None:
        return True
    w, h = 160, 90
    n = w * h
    greenish = 0
    dark = 0
    checked = 0
    step = max(1, sample_stride)
    for i in range(0, n, step):
        o = i * 3
        r_, g_, b_ = rgb[o], rgb[o + 1], rgb[o + 2]
        checked += 1
        if r_ + g_ + b_ < 40:
            dark += 1
            continue
        if g_ > r_ + 25 and g_ > b_ + 25:
            greenish += 1
    if checked == 0:
        return True
    if dark / checked > 0.85:
        return True
    if (greenish / checked) >= green_ratio:
        return True

    # Half-frame: bottom band nearly flat + bright, top has more variance.
    def band_stats(y0: int, y1: int) -> Tuple[float, float, float]:
        """Return (mean_luma, variance proxy, flat_ratio)."""
        vals: List[int] = []
        for y in range(y0, y1):
            row = y * w * 3
            for x in range(0, w, 2):
                o = row + x * 3
                vals.append(rgb[o] + rgb[o + 1] + rgb[o + 2])
        if not vals:
            return 0.0, 0.0, 1.0
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        # "flat" pixels near the band mean (void / solid fill)
        flat = sum(1 for v in vals if abs(v - mean) < 45) / len(vals)
        return mean, var, flat

    top_m, top_v, _ = band_stats(0, h // 3)
    mid_m, mid_v, mid_flat = band_stats(h // 3, 2 * h // 3)
    bot_m, bot_v, bot_flat = band_stats(2 * h // 3, h)
    # Incomplete multi-slice IDR: lower half is a flat bright void while
    # the upper half still has real texture (see previews with white bottoms).
    if bot_flat > 0.78 and bot_m > 350 and top_v > 1500:
        if bot_v < 3000 or bot_v < top_v * 0.12:
            return True
    # Cut-line mid-frame: mid band chaotic, bottom solid void
    if mid_v > 20_000 and bot_flat > 0.85 and bot_m > 500 and bot_v < 4000:
        return True
    return False


def accept_or_reject_jpeg(
    path: Path,
    *,
    ffmpeg: Optional[str] = None,
) -> None:
    """Raise SessionError and delete file if JPEG looks corrupt/green/half."""
    p = Path(path)
    if jpeg_looks_corrupt(p, ffmpeg=ffmpeg):
        try:
            p.unlink()
        except OSError:
            pass
        raise SessionError(
            "rejected incomplete/corrupt JPEG (half-frame or green keyframe)"
        )


def tf_preview_frame(
    sess: PpppSession,
    item: TfVideoItem,
    dest_jpg: Path,
    *,
    password: str = "",
    user_id: int = 1,
    pos: int = 0,
    seconds: float = 3.5,
    ffmpeg: Optional[str] = None,
    download_fallback: bool = True,
    max_download_bytes: Optional[int] = 3 * 1024 * 1024,
    download_timeout_s: float = 12.0,
    local_file_candidates: Optional[List[Path]] = None,
    keep_download_path: Optional[Path] = None,
    skip_green_check: bool = False,
    progress: Optional[ProgressCb] = None,
    prefer_stream: bool = True,
    preview_head_bytes: int = 4 * 1024 * 1024,
    preview_tail_bytes: int = 768 * 1024,
    reopen: Optional[Callable[[], None]] = None,
) -> TfPreviewResult:
    """One JPEG for a TF clip — **small transfer**, not full-file download.

    Order:
      1. Local complete MOV if present.
      2. Short ``PlaybackFile`` burst on channel 0 (default; ``prefer_stream``).
      3. Else one head range + optional moov tail via ``DownloadFile``.

    Do not send ``LoginDev`` as a session keepalive — a failed login
    leaves leftover JSON that makes the next ``GetTfVideoList`` look empty.
    Full clip = ``download_tf_file``.
    """
    dest_jpg = Path(dest_jpg)
    raw = b""
    play_err: Optional[str] = None
    ff = ffmpeg or find_ffmpeg()
    head_n = max(256 * 1024, int(preview_head_bytes))
    tail_n = max(256 * 1024, int(preview_tail_bytes))
    if max_download_bytes is not None and max_download_bytes > 0:
        head_n = min(head_n, int(max_download_bytes))
        tail_n = min(tail_n, int(max_download_bytes))

    # --- 1) local cache ----------------------------------------------------
    if local_file_candidates:
        for cand in local_file_candidates:
            cp = Path(cand)
            if not cp.is_file() or cp.stat().st_size < 1000:
                continue
            if cp.read_bytes()[:4] == _DOWNLOAD_FRAME_MAGIC:
                continue
            try:
                _jpeg_from_downloaded_file(cp, dest_jpg, ffmpeg=ff)
                if not skip_green_check and jpeg_looks_corrupt(
                    dest_jpg, ffmpeg=ff, green_ratio=0.45
                ):
                    dest_jpg.unlink(missing_ok=True)  # type: ignore[arg-type]
                    raise SessionError("local thumbnail looked corrupt")
                return TfPreviewResult(
                    item=item,
                    action="previewed",
                    path=str(dest_jpg.resolve()),
                    bytes_stream=cp.stat().st_size,
                    codec="local",
                )
            except Exception:
                try:
                    if dest_jpg.is_file():
                        dest_jpg.unlink()
                except OSError:
                    pass

    # --- 2) PlaybackFile burst (channel 0, same as live OpenVideo) --------
    if prefer_stream and seconds and seconds > 0:
        dest_jpg.parent.mkdir(parents=True, exist_ok=True)
        play_s = max(2.0, float(seconds))
        n_drw = 0
        try:
            playback_tf_file(
                sess, item.patch, password=password, user_id=user_id, pos=pos, state=1
            )
            raw, _js, n_drw = collect_stream_channel(
                sess, seconds=play_s, stop_on_keyframe=False
            )
        except Exception as e:
            play_err = f"playback: {e}"
            raw = b""
        finally:
            try:
                playback_tf_file(
                    sess,
                    item.patch,
                    password=password,
                    user_id=user_id,
                    pos=pos,
                    state=0,
                )
            except Exception:
                pass
            try:
                drain_stream_channel(sess, seconds=0.45)
            except Exception:
                pass
        if raw and len(raw) > 800:
            try:
                stream_to_jpeg(raw, dest_jpg, ffmpeg=ff)
                if not skip_green_check and jpeg_looks_corrupt(
                    dest_jpg, ffmpeg=ff, green_ratio=0.45
                ):
                    dest_jpg.unlink(missing_ok=True)  # type: ignore[arg-type]
                    raise SessionError("playback jpeg looked corrupt")
                sniffed = sniff_annexb_codec(strip_media_frame_headers(raw))
                return TfPreviewResult(
                    item=item,
                    action="previewed",
                    path=str(dest_jpg.resolve()),
                    bytes_stream=len(raw),
                    codec=f"play-{sniffed or 'hevc'}",
                )
            except Exception as e:
                play_err = f"playback: {e}"
                try:
                    if dest_jpg.is_file():
                        dest_jpg.unlink()
                except OSError:
                    pass
        elif play_err is None:
            play_err = f"playback silent (drw={n_drw} bytes={len(raw)})"
        if play_err and reopen is not None:
            try:
                reopen()
            except Exception as e:
                play_err = f"{play_err}; reopen: {e}"

    if not download_fallback:
        return TfPreviewResult(
            item=item,
            action="failed",
            error=play_err or "download fallback disabled and no local file",
        )

    # --- 3) ONE head + ONE tail (no retry thrash) -------------------------
    tmp_dir = dest_jpg.parent
    head_path = tmp_dir / (dest_jpg.stem + ".head.tmp")
    tail_path = tmp_dir / (dest_jpg.stem + ".tail.tmp")
    transferred = 0
    try:
        for p in (head_path, tail_path):
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass

        if progress:
            progress(0, head_n + tail_n, 0.0)

        dl_head = download_tf_file(
            sess,
            item,
            head_path,
            password=password,
            pos=0,
            max_bytes=head_n,
            no_data_timeout=max(download_timeout_s, 10.0),
            progress=progress,
        )
        if (
            dl_head.action == "failed"
            or not head_path.is_file()
            or head_path.stat().st_size < 500
        ):
            return TfPreviewResult(
                item=item,
                action="failed",
                error=f"preview-head: {dl_head.error or 'empty'}",
            )
        head = head_path.read_bytes()
        transferred += len(head)

        # faststart: moov already in head
        if b"moov" in head and b"ftyp" in head[:64]:
            try:
                _jpeg_from_downloaded_file(head_path, dest_jpg, ffmpeg=ff)
                return TfPreviewResult(
                    item=item,
                    action="previewed",
                    path=str(dest_jpg.resolve()),
                    bytes_stream=transferred,
                    codec="file-head",
                )
            except Exception as e:
                play_err = f"head-decode: {e}"

        size = item.size_bytes if item.size_bytes > 0 else 0
        # Locate end of mdat from head (moov usually follows).
        # ISO-BMFF: size==1 means a 64-bit largesize follows the type.
        mdat_end = 0
        if len(head) >= 40 and head[28:32] == b"mdat":
            mdat_sz32 = struct.unpack_from(">I", head, 24)[0]
            if mdat_sz32 == 1:
                mdat_sz = struct.unpack_from(">Q", head, 32)[0]
                if 16 < mdat_sz < 500_000_000:
                    mdat_end = 24 + mdat_sz
            elif 8 < mdat_sz32 < 500_000_000:
                mdat_end = 24 + mdat_sz32
        tail = b""
        if size > head_n + 64 or mdat_end > head_n:
            # ONE tail starting at moov (or near declared EOF).
            if mdat_end > 0:
                # start a few KB before moov; pull ~1–2 MiB of metadata
                tail_pos = max(0, mdat_end - 4096)
                want = min(tail_n, max(512 * 1024, (size - tail_pos) if size else tail_n))
            else:
                tail_pos = max(0, size - tail_n)
                want = tail_n
            # Mid-file DownloadFile pos is unreliable on the *same* session
            # after a head range — reopen when the caller provides a hook.
            # Do not LoginDev here: leftover login JSON poisons GetTfVideoList.
            if reopen is not None:
                try:
                    reopen()
                except Exception as e:
                    play_err = f"reopen: {e}"
            dl_tail = download_tf_file(
                sess,
                item,
                tail_path,
                password=password,
                pos=tail_pos,
                max_bytes=want,
                no_data_timeout=max(download_timeout_s, 10.0),
                progress=progress,
            )
            if dl_tail.action != "failed" and tail_path.is_file():
                tail = tail_path.read_bytes()
                transferred += len(tail)

        moov_atom = _extract_moov_atom(tail) if tail else None
        # Best path: rebuild a tiny valid MP4 (head + moov) so ffmpeg demuxes
        # the first frame properly (fixes multi-slice green bottoms).
        if moov_atom:
            mini = _build_preview_mp4(head, moov_atom)
            if mini:
                mini_path = tmp_dir / (dest_jpg.stem + ".mini.mp4")
                try:
                    mini_path.write_bytes(mini)
                    _jpeg_from_downloaded_file(mini_path, dest_jpg, ffmpeg=ff)
                    if (
                        not skip_green_check
                        and jpeg_looks_corrupt(
                            dest_jpg, ffmpeg=ff, green_ratio=0.75
                        )
                        and dest_jpg.stat().st_size < 12_000
                    ):
                        raise SessionError("mini-mp4 jpeg empty/corrupt")
                    return TfPreviewResult(
                        item=item,
                        action="previewed",
                        path=str(dest_jpg.resolve()),
                        bytes_stream=transferred,
                        codec="range-mp4",
                    )
                except Exception as e:
                    play_err = f"mini-mp4: {e}"
                    try:
                        if dest_jpg.is_file():
                            dest_jpg.unlink()
                    except OSError:
                        pass
                finally:
                    try:
                        if mini_path.is_file():
                            mini_path.unlink()
                    except OSError:
                        pass

        annex = _mp4_first_sample_annexb(
            head, tail, size or (len(head) + len(tail))
        )
        if annex:
            payload, codec = annex
            try:
                stream_to_jpeg(payload, dest_jpg, ffmpeg=ff, codec=codec)
                if (
                    not skip_green_check
                    and jpeg_looks_corrupt(dest_jpg, ffmpeg=ff, green_ratio=0.85)
                    and dest_jpg.stat().st_size < 15_000
                ):
                    raise SessionError("range jpeg looked empty/corrupt")
                return TfPreviewResult(
                    item=item,
                    action="previewed",
                    path=str(dest_jpg.resolve()),
                    bytes_stream=transferred,
                    codec=f"range-{codec}",
                )
            except Exception as e:
                play_err = f"range-decode: {e}"
                try:
                    if dest_jpg.is_file():
                        dest_jpg.unlink()
                except OSError:
                    pass

        moov_ok = bool(moov_atom)
        return TfPreviewResult(
            item=item,
            action="failed",
            bytes_stream=transferred,
            error=(
                f"preview failed after ~{transferred} B "
                f"(head={len(head)} tail={len(tail)} moov={'yes' if moov_ok else 'no'}); "
                f"{play_err or 'could not extract first frame'}. "
                f"Use download_tf_file for the full file."
            ),
        )
    finally:
        for p in (head_path, tail_path):
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass


def resolve_tf_item(
    items: List[TfVideoItem],
    name: str,
) -> TfVideoItem:
    """Match list entry by exact name, basename, patch, or unique fnmatch."""
    import fnmatch

    needle = (name or "").strip()
    if not needle:
        raise SessionError("empty video name")
    # exact name
    for it in items:
        if it.name == needle or it.patch == needle:
            return it
    # basename of patch
    for it in items:
        if Path(it.patch.replace("\\", "/")).name == needle:
            return it
        if Path(it.name).name == needle:
            return it
    # unique glob
    hits = [
        it
        for it in items
        if fnmatch.fnmatch(it.name, needle) or fnmatch.fnmatch(it.patch, needle)
    ]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        names = ", ".join(h.name for h in hits[:8])
        raise SessionError(f"ambiguous video name {needle!r}: {names}")
    raise SessionError(f"video not found: {needle!r}")


__all__ = [
    "CHANNEL_CMD",
    "CHANNEL_DOWNLOAD",
    "CHANNEL_STREAM",
    "NO_DATA_TIMEOUT_S",
    "ProgressCb",
    "TfDownloadResult",
    "TfPreviewResult",
    "TfVideoItem",
    "collect_stream_channel",
    "collect_tf_list_page",
    "download_tf_file",
    "drain_stream_channel",
    "extract_hevc_annexb",
    "extract_hevc_keyframe_au",
    "accept_or_reject_jpeg",
    "find_ffmpeg",
    "jpeg_looks_corrupt",
    "list_tf_videos",
    "parse_tf_list_payload",
    "parse_tf_list_replies",
    "playback_tf_file",
    "resolve_tf_item",
    "sniff_annexb_codec",
    "stream_to_jpeg",
    "strip_media_frame_headers",
    "tf_preview_frame",
]
