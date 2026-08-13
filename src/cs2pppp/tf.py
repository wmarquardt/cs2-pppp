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
) -> TfDownloadResult:
    """Download one TF file via ``DownloadFile`` + DRW channel 3.

    Supports resume when ``dest`` already exists and is shorter than
    ``item.size_bytes`` (uses ``pos``).
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    start_pos = 0
    mode = "wb"
    if dest.is_file():
        existing = dest.stat().st_size
        if item.size_bytes > 0 and existing >= item.size_bytes:
            return TfDownloadResult(
                item=item,
                action="skipped",
                path=str(dest.resolve()),
                bytes_written=existing,
            )
        if existing > 0:
            start_pos = existing
            mode = "ab"

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

    written = start_pos
    total = item.size_bytes if item.size_bytes > 0 else 0
    t0 = time.time()
    last_data = t0
    last_prog = 0.0
    action = "resumed" if start_pos > 0 else "downloaded"
    err: Optional[str] = None
    json_notes: List[str] = []

    try:
        with dest.open(mode) as fh:
            while True:
                now = time.time()
                if now - last_data > no_data_timeout:
                    if written > start_pos:
                        if total > 0 and written >= total:
                            break
                        err = (
                            f"no channel-3 data for {no_data_timeout:.0f}s "
                            f"(have {written}/{total or '?'} bytes)"
                        )
                    else:
                        err = (
                            f"no channel-3 data for {no_data_timeout:.0f}s "
                            "(DownloadFile may need password or path invalid)"
                        )
                    break
                if total > 0 and written >= total:
                    break

                if now - last_prog >= progress_interval and progress is not None:
                    elapsed = max(now - t0, 1e-3)
                    rate = (written - start_pos) / elapsed
                    progress(written, total, rate)
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
                            fh.write(payload)
                            written += len(payload)
                            last_data = time.time()
                            if total > 0 and written >= total:
                                break
                        else:
                            for j in extract_json_strings(payload):
                                if j not in json_notes:
                                    json_notes.append(j)
                                try:
                                    jo = json.loads(j)
                                except json.JSONDecodeError:
                                    continue
                                if (
                                    isinstance(jo, dict)
                                    and jo.get("cmd") == "DownloadFile"
                                ):
                                    st = jo.get("state")
                                    if st is not None:
                                        try:
                                            si = int(st)
                                        except (TypeError, ValueError):
                                            si = 0
                                        if si < 0 and written == start_pos:
                                            err = f"DownloadFile state={si}"
                                            last_data = 0
                    elif t == MSG_CLOSE:
                        err = err or "session closed by peer"
                        last_data = 0
                        break
                if err and written == start_pos:
                    break
                if total > 0 and written >= total:
                    break
    except OSError as e:
        err = f"write failed: {e}"
    finally:
        try:
            _send_json(sess, stop_req)
        except Exception:
            pass

    if progress is not None:
        elapsed = max(time.time() - t0, 1e-3)
        progress(written, total, (written - start_pos) / elapsed)

    if err and written <= start_pos:
        if dest.is_file() and dest.stat().st_size == 0:
            try:
                dest.unlink()
            except OSError:
                pass
        return TfDownloadResult(item=item, action="failed", path=None, error=err)

    if err and total > 0 and written < total:
        return TfDownloadResult(
            item=item,
            action="failed",
            path=str(dest.resolve()) if dest.is_file() else None,
            bytes_written=written,
            error=err,
        )

    if total > 0 and written < total and not err:
        return TfDownloadResult(
            item=item,
            action="failed",
            path=str(dest.resolve()) if dest.is_file() else None,
            bytes_written=written,
            error=f"incomplete {written}/{total} bytes",
        )

    return TfDownloadResult(
        item=item,
        action=action,
        path=str(dest.resolve()),
        bytes_written=written,
        error=None,
    )


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
) -> Tuple[bytes, List[str], int]:
    """ACK DRW and accumulate payloads for one channel for ``seconds``.

    If ``stop_on_keyframe``, return early once a full HEVC VPS+SPS+PPS+IDR AU
    is present (after media-header strip).
    """
    if not sess.sock or not sess.peer:
        raise SessionError("session not open")
    blobs: List[bytes] = []
    jsons: List[str] = []
    n_drw = 0
    deadline = time.time() + max(seconds, 0.5)
    last_alive = 0.0
    while time.time() < deadline:
        now = time.time()
        if now - last_alive > 0.8:
            sess._send(header(MSG_ALIVE, 0), (sess.peer.ip, sess.peer.port))  # noqa: SLF001
            last_alive = now
        for data, addr in sess._recv(0.35):  # noqa: SLF001
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
            if extract_hevc_keyframe_au(b"".join(blobs)):
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
    """Extract one HEVC access unit: VPS+SPS+PPS (+SEI) + first IDR/CRA slice.

    Prefer the **latest** complete parameter set + keyframe in the buffer so
    we decode a real picture instead of a lone VPS / mid-stream P-slice
    (green/corrupt JPEGs).
    """
    clean = strip_media_frame_headers(data)
    nals = _iter_annexb_nals(clean)
    if not nals:
        return b""

    # HEVC types: 32 VPS, 33 SPS, 34 PPS, 39/40 SEI, 19/20 IDR, 21 CRA
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
            end = nals[k][2]
            # include a little trailing data of the IDR NAL only
            best = clean[start:end]
            i = k + 1
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
    """Decode first frame from annex-B stream to JPEG via ffmpeg."""
    ff = ffmpeg or find_ffmpeg()
    if not ff:
        raise SessionError(
            "ffmpeg not found (install on PATH, or: pip install imageio-ffmpeg)"
        )
    if not stream:
        raise SessionError("empty stream")
    clean = strip_media_frame_headers(stream)
    c = codec or sniff_annexb_codec(clean) or sniff_annexb_codec(stream)
    if c == "h264":
        payload, fmt = clean, "h264"
    else:
        # Require a full VPS+SPS+PPS+IDR AU — incomplete HEVC → green/corrupt JPEGs
        payload = extract_hevc_keyframe_au(clean)
        fmt = "hevc"
        if not payload:
            raise SessionError(
                "no complete HEVC keyframe (VPS+SPS+PPS+IDR) in stream"
            )

    if len(payload) < 64:
        raise SessionError("stream too short after strip/keyframe extract")

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


def jpeg_looks_corrupt(
    path: Path,
    *,
    ffmpeg: Optional[str] = None,
    green_ratio: float = 0.28,
    sample_stride: int = 8,
) -> bool:
    """Return True if JPEG looks like a green/corrupt decode artifact.

    Samples RGB via ffmpeg rawvideo. A frame is "green" when many pixels have
    G significantly above R and B (classic missing-reference HEVC garbage).
    """
    ff = ffmpeg or find_ffmpeg()
    if not ff or not Path(path).is_file() or Path(path).stat().st_size < 200:
        return True
    # Decode to a small RGB frame for sampling
    cmd = [
        ff,
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(path),
        "-frames:v",
        "1",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "pipe:1",
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
    rgb = r.stdout or b""
    if r.returncode != 0 or len(rgb) < 300:
        return True
    # Assume roughly square-ish; we only need relative channel stats
    n = len(rgb) // 3
    if n < 100:
        return True
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
    # mostly flat green, or almost all dark (failed decode)
    if dark / checked > 0.85:
        return True
    return (greenish / checked) >= green_ratio


def accept_or_reject_jpeg(
    path: Path,
    *,
    ffmpeg: Optional[str] = None,
) -> None:
    """Raise SessionError and delete file if JPEG looks corrupt/green."""
    p = Path(path)
    if jpeg_looks_corrupt(p, ffmpeg=ffmpeg):
        try:
            p.unlink()
        except OSError:
            pass
        raise SessionError("rejected green/corrupt JPEG (no clean keyframe)")


def tf_preview_frame(
    sess: PpppSession,
    item: TfVideoItem,
    dest_jpg: Path,
    *,
    password: str = "",
    user_id: int = 1,
    pos: int = 0,
    seconds: float = 6.0,
    ffmpeg: Optional[str] = None,
    download_fallback: bool = True,
    download_timeout_s: float = 45.0,
) -> TfPreviewResult:
    """One JPEG for a TF clip.

    1. Prefer ``PlaybackFile`` + ch0 keyframe (fast when stream is clean).
    2. If that fails and ``download_fallback``, download the file via ch3 and
       extract a frame with ffmpeg (slower, usually correct colour / no green).
    """
    dest_jpg = Path(dest_jpg)
    patch = item.patch
    raw = b""
    play_err: Optional[str] = None

    # Clear leftover from previous clip
    try:
        playback_tf_file(
            sess, patch, password=password, user_id=user_id, pos=0, state=0
        )
    except Exception:
        pass
    try:
        drain_stream_channel(sess, channel=CHANNEL_STREAM, seconds=0.6)
    except Exception:
        pass

    try:
        playback_tf_file(
            sess, patch, password=password, user_id=user_id, pos=pos, state=1
        )
        time.sleep(0.2)
        playback_tf_file(
            sess, patch, password=password, user_id=user_id, pos=pos, state=1
        )
        raw, _jsons, _n = collect_stream_channel(
            sess,
            channel=CHANNEL_STREAM,
            seconds=seconds,
            stop_on_keyframe=True,
        )
    except Exception as e:
        play_err = str(e)
        raw = b""
    finally:
        try:
            playback_tf_file(
                sess, patch, password=password, user_id=user_id, pos=0, state=0
            )
        except Exception:
            pass
        try:
            drain_stream_channel(sess, channel=CHANNEL_STREAM, seconds=0.5)
        except Exception:
            pass

    if raw:
        clean = strip_media_frame_headers(raw)
        codec = sniff_annexb_codec(clean) or sniff_annexb_codec(raw)
        try:
            stream_to_jpeg(raw, dest_jpg, ffmpeg=ffmpeg, codec=codec)
            accept_or_reject_jpeg(dest_jpg, ffmpeg=ffmpeg)
            return TfPreviewResult(
                item=item,
                action="previewed",
                path=str(dest_jpg.resolve()),
                bytes_stream=len(raw),
                codec=codec,
            )
        except Exception as e:
            play_err = str(e)
            try:
                if dest_jpg.is_file():
                    dest_jpg.unlink()
            except OSError:
                pass

    if not download_fallback:
        return TfPreviewResult(
            item=item,
            action="failed",
            bytes_stream=len(raw),
            error=play_err or "playback preview failed",
        )

    # Fallback: full DownloadFile then first frame (reliable for .MOV on disk)
    tmp = dest_jpg.with_suffix(dest_jpg.suffix + ".dl.tmp")
    try:
        if tmp.is_file():
            tmp.unlink()
        dl = download_tf_file(
            sess,
            item,
            tmp,
            password=password,
            no_data_timeout=max(download_timeout_s, 20.0),
        )
        if dl.action == "failed" or not tmp.is_file() or tmp.stat().st_size < 1000:
            return TfPreviewResult(
                item=item,
                action="failed",
                bytes_stream=len(raw),
                error=(
                    f"playback: {play_err}; download: {dl.error or 'incomplete'}"
                ),
            )
        _jpeg_from_downloaded_file(tmp, dest_jpg, ffmpeg=ffmpeg)
        accept_or_reject_jpeg(dest_jpg, ffmpeg=ffmpeg)
        return TfPreviewResult(
            item=item,
            action="previewed",
            path=str(dest_jpg.resolve()),
            bytes_stream=tmp.stat().st_size,
            codec="file",
        )
    except Exception as e:
        try:
            if dest_jpg.is_file():
                dest_jpg.unlink()
        except OSError:
            pass
        return TfPreviewResult(
            item=item,
            action="failed",
            bytes_stream=len(raw),
            error=f"playback: {play_err}; download-fallback: {e}",
        )
    finally:
        try:
            if tmp.is_file():
                tmp.unlink()
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
