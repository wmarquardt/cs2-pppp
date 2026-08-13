"""High-level device helpers built on top of :class:`PpppSession`.

Prefer opening these via :meth:`cs2pppp.Cs2Client.device`, which injects the
directory servers. All commands ride the CS2 app JSON channel.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .did import to_real
from .errors import AuthError, SessionError
from .session import PpppSession
from .tf import (
    TfDownloadResult,
    TfPreviewResult,
    TfVideoItem,
    download_tf_file,
    list_tf_videos,
    tf_preview_frame,
)

logger = logging.getLogger("cs2pppp")

# Read-only info commands (best-effort; devices ignore unknown ones).
INFO_COMMANDS: List[Dict[str, Any]] = [
    {"cmd": "GetDevInfo"},
    {"cmd": "GetDevExInfo"},
    {"cmd": "GetDevVideoInfo"},
    {"cmd": "GetAlarmInfo"},
    {"cmd": "GetDevTfParam"},
]

# HEVC annex-B VPS start marker; media rides DRW channel 0.
_HEVC_VPS = b"\x00\x00\x00\x01\x40"
_CHANNEL_STREAM = 0
_CHANNEL_CMD = 1


class Device:
    """A logged-in-capable handle to one camera."""

    def __init__(
        self,
        real_did: str,
        servers,
        *,
        port: int = 32100,
        password: str = "",
        timeout: float = 20.0,
        prefer: str = "relay",
    ) -> None:
        self.real_did = to_real(real_did) or real_did
        self.password = password
        self._timeout = timeout
        self._prefer = prefer
        self.session = PpppSession(
            real_did=self.real_did, servers=tuple(servers), port=port
        )

    # --- lifecycle --------------------------------------------------------

    def open(self) -> "Device":
        self.session.open(timeout=self._timeout, prefer=self._prefer)
        if self.session.loopback:
            raise SessionError("loopback session (self-echo), not a real device")
        self.session.ensure_app_channel()
        if self.password:
            self.login()
        return self

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "Device":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- commands ---------------------------------------------------------

    def login(self, password: Optional[str] = None) -> Dict[str, Any]:
        """Send LoginDev; raise :class:`AuthError` if rejected."""
        pwd = self.password if password is None else password
        replies = self.session.request_json({"cmd": "LoginDev", "pwd": pwd})
        for r in replies:
            if r.get("cmd") == "LoginDev":
                result = r.get("result", r.get("ret"))
                if result not in (None, 0, "0", "success", "ok"):
                    raise AuthError(f"LoginDev rejected: {r}")
                return r
        # No explicit LoginDev reply: treat silence as inconclusive, not success.
        raise AuthError("LoginDev got no acknowledgement")

    def get_info(self) -> Dict[str, Any]:
        """Collect device info from GetDevInfo (+ related), merged into one dict."""
        merged: Dict[str, Any] = {}
        for cmd in INFO_COMMANDS:
            for r in self.session.request_json(cmd, read_timeout=3.0):
                if isinstance(r, dict):
                    merged.setdefault(r.get("cmd", "?"), r)
        info = merged.get("GetDevInfo", {})
        return {"did": self.real_did, "info": info, "all": merged}

    def command(self, obj: Dict[str, Any], **kw) -> List[Dict[str, Any]]:
        """Send an arbitrary app-channel command; parsed JSON replies."""
        return self.session.request_json(obj, **kw)

    # --- TF / SD card recordings ------------------------------------------

    def list_tf_videos(
        self,
        *,
        page_size: int = 30,
        read_timeout: float = 12.0,
        max_pages: int = 200,
        start_page: int = 1,
    ) -> List[TfVideoItem]:
        """List recordings on the device TF/SD card (``GetTfVideoList``)."""
        return list_tf_videos(
            self.session,
            page_size=page_size,
            read_timeout=read_timeout,
            max_pages=max_pages,
            start_page=start_page,
        )

    def download_tf_file(
        self,
        item: TfVideoItem,
        dest: Union[str, Path],
        *,
        password: Optional[str] = None,
        progress: Optional[Callable[[int, int, float], None]] = None,
    ) -> TfDownloadResult:
        """Download one TF file to ``dest`` (``DownloadFile`` + DRW channel 3)."""
        pwd = self.password if password is None else password
        return download_tf_file(
            self.session,
            item,
            Path(dest),
            password=pwd or "",
            progress=progress,
        )

    def tf_preview(
        self,
        item: TfVideoItem,
        dest_jpg: Union[str, Path],
        *,
        password: Optional[str] = None,
        seconds: float = 3.5,
    ) -> TfPreviewResult:
        """One JPEG from TF playback (``PlaybackFile`` + channel 0). Needs ffmpeg."""
        pwd = self.password if password is None else password
        return tf_preview_frame(
            self.session,
            item,
            Path(dest_jpg),
            password=pwd or "",
            seconds=seconds,
        )

    # --- snapshot (optional; needs system ffmpeg) -------------------------

    def snapshot(self, out_path: str, *, stream: int = 0, seconds: float = 6.0) -> str:
        """Grab one JPEG frame via OpenVideo. Requires ``ffmpeg`` on PATH.

        Opens the video stream, collects channel-0 HEVC for ``seconds``, then
        decodes the first frame with ffmpeg. Returns ``out_path``.
        """
        ffmpeg = shutil.which("ffmpeg")
        if not ffmpeg:
            raise SessionError("ffmpeg not found on PATH (needed for snapshot)")
        import time

        self.session.send_json(
            {"cmd": "OpenVideo", "state": 1, "stream": stream, "userid": 1},
            channel=_CHANNEL_CMD,
        )
        self.session.send_json(
            {"cmd": "OpenVideo", "state": 1, "stream": stream, "userid": 1},
            channel=_CHANNEL_CMD,
        )
        blobs: List[bytes] = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            # recv() ACKs and returns cmd-channel JSON; capture raw ch0 via a
            # dedicated pass over the socket.
            for data, addr in self.session._recv(0.4):  # noqa: SLF001
                if len(data) >= 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    ch = data[5]
                    if ch == _CHANNEL_STREAM:
                        blobs.append(data[8:])
                    # ACK every DRW to keep the stream flowing
                    self.session.recv(timeout=0.01)
        hevc = _extract_hevc(b"".join(blobs))
        if not hevc:
            raise SessionError("no HEVC captured on channel 0")
        proc = subprocess.run(
            [ffmpeg, "-y", "-f", "hevc", "-i", "pipe:0", "-frames:v", "1",
             "-q:v", "2", out_path],
            input=hevc,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if proc.returncode != 0:
            raise SessionError("ffmpeg failed to decode a frame")
        return out_path


def _extract_hevc(buf: bytes) -> bytes:
    """Concatenate annex-B regions starting at each VPS marker."""
    if _HEVC_VPS not in buf:
        return buf if buf else b""
    out = bytearray()
    idx = buf.find(_HEVC_VPS)
    while idx != -1:
        nxt = buf.find(_HEVC_VPS, idx + len(_HEVC_VPS))
        end = nxt if nxt != -1 else min(len(buf), idx + 80000)
        out += buf[idx:end]
        idx = nxt
    return bytes(out)


__all__ = [
    "Device",
    "INFO_COMMANDS",
    "TfVideoItem",
    "TfDownloadResult",
    "TfPreviewResult",
]
