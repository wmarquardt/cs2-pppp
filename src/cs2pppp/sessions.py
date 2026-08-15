"""Session status over CS2 app JSON (LoginDev connectNum + path peer).

Protocol facts (CS2-style cameras, app JSON):

* ``LoginDev`` returns ``connectNum`` (concurrent-session **count**, often
  ``-1`` when firmware does not track it) — never a list of client IPs.
* ``GetDevInfo.ip`` is the **camera** address when set (often empty on 4G).
* There is no standard app-JSON command that returns viewer/client addresses.
  Optional speculative probes (``GetUserList``, …) typically get ``state=-1``.
* The PPPP peer (``session.peer``) is **this** connection's path (relay or
  direct), equivalent to native ``PPCS_Check`` RemoteIP for our session only.

This module is protocol-only: caller supplies an open :class:`PpppSession`
and password. No directory presets, no password store, no CLI formatting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .session import PpppSession

# Names never observed in stock app protocol packages; firmware usually
# answers state=-1 or silence. Optional RE / completeness probes.
CLIENT_LIST_PROBES: tuple[Dict[str, Any], ...] = (
    {"cmd": "GetUserList"},
    {"cmd": "GetUser"},
    {"cmd": "GetClientList"},
    {"cmd": "GetSessionList"},
    {"cmd": "GetOnlineUser"},
    {"cmd": "GetConnectList"},
)


@dataclass
class CmdProbe:
    """One app-JSON command attempt (request + raw reply strings or error)."""

    request: Dict[str, Any]
    replies: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def summary(self) -> str:
        if self.error:
            return self.error
        if not self.replies:
            return "no reply"
        parts: List[str] = []
        for r in self.replies:
            try:
                parts.append(json.dumps(json.loads(r), ensure_ascii=False))
            except json.JSONDecodeError:
                parts.append(r.replace("\n", " ")[:200])
        return " | ".join(parts)


@dataclass
class SessionStatus:
    """What the wire protocol exposes about concurrent sessions / path.

    ``client_list_available`` is always False for known firmwares; ``clients``
    stays empty. Use ``connect_num`` as a count only (``None`` missing, ``<0``
    unsupported).
    """

    login_ok: bool
    login_result: Optional[int]
    connect_num: Optional[int]
    device_type: Optional[str]
    login_raw: Optional[Dict[str, Any]]
    device_ip: Optional[str]
    wifissid: Optional[str]
    four_g: Optional[int]
    imei: Optional[str]
    getdevinfo_raw: Optional[Dict[str, Any]]
    peer: Optional[str]  # "ip:port" of this PPPP path
    via: str  # relay / direct / …
    loopback: bool
    speculative: List[CmdProbe] = field(default_factory=list)

    @property
    def client_list_available(self) -> bool:
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "login": {
                "ok": self.login_ok,
                "result": self.login_result,
                "connect_num": self.connect_num,
                "device_type": self.device_type,
                "raw": self.login_raw,
            },
            "device": {
                "ip": self.device_ip,
                "wifissid": self.wifissid,
                "4G": self.four_g,
                "imei": self.imei,
                "raw": self.getdevinfo_raw,
            },
            "session": {
                "via": self.via,
                "peer": self.peer,
                "loopback": self.loopback,
            },
            "clients": [],
            "client_list_available": False,
            "speculative": [
                {
                    "request": s.request,
                    "error": s.error,
                    "replies": s.replies,
                }
                for s in self.speculative
            ],
            "note": (
                "connectNum is a count only; GetDevInfo.ip is the camera; "
                "session.peer is this PPPP path (usually a relay). "
                "No standard cmd returns other viewers' IPs."
            ),
        }


def parse_login_dev(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize fields from a LoginDev JSON object.

    Returns keys: ``result``, ``connect_num``, ``device_type``, ``ok``.
    """
    result = _as_int(obj.get("result") if "result" in obj else obj.get("ret"))
    connect_num = _as_int(obj.get("connectNum") or obj.get("connect_num"))
    dt = obj.get("deviceType") or obj.get("devicetype")
    device_type = str(dt).strip() if dt is not None and str(dt).strip() else None
    ok = result == 0
    return {
        "result": result,
        "connect_num": connect_num,
        "device_type": device_type,
        "ok": ok,
    }


def parse_dev_info(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Pull network-ish fields from a GetDevInfo (or similar) object."""
    return {
        "device_ip": _str_or_none(obj.get("ip") or obj.get("ipAddress")),
        "wifissid": _str_or_none(obj.get("wifissid") or obj.get("wifiSsid")),
        "four_g": _as_int(obj.get("4G")),
        "imei": _str_or_none(
            obj.get("imei") or obj.get("IMEI") or obj.get("Imei")
        ),
    }


def peer_endpoint(session: PpppSession) -> Optional[str]:
    """``ip:port`` of the open session peer, or None."""
    if session.peer is None:
        return None
    return f"{session.peer.ip}:{session.peer.port}"


def collect_session_status(
    session: PpppSession,
    *,
    password: str = "",
    read_timeout: float = 5.0,
    probe_client_list: bool = False,
) -> SessionStatus:
    """LoginDev + GetDevInfo on an **already open** session.

    Does not open/close the session. Does not try password fallbacks — caller
    supplies the password to use for LoginDev.
    """
    via = getattr(session, "_via", None) or ""
    peer = peer_endpoint(session)
    loopback = bool(getattr(session, "loopback", False))

    login_raw = _first_cmd_dict(
        _safe_command(
            session,
            {"cmd": "LoginDev", "pwd": password or ""},
            read_timeout=read_timeout,
            expect_cmd="LoginDev",
        ),
        "LoginDev",
    )
    login_ok = False
    login_result: Optional[int] = None
    connect_num: Optional[int] = None
    device_type: Optional[str] = None
    if login_raw is not None:
        parsed = parse_login_dev(login_raw)
        login_result = parsed["result"]
        connect_num = parsed["connect_num"]
        device_type = parsed["device_type"]
        login_ok = bool(parsed["ok"])

    info_raw = _first_cmd_dict(
        _safe_command(
            session,
            {"cmd": "GetDevInfo"},
            read_timeout=read_timeout,
        ),
        "GetDevInfo",
    )
    device_ip = wifissid = imei = None
    four_g: Optional[int] = None
    if info_raw is not None:
        d = parse_dev_info(info_raw)
        device_ip = d["device_ip"]
        wifissid = d["wifissid"]
        four_g = d["four_g"]
        imei = d["imei"]

    speculative: List[CmdProbe] = []
    if probe_client_list:
        for obj in CLIENT_LIST_PROBES:
            speculative.append(
                _run_probe(session, obj, read_timeout=min(read_timeout, 2.5))
            )

    return SessionStatus(
        login_ok=login_ok,
        login_result=login_result,
        connect_num=connect_num,
        device_type=device_type,
        login_raw=login_raw,
        device_ip=device_ip,
        wifissid=wifissid,
        four_g=four_g,
        imei=imei,
        getdevinfo_raw=info_raw,
        peer=peer,
        via=via,
        loopback=loopback,
        speculative=speculative,
    )


def _safe_command(
    session: PpppSession,
    obj: Dict[str, Any],
    *,
    read_timeout: float,
    expect_cmd: Optional[str] = None,
) -> List[str]:
    try:
        return session.command(
            obj, read_timeout=read_timeout, expect_cmd=expect_cmd
        )
    except Exception:
        return []


def _run_probe(
    session: PpppSession, obj: Dict[str, Any], *, read_timeout: float
) -> CmdProbe:
    req = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    try:
        replies = session.command(obj, read_timeout=read_timeout)
    except Exception as e:
        return CmdProbe(request=obj, error=str(e))
    non_echo = [r for r in replies if r.strip() != req]
    if not non_echo:
        return CmdProbe(request=obj, error="no reply")
    return CmdProbe(request=obj, replies=non_echo)


def _first_cmd_dict(
    replies: List[str], cmd: str
) -> Optional[Dict[str, Any]]:
    for r in replies:
        try:
            obj = json.loads(r)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("cmd") == cmd:
            return obj
    for r in replies:
        try:
            obj = json.loads(r)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _as_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _str_or_none(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


__all__ = [
    "CLIENT_LIST_PROBES",
    "CmdProbe",
    "SessionStatus",
    "collect_session_status",
    "parse_dev_info",
    "parse_login_dev",
    "peer_endpoint",
]
