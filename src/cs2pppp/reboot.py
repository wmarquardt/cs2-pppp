"""Soft reboot via CS2 app JSON ``AppointDev`` ``state=1``.

Does **not** wipe pairing or Wi‑Fi. Factory reset is
:func:`cs2pppp.factory.factory_reset` (``state=2``).

This module is protocol-only: caller supplies an already-open
:class:`~cs2pppp.session.PpppSession`. No directory presets, no CLI.
A dead P2P path cannot reboot the device remotely.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .session import PpppSession

# Soft-reboot state used by CS2-style app JSON (not factory reset).
APPOINT_REBOOT = 1
# Shared with :mod:`cs2pppp.factory` (wipe). Keep the constants together.
APPOINT_FACTORY = 2


@dataclass
class RebootResult:
    """Outcome of one ``AppointDev`` ``state=1`` attempt."""

    fired: bool = False
    likely_ok: bool = False
    appoint_reply: Optional[str] = None
    appoint_state: Optional[int] = None
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fired": self.fired,
            "likely_ok": self.likely_ok,
            "appoint_reply": self.appoint_reply,
            "appoint_state": self.appoint_state,
            "error": self.error,
            "notes": list(self.notes),
        }


def parse_appoint_reply(text: str) -> Optional[Dict[str, Any]]:
    """Parse one app-JSON reply; return the object if it looks like AppointDev."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    cmd = obj.get("cmd")
    if cmd is not None and cmd != "AppointDev":
        return None
    return obj


def _first_appoint_raw(replies: List[str]) -> Optional[str]:
    for r in replies:
        if re.search(r'"cmd"\s*:\s*"AppointDev"', r):
            return r
    return replies[0] if replies else None


def appoint(
    session: PpppSession,
    state: int,
    *,
    password: Optional[str] = None,
    read_timeout: float = 10.0,
    check_alive: bool = True,
    refuse_loopback: str = "loopback session — refusing",
) -> RebootResult:
    """Fire ``AppointDev`` with ``state`` on an **already open** session.

    Does not open/close the session. Optional ``password`` becomes the ``pwd``
    field; omit it (default) — tested firmwares accept AppointDev without
    ``pwd``.

    ``likely_ok`` is True when the device answers AppointDev, the channel dies
    mid-flight (typical while restarting), or a follow-up GetDevInfo is silent.
    """
    result = RebootResult()
    if getattr(session, "loopback", False):
        result.error = refuse_loopback
        result.notes.append("loopback")
        return result
    if not getattr(session, "sock", None) or not getattr(session, "peer", None):
        result.error = "session not open"
        return result

    obj: Dict[str, Any] = {"cmd": "AppointDev", "state": state}
    if password is not None:
        obj["pwd"] = password

    try:
        replies = session.command(obj, read_timeout=read_timeout)
    except Exception as e:
        # Packet may have been accepted; device often drops the socket next.
        result.fired = True
        result.likely_ok = True
        result.notes.append(f"command error after send: {e}")
        return result

    result.fired = True
    raw = _first_appoint_raw(replies)
    result.appoint_reply = raw
    parsed = parse_appoint_reply(raw) if raw else None
    if parsed and "state" in parsed:
        try:
            result.appoint_state = int(parsed["state"])
        except (TypeError, ValueError):
            result.appoint_state = None

    if parsed is not None and parsed.get("cmd") == "AppointDev":
        result.likely_ok = True
        result.notes.append(f"appoint reply state={result.appoint_state}")
    elif raw is None:
        result.notes.append("no appoint reply")
    else:
        result.notes.append(f"appoint raw={raw[:120]!r}")

    if check_alive:
        try:
            post = session.command(
                {"cmd": "GetDevInfo"}, read_timeout=min(3.0, read_timeout)
            )
        except Exception:
            post = []
        if not post:
            result.notes.append("post GetDevInfo silent (expected if rebooting)")
            result.likely_ok = True
        else:
            result.notes.append("post GetDevInfo still answering")

    return result


def reboot(
    session: PpppSession,
    *,
    password: Optional[str] = None,
    read_timeout: float = 10.0,
    check_alive: bool = True,
) -> RebootResult:
    """Fire ``AppointDev`` ``state=1`` on an **already open** session.

    Does not open/close the session. Optional ``password`` becomes the ``pwd``
    field; omit it (default) — tested firmwares accept reboot without ``pwd``.

    ``likely_ok`` is True when the device answers AppointDev, the channel dies
    mid-flight (typical while rebooting), or a follow-up GetDevInfo is silent.
    """
    return appoint(
        session,
        APPOINT_REBOOT,
        password=password,
        read_timeout=read_timeout,
        check_alive=check_alive,
        refuse_loopback="loopback session — refusing reboot",
    )


__all__ = [
    "APPOINT_FACTORY",
    "APPOINT_REBOOT",
    "RebootResult",
    "appoint",
    "parse_appoint_reply",
    "reboot",
]
