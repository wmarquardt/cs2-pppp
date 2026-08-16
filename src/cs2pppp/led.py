"""IR / night illuminator via CS2 app JSON ``SetLed``.

Live-view LED toggle (one-way in the app):

    {"cmd": "SetLed", "ledstatus": 1}   # on
    {"cmd": "SetLed", "ledstatus": 0}   # off

Field name is ``ledstatus`` (lowercase). The app does not wait for a typed
reply; silence after send is the expected success path.

Protocol-only: caller supplies an already-open
:class:`~cs2pppp.session.PpppSession`. No directory presets, no CLI.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .session import PpppSession

LED_ON = 1
LED_OFF = 0


@dataclass
class SetLedResult:
    """Outcome of one ``SetLed`` attempt."""

    fired: bool = False
    likely_ok: bool = False
    enabled: bool = False
    ledstatus: int = LED_OFF
    reply: Optional[str] = None
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fired": self.fired,
            "likely_ok": self.likely_ok,
            "enabled": self.enabled,
            "ledstatus": self.ledstatus,
            "reply": self.reply,
            "error": self.error,
            "notes": list(self.notes),
        }


def parse_set_led_reply(text: str) -> Optional[Dict[str, Any]]:
    """Parse one app-JSON reply; return the object if it looks like SetLed."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    cmd = obj.get("cmd")
    if cmd is not None and cmd != "SetLed":
        return None
    return obj


def _first_set_led_raw(replies: List[str]) -> Optional[str]:
    for r in replies:
        if re.search(r'"cmd"\s*:\s*"SetLed"', r):
            return r
    return replies[0] if replies else None


def set_led(
    session: PpppSession,
    enabled: bool,
    *,
    read_timeout: float = 4.0,
    refuse_loopback: str = "loopback session — refusing SetLed",
) -> SetLedResult:
    """Fire ``SetLed`` on an **already open** session.

    Does not open/close the session. ``enabled=True`` sends ``ledstatus=1``.

    ``likely_ok`` is True when the send completes. A missing reply is normal
    (one-way in the app). A socket error after send is treated as fired but
    outcome unclear — unlike reboot, the channel should stay up.
    """
    result = SetLedResult()
    result.enabled = bool(enabled)
    result.ledstatus = LED_ON if enabled else LED_OFF
    if getattr(session, "loopback", False):
        result.error = refuse_loopback
        result.notes.append("loopback")
        return result
    if not getattr(session, "sock", None) or not getattr(session, "peer", None):
        result.error = "session not open"
        return result

    obj: Dict[str, Any] = {"cmd": "SetLed", "ledstatus": result.ledstatus}

    try:
        replies = session.command(obj, read_timeout=read_timeout)
    except Exception as e:
        result.fired = True
        result.notes.append(f"command error after send: {e}")
        return result

    result.fired = True
    result.likely_ok = True
    raw = _first_set_led_raw(replies)
    result.reply = raw
    parsed = parse_set_led_reply(raw) if raw else None
    if parsed is not None:
        result.notes.append(f"setled reply={raw[:120]!r}" if raw else "setled reply")
        status = parsed.get("ledstatus", parsed.get("state"))
        if status is not None:
            try:
                result.ledstatus = int(status)
                result.enabled = result.ledstatus != LED_OFF
            except (TypeError, ValueError):
                pass
    else:
        result.notes.append("no SetLed reply (one-way; expected)")

    return result


def ir_on(
    session: PpppSession,
    *,
    read_timeout: float = 4.0,
) -> SetLedResult:
    """Turn the IR / night LED on (``ledstatus=1``)."""
    return set_led(session, True, read_timeout=read_timeout)


def ir_off(
    session: PpppSession,
    *,
    read_timeout: float = 4.0,
) -> SetLedResult:
    """Turn the IR / night LED off (``ledstatus=0``)."""
    return set_led(session, False, read_timeout=read_timeout)


__all__ = [
    "LED_OFF",
    "LED_ON",
    "SetLedResult",
    "ir_off",
    "ir_on",
    "parse_set_led_reply",
    "set_led",
]
