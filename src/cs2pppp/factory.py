"""Factory reset via CS2 app JSON ``AppointDev`` ``state=2``.

Wipes device settings (including Wi‑Fi on typical firmware). Soft reboot
is :func:`cs2pppp.reboot.reboot` (``state=1``).

Protocol-only: caller supplies an already-open
:class:`~cs2pppp.session.PpppSession`. Confirmation policy (when it is
safe to fire) is the caller's job. No directory presets, no CLI.
"""

from __future__ import annotations

from typing import Optional

from .reboot import APPOINT_FACTORY, RebootResult, appoint
from .session import PpppSession

FactoryResult = RebootResult


def factory_reset(
    session: PpppSession,
    *,
    password: Optional[str] = None,
    read_timeout: float = 10.0,
    check_alive: bool = True,
) -> FactoryResult:
    """Fire ``AppointDev`` ``state=2`` on an **already open** session.

    Does not open/close the session. Optional ``password`` becomes the ``pwd``
    field; omit it (default) — tested firmwares accept factory reset without
    ``pwd``.
    """
    return appoint(
        session,
        APPOINT_FACTORY,
        password=password,
        read_timeout=read_timeout,
        check_alive=check_alive,
        refuse_loopback="loopback session — refusing factory reset",
    )


__all__ = [
    "APPOINT_FACTORY",
    "FactoryResult",
    "factory_reset",
]
