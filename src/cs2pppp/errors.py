"""Typed exception hierarchy for cs2pppp."""

from __future__ import annotations


class Cs2Error(Exception):
    """Base class for all cs2pppp errors."""


class ConfigError(Cs2Error):
    """Client misconfiguration, e.g. no directory servers supplied."""


class DirectoryError(Cs2Error):
    """Directory lookup failure: InvalidId, Offline when Online required, or timeout."""


class SessionError(Cs2Error):
    """Session open failure: relay/direct punch failed, or a loopback (self-echo)
    session was detected instead of a real device."""


class ProtocolError(Cs2Error):
    """Malformed frame or unexpected wire data."""


class AuthError(Cs2Error):
    """LoginDev rejected the supplied password."""


__all__ = [
    "Cs2Error",
    "ConfigError",
    "DirectoryError",
    "SessionError",
    "ProtocolError",
    "AuthError",
]
