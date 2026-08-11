"""Directory probe status enums and result object."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Status(enum.Enum):
    """Meaning of the directory ``MSG_P2P_REQ_ACK`` result byte."""

    ONLINE = "online"
    OFFLINE = "offline"
    INVALID_ID = "invalid_id"
    INVALID_PREFIX = "invalid_prefix"
    UNKNOWN = "unknown"

    @classmethod
    def from_code(cls, code: int) -> "Status":
        return _WIRE_MAP.get(code, cls.UNKNOWN)


# Directory result byte -> Status. Wire values per CS2 directory ACK.
_WIRE_MAP = {
    0x00: Status.ONLINE,
    0xFE: Status.OFFLINE,
    0xFF: Status.INVALID_ID,
    0xFD: Status.INVALID_PREFIX,
}


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of :meth:`cs2pppp.Cs2Client.probe`."""

    status: Status
    raw_code: int
    server: str

    @property
    def value(self) -> str:
        return self.status.value

    @property
    def online(self) -> bool:
        return self.status is Status.ONLINE

    @property
    def offline(self) -> bool:
        return self.status is Status.OFFLINE

    @property
    def invalid_id(self) -> bool:
        return self.status is Status.INVALID_ID

    @property
    def invalid_prefix(self) -> bool:
        return self.status is Status.INVALID_PREFIX

    def __str__(self) -> str:
        return f"{self.status.value} (0x{self.raw_code:02x} via {self.server})"


__all__ = ["Status", "ProbeResult"]
