"""Single-shot directory status probe (no full session).

Sends ``MSG_P2P_REQ`` to each supplied directory server and maps the
``MSG_P2P_REQ_ACK`` result byte to a :class:`~cs2pppp.status.Status`.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional, Sequence

from ._protocol import DIR_PORT, MAGIC, MSG_P2P_REQ, MSG_P2P_REQ_ACK, pack_uid
from .errors import DirectoryError
from .status import ProbeResult, Status


def build_p2p_req(real_did: str) -> bytes:
    """MSG_P2P_REQ probe packet: header + uid(20) + sockaddr_in(16).

    The single-shot probe uses a zeroed sockaddr (family LE, 0.0.0.0:0).
    """
    uid = pack_uid(real_did)
    sockaddr = struct.pack("<HH", 2, 0) + socket.inet_aton("0.0.0.0") + b"\x00" * 8
    header = struct.pack(">BBH", MAGIC, MSG_P2P_REQ, 36)
    return header + uid + sockaddr


def parse_p2p_req_ack(data: bytes) -> Optional[int]:
    """Return the result byte from MSG_P2P_REQ_ACK, or None if not an ACK."""
    if len(data) < 5 or data[0] != MAGIC or data[1] != MSG_P2P_REQ_ACK:
        return None
    return data[4]


def probe(
    real_did: str,
    servers: Sequence[str],
    *,
    port: int = DIR_PORT,
    timeout: float = 2.5,
) -> ProbeResult:
    """Probe ``real_did`` against ``servers``; return the first definitive answer.

    Raises :class:`~cs2pppp.errors.DirectoryError` if no server responds.
    """
    if not servers:
        raise DirectoryError("no directory servers supplied")
    pkt = build_p2p_req(real_did)
    errors = []
    for ip in servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (ip, port))
            data, _addr = sock.recvfrom(4096)
        except OSError as e:
            errors.append(f"{ip}: {e}")
            continue
        finally:
            sock.close()
        result = parse_p2p_req_ack(data)
        if result is None:
            errors.append(f"{ip}: no ACK")
            continue
        return ProbeResult(Status.from_code(result), result, ip)
    raise DirectoryError("no directory response; " + "; ".join(errors[:4]))


__all__ = ["probe", "build_p2p_req", "parse_p2p_req_ack"]
