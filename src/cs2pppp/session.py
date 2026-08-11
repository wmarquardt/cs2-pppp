"""Pure-Python CS2 PPPP UDP session state machine.

Default open path prefers the directory relay (direct hole-punch often fails on
CGNAT). Validated live against CS2/mykj-style devices:

1. MSG_HELLO -> HELLO_ACK (WAN mapping)
2. MSG_P2P_REQ first (wake/notify the device)
3. LIST -> RLY_HELLO/RLY_PORT -> RLY_REQ -> RLY_PKT with is_dev=0 (client only)
4. MSG_RLY_RDY from the relay-allocated port
5. MSG_REPORT_SESSION_RDY (0xF9), encrypted with the CS2 session key
6. MSG_ALIVE / ALIVE_ACK
7. MSG_DRW / DRW_ACK for app JSON

Directory servers are always supplied by the caller — this module ships no
server list and no route presets.
"""

from __future__ import annotations

import json
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from ._protocol import (
    DIR_PORT,
    DRW_MAGIC,
    MAGIC,
    SESSION_RDY_BODY_LEN,
    header,
    pack_sockaddr,
    pack_uid,
    parse_sockaddr,
)
from .crypto import CS2_SESSION_KEY, prop_dec, prop_enc
from .errors import ConfigError, SessionError
from .framing import encode_json, extract_json_strings, local_timezone_hours

MSG_HELLO = 0x00
MSG_HELLO_ACK = 0x01
MSG_P2P_REQ = 0x20
MSG_P2P_REQ_ACK = 0x21
MSG_PUNCH_TO = 0x40
MSG_PUNCH_PKT = 0x41
MSG_P2P_RDY = 0x42
MSG_LIST_REQ1 = 0x67
MSG_LIST_REQ = 0x68
MSG_LIST_REQ_ACK = 0x69
MSG_RLY_HELLO = 0x70
MSG_RLY_PORT = 0x72
MSG_RLY_PORT_ACK = 0x73
MSG_RLY_REQ = 0x80
MSG_RLY_REQ_ACK = 0x81
MSG_RLY_TO = 0x82
MSG_RLY_PKT = 0x83
MSG_RLY_RDY = 0x84
MSG_DRW = 0xD0
MSG_DRW_ACK = 0xD1
MSG_ALIVE = 0xE0
MSG_ALIVE_ACK = 0xE1
MSG_CLOSE = 0xF0
MSG_REPORT_SESSION_RDY = 0xF9


@dataclass
class PeerEndpoint:
    ip: str
    port: int


@dataclass
class PpppSession:
    """One UDP session to a single device. Prefer the ``Cs2Client`` factories."""

    real_did: str
    servers: Tuple[str, ...] = ()
    port: int = DIR_PORT
    sock: Optional[socket.socket] = None
    peer: Optional[PeerEndpoint] = None
    our_wan: Optional[PeerEndpoint] = None
    drw_index: int = 0
    punch_targets: List[PeerEndpoint] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    _uid: bytes = b""
    _via: str = ""  # "direct" | "relay"
    # True when RLY_RDY needed is_dev=1 (same UDP source plays both roles); DRW
    # then echoes our own payloads — not a real camera session.
    loopback: bool = False
    _rsr_marker: bytes = b""

    def _log(self, msg: str) -> None:
        self.log.append(msg)

    def _send(self, data: bytes, addr: Tuple[str, int]) -> None:
        assert self.sock
        try:
            self.sock.sendto(data, addr)
        except OSError as e:
            self._log(f"send error {addr}: {e}")

    def _recv(self, timeout: float = 0.4) -> List[Tuple[bytes, Tuple[str, int]]]:
        assert self.sock
        self.sock.settimeout(timeout)
        out: List[Tuple[bytes, Tuple[str, int]]] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = self.sock.recvfrom(65535)
                out.append((data, addr))
            except socket.timeout:
                break
            except BlockingIOError:
                break
        return out

    # --- open -------------------------------------------------------------

    def open(self, *, timeout: float = 20.0, prefer: str = "relay") -> None:
        if not self.servers:
            raise ConfigError("no directory servers supplied")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self._uid = pack_uid(self.real_did)
        local_port = self.sock.getsockname()[1]

        for ip in self.servers:
            self._send(header(MSG_HELLO, 0), (ip, self.port))
        for data, addr in self._recv(1.5):
            if len(data) >= 20 and data[0] == MAGIC and data[1] == MSG_HELLO_ACK:
                ip, port = parse_sockaddr(data[4:20])
                self.our_wan = PeerEndpoint(ip, port)
                self._log(f"HELLO_ACK wan={ip}:{port} via {addr[0]}")
                break

        if prefer == "relay":
            try:
                self._wake_device(local_port, wait=3.0)
                self._open_relay(timeout=timeout)
                return
            except SessionError as e:
                self._log(f"relay failed: {e}; trying direct")
            try:
                self._open_direct(local_port, timeout=min(timeout, 12.0))
                return
            except SessionError as e:
                raise SessionError(f"relay+direct failed: {e}") from e
        else:
            try:
                self._open_direct(local_port, timeout=min(timeout, 12.0))
                return
            except SessionError as e:
                self._log(f"direct failed: {e}; trying relay")
            self._wake_device(local_port, wait=2.0)
            self._open_relay(timeout=timeout)

    def _open_direct(self, local_port: int, *, timeout: float) -> None:
        assert self.sock and self._uid
        if self.our_wan:
            sa = pack_sockaddr(self.our_wan.ip, self.our_wan.port)
        else:
            sa = pack_sockaddr("0.0.0.0", local_port)
        req = header(MSG_P2P_REQ, 36) + self._uid + sa
        for ip in self.servers:
            self._send(req, (ip, self.port))
        self._log("P2P_REQ sent")

        deadline = time.time() + timeout
        last_punch = 0.0
        online = False
        while time.time() < deadline:
            now = time.time()
            if self.punch_targets and now - last_punch > 0.25:
                self._send_punches()
                last_punch = now
            for data, addr in self._recv(0.3):
                if len(data) < 2 or data[0] != MAGIC:
                    continue
                t = data[1]
                if t == MSG_P2P_REQ_ACK and len(data) >= 5:
                    if data[4] == 0x00:
                        online = True
                        self._log(f"P2P_REQ_ACK online via {addr[0]}")
                    else:
                        raise SessionError(f"directory result 0x{data[4]:02x}")
                elif t == MSG_PUNCH_TO and len(data) >= 20:
                    ip, port = parse_sockaddr(data[4:20])
                    ep = PeerEndpoint(ip, port)
                    if ep not in self.punch_targets:
                        self.punch_targets.append(ep)
                        self._log(f"PUNCH_TO {ip}:{port}")
                    self._send_punches()
                elif t in (MSG_PUNCH_PKT, MSG_P2P_RDY, MSG_ALIVE, MSG_DRW):
                    self.peer = PeerEndpoint(addr[0], addr[1])
                    self._via = "direct"
                    self._log(f"direct peer {self.peer.ip}:{self.peer.port} type=0x{t:02x}")
                    self._alive_burst()
                    return
        raise SessionError(
            f"direct timeout online={online} "
            f"punches={[(p.ip, p.port) for p in self.punch_targets]}"
        )

    def _send_punches(self) -> None:
        pkt = header(MSG_PUNCH_PKT, 20) + self._uid
        for t in self.punch_targets:
            for d in range(-3, 4):
                port = t.port + d
                if 1 <= port <= 65535:
                    self._send(pkt, (t.ip, port))

    def _wake_device(self, local_port: int, *, wait: float = 3.0) -> None:
        """MSG_P2P_REQ so the directory notifies the device.

        Without this, a client-only relay path (is_dev=0) rarely gets RLY_RDY.
        """
        assert self.sock and self._uid
        if self.our_wan:
            sa = pack_sockaddr(self.our_wan.ip, self.our_wan.port)
        else:
            sa = pack_sockaddr("0.0.0.0", local_port)
        req = header(MSG_P2P_REQ, 36) + self._uid + sa
        for ip in self.servers:
            self._send(req, (ip, self.port))
        self._log("P2P_REQ wake sent")
        deadline = time.time() + wait
        while time.time() < deadline:
            for data, addr in self._recv(0.35):
                if len(data) < 2 or data[0] != MAGIC:
                    continue
                t = data[1]
                if t == MSG_P2P_REQ_ACK and len(data) >= 5:
                    self._log(f"P2P_REQ_ACK 0x{data[4]:02x} via {addr[0]}")
                elif t == MSG_PUNCH_TO and len(data) >= 20:
                    ip, port = parse_sockaddr(data[4:20])
                    ep = PeerEndpoint(ip, port)
                    if ep not in self.punch_targets:
                        self.punch_targets.append(ep)
                        self._log(f"PUNCH_TO {ip}:{port}")
                    self._send_punches()
            if self.punch_targets:
                self._send_punches()

    def _open_relay(self, *, timeout: float) -> None:
        assert self.sock and self._uid
        for ip in self.servers:
            self._send(header(MSG_LIST_REQ1, 20) + self._uid, (ip, self.port))
            self._send(header(MSG_LIST_REQ, 0), (ip, self.port))

        relays: List[PeerEndpoint] = []
        for data, addr in self._recv(3.0):
            if len(data) < 2 or data[0] != MAGIC:
                continue
            t = data[1]
            if t == MSG_LIST_REQ_ACK and len(data) >= 8:
                n = data[4]
                off = 8
                for _ in range(n):
                    if off + 16 > len(data):
                        break
                    ip, port = parse_sockaddr(data[off : off + 16])
                    ep = PeerEndpoint(ip, port)
                    if ep not in relays:
                        relays.append(ep)
                    off += 16
            elif t == MSG_RLY_TO and len(data) >= 20:
                ip, port = parse_sockaddr(data[4:20])
                ep = PeerEndpoint(ip, port)
                if ep not in relays:
                    relays.append(ep)

        self._log(f"relays={len(relays)}")
        if not relays:
            raise SessionError("no relays from LIST_REQ")

        deadline = time.time() + timeout
        errors: List[str] = []
        # First pass client-only (real device); second pass loopback fallback.
        for allow_loopback in (False, True):
            for rel in relays:
                if time.time() > deadline:
                    break
                try:
                    if self._try_one_relay(rel, deadline, allow_loopback=allow_loopback):
                        return
                except SessionError as e:
                    errors.append(f"{rel.ip}:{rel.port}:lb={allow_loopback}:{e}")
                    continue
        raise SessionError("all relays failed: " + "; ".join(errors[:8]))

    def _try_one_relay(
        self, rel: PeerEndpoint, deadline: float, *, allow_loopback: bool = True
    ) -> bool:
        assert self.sock and self._uid
        rip, rport = rel.ip, rel.port
        self._send(header(MSG_RLY_HELLO, 0), (rip, rport))
        self._send(header(MSG_RLY_PORT, 0), (rip, rport))

        magic: Optional[bytes] = None
        aport: Optional[int] = None
        for data, addr in self._recv(2.0):
            if (
                len(data) >= 12
                and data[0] == MAGIC
                and data[1] == MSG_RLY_PORT_ACK
                and addr[0] == rip
            ):
                magic = data[4:8]
                aport = struct.unpack(">H", data[8:10])[0]
                self._log(f"RLY_PORT_ACK {rip} magic={magic.hex()} aport={aport}")
                break
        if not magic or not aport:
            raise SessionError("no RLY_PORT_ACK")

        body = self._uid + pack_sockaddr(rip, rport) + magic
        body_aport = self._uid + pack_sockaddr(rip, aport) + magic
        for ip in self.servers:
            self._send(header(MSG_RLY_REQ, 40) + body, (ip, self.port))
            self._send(header(MSG_RLY_REQ, 40) + body_aport, (ip, self.port))

        ok = False
        for data, addr in self._recv(2.5):
            if len(data) < 2 or data[0] != MAGIC:
                continue
            if data[1] == MSG_RLY_REQ_ACK and len(data) >= 5 and data[4] == 0:
                ok = True
                self._log(f"RLY_REQ_ACK ok via {addr[0]}")
            if data[1] == MSG_RLY_RDY and addr[0] == rip:
                self.peer = PeerEndpoint(addr[0], addr[1])
                self._via = "relay"
                self.loopback = False
                self._log(f"early RLY_RDY {self.peer.ip}:{self.peer.port}")
                self._alive_burst()
                return True
        if not ok:
            raise SessionError("RLY_REQ failed")

        phases: List[Tuple[str, Tuple[int, ...], float, bool]] = [
            ("client", (0,), 8.0, False),
        ]
        if allow_loopback:
            phases.append(("loopback", (0, 1), 3.0, True))
        for phase, flags, wait, loopback in phases:
            if time.time() >= deadline:
                break
            self._log(f"RLY_PKT phase={phase} flags={flags}")
            t0 = time.time()
            last_req = 0.0
            while time.time() < min(deadline, t0 + wait):
                for flag in flags:
                    pkt = magic + self._uid + bytes([flag, 0, 0, 0])
                    self._send(header(MSG_RLY_PKT, 28) + pkt, (rip, rport))
                    self._send(header(MSG_RLY_PKT, 28) + pkt, (rip, aport))
                now = time.time()
                if now - last_req > 1.5:
                    for ip in self.servers:
                        self._send(header(MSG_RLY_REQ, 40) + body, (ip, self.port))
                    last_req = now
                for data, addr in self._recv(0.25):
                    if len(data) < 2 or data[0] != MAGIC:
                        continue
                    t = data[1]
                    if t in (MSG_RLY_TO, MSG_RLY_PORT_ACK, MSG_RLY_REQ_ACK):
                        continue
                    if t == MSG_RLY_RDY and addr[0] == rip:
                        self.peer = PeerEndpoint(addr[0], addr[1])
                        self._via = "relay"
                        self.loopback = loopback
                        self._log(
                            f"RLY_RDY peer={self.peer.ip}:{self.peer.port} "
                            f"phase={phase} loopback={loopback}"
                        )
                        self._alive_burst()
                        return True
                    if (
                        t
                        in (
                            MSG_PUNCH_PKT,
                            MSG_P2P_RDY,
                            MSG_ALIVE,
                            MSG_DRW,
                            MSG_REPORT_SESSION_RDY,
                        )
                        and addr[0] == rip
                    ):
                        self.peer = PeerEndpoint(addr[0], addr[1])
                        self._via = "relay"
                        self.loopback = loopback
                        self._log(
                            f"relay peer via 0x{t:02x} {self.peer.ip}:{self.peer.port} "
                            f"phase={phase} loopback={loopback}"
                        )
                        self._alive_burst()
                        return True
        raise SessionError(
            "timeout waiting RLY_RDY "
            f"(client-only empty; loopback={'tried' if allow_loopback else 'skipped'})"
        )

    def _build_report_session_rdy(self) -> bytes:
        body = bytearray(SESSION_RDY_BODY_LEN)
        body[0:20] = self._uid
        if self.our_wan:
            body[0x28 : 0x28 + 16] = pack_sockaddr(self.our_wan.ip, self.our_wan.port)
        if self.peer:
            body[0x38 : 0x38 + 16] = pack_sockaddr(self.peer.ip, self.peer.port)
        if not self._rsr_marker:
            self._rsr_marker = struct.pack(">I", int(time.time()) & 0xFFFFFFFF)
        body[0x50:0x54] = self._rsr_marker
        ct = prop_enc(bytes(body), CS2_SESSION_KEY)
        return header(MSG_REPORT_SESSION_RDY, len(ct)) + ct

    def _alive_burst(self) -> None:
        if not self.peer or not self._uid:
            return
        peer = (self.peer.ip, self.peer.port)
        self._send(header(MSG_RLY_RDY, 20) + self._uid, peer)
        self._send(header(MSG_P2P_RDY, 20) + self._uid, peer)
        self._send(header(MSG_PUNCH_PKT, 20) + self._uid, peer)
        rsr = self._build_report_session_rdy()
        self._send(rsr, peer)
        self._log(f"REPORT_SESSION_RDY len={len(rsr)}")
        for _ in range(8):
            self._send(header(MSG_ALIVE, 0), peer)

        answered_rdy = False
        peer_rsr = False
        alive_acks = 0
        last_rsr = time.time()
        deadline = time.time() + 6.0
        while time.time() < deadline:
            now = time.time()
            if now - last_rsr > 2.0:
                self._send(rsr, peer)
                self._send(header(MSG_ALIVE, 0), peer)
                last_rsr = now
            for data, addr in self._recv(0.35):
                if len(data) < 2 or data[0] != MAGIC:
                    continue
                t = data[1]
                if t == MSG_ALIVE:
                    self._send(header(MSG_ALIVE_ACK, 0), addr)
                elif t == MSG_ALIVE_ACK:
                    alive_acks += 1
                elif t == MSG_REPORT_SESSION_RDY:
                    try:
                        pt = prop_dec(data[4:])
                        if self._rsr_marker and self._rsr_marker in pt:
                            self.loopback = True
                            self._log("REPORT_SESSION_RDY contains our marker -> loopback")
                        else:
                            peer_rsr = True
                    except Exception:
                        peer_rsr = True
                    self._send(rsr, addr)
                elif t in (MSG_RLY_RDY, MSG_P2P_RDY) and not answered_rdy:
                    self._send(header(MSG_RLY_RDY, 20) + self._uid, addr)
                    self._send(header(MSG_P2P_RDY, 20) + self._uid, addr)
                    answered_rdy = True
                elif t == MSG_PUNCH_PKT:
                    self._send(header(MSG_PUNCH_PKT, 20) + self._uid, addr)
                    self._send(header(MSG_P2P_RDY, 20) + self._uid, addr)
        self._log(
            f"handshake settle peer_rsr={peer_rsr} alive_acks={alive_acks} "
            f"loopback={self.loopback}"
        )

    # --- app channel ------------------------------------------------------

    def ensure_app_channel(self, *, timeout: float = 12.0, probes: int = 4) -> bool:
        """Probe GetDevInfo until a real JSON reply (app channel live)."""
        if not self.sock or not self.peer:
            return False
        deadline = time.time() + timeout
        n = 0
        while time.time() < deadline and n < probes:
            n += 1
            replies = self.command(
                {"cmd": "GetDevInfo"},
                read_timeout=min(5.0, max(2.0, timeout / probes)),
            )
            if replies:
                self._log(f"app channel OK after probe #{n}")
                return True
            self._send(header(MSG_ALIVE, 0), (self.peer.ip, self.peer.port))
            time.sleep(0.4)
        return False

    def send_json(
        self,
        obj: Union[Dict[str, Any], str],
        *,
        channel: int = 1,
        timezone_hours: Optional[int] = None,
    ) -> int:
        """Frame and send a single app-channel JSON command (no wait for reply)."""
        if not self.sock or not self.peer:
            raise SessionError("session not open")
        text = (
            json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            if isinstance(obj, dict)
            else obj
        )
        tz = local_timezone_hours() if timezone_hours is None else timezone_hours
        framed = encode_json(text, timezone_hours=tz)
        idx = self.drw_index & 0xFFFF
        self.drw_index = (self.drw_index + 1) & 0xFFFF
        sub = bytes([DRW_MAGIC, channel & 0xFF]) + struct.pack(">H", idx)
        body = sub + framed
        self._send(header(MSG_DRW, len(body)) + body, (self.peer.ip, self.peer.port))
        return idx

    def _drw_packet(self, framed: bytes, *, channel: int, idx: int) -> bytes:
        sub = bytes([DRW_MAGIC, channel & 0xFF]) + struct.pack(">H", idx & 0xFFFF)
        body = sub + framed
        return header(MSG_DRW, len(body)) + body

    def recv(
        self,
        *,
        timeout: float = 4.0,
        max_pkts: int = 64,
        skip_echo_of: Optional[bytes] = None,
        pending_pkt: Optional[bytes] = None,
        expect_cmd: Optional[str] = None,
    ) -> List[str]:
        """Receive app-channel JSON replies. Returns a list of JSON strings."""
        if not self.sock or not self.peer:
            raise SessionError("session not open")
        replies: List[str] = []
        deadline = time.time() + timeout
        n = 0
        last_retx = 0.0
        # Relay may DRW_ACK before the app processes the command; keep
        # retransmitting until real app JSON arrives or the timeout ends.
        while time.time() < deadline and n < max_pkts:
            now = time.time()
            if pending_pkt and now - last_retx > 0.55:
                self._send(pending_pkt, (self.peer.ip, self.peer.port))
                last_retx = now
            self._send(header(MSG_ALIVE, 0), (self.peer.ip, self.peer.port))
            for data, addr in self._recv(0.45):
                if len(data) < 2 or data[0] != MAGIC:
                    continue
                t = data[1]
                if t == MSG_ALIVE:
                    self._send(header(MSG_ALIVE_ACK, 0), addr)
                    continue
                if t in (MSG_ALIVE_ACK, MSG_RLY_RDY, MSG_RLY_PKT, MSG_P2P_RDY,
                         MSG_PUNCH_PKT, MSG_DRW_ACK):
                    continue
                if t == MSG_DRW and len(data) >= 8:
                    n += 1
                    self.peer = PeerEndpoint(addr[0], addr[1])
                    idx = struct.unpack_from(">H", data, 6)[0]
                    ch = data[5]
                    ack = (
                        header(MSG_DRW_ACK, 6)
                        + bytes([DRW_MAGIC, ch, 0x00, 0x01])
                        + struct.pack(">H", idx)
                    )
                    self._send(ack, addr)
                    payload = data[8:]
                    if skip_echo_of and skip_echo_of[:16] in payload:
                        continue
                    got: List[str] = []
                    for j in extract_json_strings(payload):
                        got.append(j)
                    for j in extract_json_strings(data[4:]):
                        if j not in got:
                            got.append(j)
                    for j in got:
                        if j in replies:
                            continue
                        if expect_cmd is not None and not re.search(
                            r'"cmd"\s*:\s*"%s"' % re.escape(expect_cmd), j
                        ):
                            continue
                        replies.append(j)
                    if replies:
                        drain_end = time.time() + 0.3
                        while time.time() < drain_end:
                            for data2, _a2 in self._recv(0.12):
                                if (
                                    len(data2) >= 8
                                    and data2[0] == MAGIC
                                    and data2[1] == MSG_DRW
                                ):
                                    for j in extract_json_strings(data2[8:]):
                                        if j in replies:
                                            continue
                                        if expect_cmd is not None and not re.search(
                                            r'"cmd"\s*:\s*"%s"' % re.escape(expect_cmd),
                                            j,
                                        ):
                                            continue
                                        replies.append(j)
                        return replies
                if t == MSG_CLOSE:
                    return replies
        return replies

    def command(
        self,
        obj: Dict[str, Any],
        *,
        read_timeout: float = 4.0,
        channel: int = 1,
        timezone_hours: Optional[int] = None,
        expect_cmd: Optional[str] = None,
    ) -> List[str]:
        """Send a JSON command and return the app-channel JSON replies."""
        if not self.sock or not self.peer:
            raise SessionError("session not open")
        text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        tz = local_timezone_hours() if timezone_hours is None else timezone_hours
        framed = encode_json(text, timezone_hours=tz)
        idx = self.drw_index & 0xFFFF
        self.drw_index = (self.drw_index + 1) & 0xFFFF
        pkt = self._drw_packet(framed, channel=channel, idx=idx)
        self._send(pkt, (self.peer.ip, self.peer.port))
        want = expect_cmd
        if want is None:
            c = obj.get("cmd")
            want = c if isinstance(c, str) else None
        return self.recv(
            timeout=read_timeout, skip_echo_of=framed, pending_pkt=pkt, expect_cmd=want
        )

    def request_json(
        self, obj: Dict[str, Any], *, read_timeout: float = 4.0
    ) -> List[Dict[str, Any]]:
        """Like :meth:`command` but parse replies into dicts (bad JSON dropped)."""
        out: List[Dict[str, Any]] = []
        for s in self.command(obj, read_timeout=read_timeout):
            try:
                out.append(json.loads(s))
            except json.JSONDecodeError:
                continue
        return out

    def alive(self) -> None:
        """Send a single keepalive to the peer."""
        if not self.sock or not self.peer:
            raise SessionError("session not open")
        self._send(header(MSG_ALIVE, 0), (self.peer.ip, self.peer.port))

    def close(self) -> None:
        if self.sock and self.peer:
            try:
                self._send(header(MSG_CLOSE, 0), (self.peer.ip, self.peer.port))
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def __enter__(self) -> "PpppSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["PpppSession", "PeerEndpoint"]
