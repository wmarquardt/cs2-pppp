"""The caller-facing client: directory servers are always injected here."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

from ._protocol import DIR_PORT
from .device import Device
from .did import to_real
from .errors import ConfigError
from .probe import probe as _probe
from .session import PpppSession
from .status import ProbeResult


@dataclass(frozen=True)
class DirectoryConfig:
    """Directory server configuration (hosts + port)."""

    servers: Tuple[str, ...]
    port: int = DIR_PORT

    def __post_init__(self) -> None:
        object.__setattr__(self, "servers", tuple(self.servers))
        if not self.servers:
            raise ConfigError("DirectoryConfig.servers must be non-empty")


class Cs2Client:
    """Entry point for probing and connecting to CS2/PPPP devices.

    The caller must supply directory servers — there are no built-in defaults.
    Obtain them by decoding your own InitString (:func:`decode_init_string`) or
    from your own configuration/env.
    """

    def __init__(
        self,
        servers: Optional[Sequence[str]] = None,
        *,
        directory: Optional[DirectoryConfig] = None,
        directory_port: int = DIR_PORT,
        timeout: float = 20.0,
        prefer: str = "relay",
    ) -> None:
        if directory is not None:
            cfg = directory
        elif servers:
            cfg = DirectoryConfig(tuple(servers), directory_port)
        else:
            raise ConfigError(
                "Cs2Client needs directory servers: pass servers=[...] or "
                "directory=DirectoryConfig(...). There are no built-in defaults."
            )
        self.directory = cfg
        self.timeout = timeout
        self.prefer = prefer

    @property
    def servers(self) -> Tuple[str, ...]:
        return self.directory.servers

    @property
    def port(self) -> int:
        return self.directory.port

    # --- probe ------------------------------------------------------------

    def probe(self, did: str, *, timeout: float = 2.5) -> ProbeResult:
        """Directory status probe (Online/Offline/InvalidId) — no session."""
        real = to_real(did) or did
        return _probe(real, self.servers, port=self.port, timeout=timeout)

    # --- session ----------------------------------------------------------

    def session(
        self, did: str, *, timeout: Optional[float] = None, prefer: Optional[str] = None
    ) -> PpppSession:
        """Open a low-level session (context manager). Returns it already open."""
        real = to_real(did) or did
        sess = PpppSession(real_did=real, servers=self.servers, port=self.port)
        sess.open(
            timeout=self.timeout if timeout is None else timeout,
            prefer=self.prefer if prefer is None else prefer,
        )
        return sess

    def device(
        self,
        did: str,
        *,
        password: str = "",
        timeout: Optional[float] = None,
        prefer: Optional[str] = None,
    ) -> Device:
        """High-level device handle (context manager). Opens on ``__enter__``."""
        real = to_real(did) or did
        return Device(
            real,
            self.servers,
            port=self.port,
            password=password,
            timeout=self.timeout if timeout is None else timeout,
            prefer=self.prefer if prefer is None else prefer,
        )


__all__ = ["Cs2Client", "DirectoryConfig"]
