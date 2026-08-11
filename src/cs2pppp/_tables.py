"""Caller-injected protocol tables.

This library ships **no** byte tables. The InitString decode LUT and the two
cipher tables (S-box + CRC table) are the caller's responsibility — supply them
the same way you supply directory servers, via :func:`configure_tables` or
environment variables.

Each table is a fixed-length byte string the caller provides from their own
configuration:

======================  =========================  =======
name                    environment variable       length
======================  =========================  =======
``lut``                 ``CS2PPPP_LUT``            54
``prop_table``          ``CS2PPPP_PROP_TABLE``     256
``crc_table``           ``CS2PPPP_CRC_TABLE``      64
======================  =========================  =======

Values may be given as ``bytes`` or as a hex string (env vars are hex).
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Union

from .errors import ConfigError

_SPEC = {
    "lut": ("CS2PPPP_LUT", 54),
    "prop_table": ("CS2PPPP_PROP_TABLE", 256),
    "crc_table": ("CS2PPPP_CRC_TABLE", 64),
}

_overrides: Dict[str, bytes] = {}


def _coerce(value: Union[bytes, bytearray, str], length: int, name: str) -> bytes:
    if isinstance(value, str):
        try:
            b = bytes.fromhex(value.strip())
        except ValueError as e:
            raise ConfigError(f"{name} table is not valid hex: {e}") from e
    else:
        b = bytes(value)
    if len(b) != length:
        raise ConfigError(f"{name} table must be {length} bytes, got {len(b)}")
    return b


def configure_tables(
    *,
    lut: Optional[Union[bytes, str]] = None,
    prop_table: Optional[Union[bytes, str]] = None,
    crc_table: Optional[Union[bytes, str]] = None,
) -> None:
    """Register one or more protocol tables programmatically.

    Overrides any environment variable for the same table. Pass a value as
    ``bytes`` or a hex string.
    """
    for name, value in (
        ("lut", lut),
        ("prop_table", prop_table),
        ("crc_table", crc_table),
    ):
        if value is None:
            continue
        _, length = _SPEC[name]
        _overrides[name] = _coerce(value, length, name)


def clear_tables() -> None:
    """Forget all programmatically-configured tables (mainly for tests)."""
    _overrides.clear()


def get_table(name: str) -> bytes:
    """Resolve a table: override first, then env var, else raise ConfigError."""
    env_name, length = _SPEC[name]
    if name in _overrides:
        return _overrides[name]
    raw = os.environ.get(env_name)
    if raw:
        return _coerce(raw, length, name)
    raise ConfigError(
        f"the {name!r} table is not configured. This library ships no "
        f"vendor-derived tables — supply your own: set the {env_name} env var "
        f"(hex, {length} bytes) or call cs2pppp.configure_tables({name}=...)."
    )


__all__ = ["configure_tables", "clear_tables", "get_table"]
