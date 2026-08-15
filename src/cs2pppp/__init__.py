"""cs2pppp — stdlib Python client for the CS2 PPPP wire protocol and
CS2-style app JSON, where directory servers are always supplied by the
caller.

Not affiliated with CS2 Network or any device vendor.
"""

from __future__ import annotations

from .client import Cs2Client, DirectoryConfig
from .crypto import (
    CS2_SESSION_KEY,
    PpppKey,
    crc_dec,
    crc_enc,
    crack_key,
    derive_key,
    prop_dec,
    prop_enc,
    recover_key,
    xor_apply,
)
from .device import Device
from .did import (
    Did,
    PREFIX_MAP,
    normalize_did,
    parse_did,
    real_to_virtual,
    to_real,
    virtual_to_real,
)
from .errors import (
    AuthError,
    ConfigError,
    Cs2Error,
    DirectoryError,
    SessionError,
)
from .framing import encode_json, extract_json_strings
from .initstring import DecodedInit, decode_init_string
from .probe import probe
from .session import PeerEndpoint, PpppSession
from .status import ProbeResult, Status
from .sessions import (
    CLIENT_LIST_PROBES,
    CmdProbe,
    SessionStatus,
    collect_session_status,
    parse_dev_info,
    parse_login_dev,
    peer_endpoint,
)
from .tf import (
    TfDownloadResult,
    TfPreviewResult,
    TfVideoItem,
    download_tf_file,
    list_tf_videos,
    parse_tf_list_payload,
    parse_tf_list_replies,
    playback_tf_file,
    resolve_tf_item,
    tf_preview_frame,
)
from ._tables import clear_tables, configure_tables

__version__ = "0.2.5"

__all__ = [
    "__version__",
    # client
    "Cs2Client",
    "DirectoryConfig",
    "Device",
    "PpppSession",
    "PeerEndpoint",
    # session status (LoginDev connectNum + path peer)
    "SessionStatus",
    "CmdProbe",
    "CLIENT_LIST_PROBES",
    "collect_session_status",
    "parse_login_dev",
    "parse_dev_info",
    "peer_endpoint",
    # TF / SD card
    "TfVideoItem",
    "TfDownloadResult",
    "TfPreviewResult",
    "list_tf_videos",
    "download_tf_file",
    "tf_preview_frame",
    "playback_tf_file",
    "resolve_tf_item",
    "parse_tf_list_payload",
    "parse_tf_list_replies",
    # probe / status
    "probe",
    "ProbeResult",
    "Status",
    # did
    "Did",
    "PREFIX_MAP",
    "parse_did",
    "normalize_did",
    "virtual_to_real",
    "real_to_virtual",
    "to_real",
    # initstring
    "decode_init_string",
    "DecodedInit",
    # caller-injected protocol tables
    "configure_tables",
    "clear_tables",
    # framing
    "encode_json",
    "extract_json_strings",
    # crypto (session + research helpers)
    "CS2_SESSION_KEY",
    "prop_enc",
    "prop_dec",
    "crc_enc",
    "crc_dec",
    "PpppKey",
    "derive_key",
    "xor_apply",
    "recover_key",
    "crack_key",
    # errors
    "Cs2Error",
    "ConfigError",
    "DirectoryError",
    "SessionError",
    "AuthError",
]
