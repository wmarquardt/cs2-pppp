"""Unit tests for TF list parse helpers (no network)."""

from cs2pppp.tf import (
    TfVideoItem,
    extract_hevc_annexb,
    parse_tf_list_payload,
    parse_tf_list_replies,
    resolve_tf_item,
    sniff_annexb_codec,
)
from cs2pppp.errors import SessionError
import pytest


def test_parse_envelope_value():
    obj = {
        "cmd": "GetTfVideoList",
        "page": 1,
        "count": 10,
        "allCount": 2,
        "value": [
            {"name": "a.mp4", "patch": "/rec/a.mp4", "size": 1000, "time": 1700000000},
            {"name": "b.mp4", "patch": "/rec/b.mp4", "size": "2000000", "time": "1700001000"},
        ],
    }
    items, ac = parse_tf_list_payload(obj)
    assert ac == 2
    assert len(items) == 2
    assert items[0].name == "a.mp4"
    assert items[0].size_bytes == 1000
    assert items[1].size_bytes == 2000000


def test_parse_bare_item():
    bare = {
        "name": "2026081312024000.MOV",
        "patch": "/app/sd/VIDEO/2026081312024000.MOV",
        "size": 6815744,
        "time": 1786622740,
    }
    items, ac = parse_tf_list_payload(bare)
    assert ac is None
    assert len(items) == 1
    assert items[0].name == "2026081312024000.MOV"
    assert items[0].size_bytes == 6815744


def test_parse_replies_mixed():
    raw = [
        '{"cmd":"LoginDev","result":0}',
        '{"name":"a.MOV","patch":"/app/sd/VIDEO/a.MOV","size":100,"time":1}',
        '{"name":"b.MOV","patch":"/app/sd/VIDEO/b.MOV","size":200,"time":2}',
        '{"cmd":"GetDevInfo","id":"x"}',
    ]
    items, ac = parse_tf_list_replies(raw)
    assert ac is None
    assert len(items) == 2
    assert items[0].name == "a.MOV"
    assert items[1].size_bytes == 200


def test_sniff_and_hevc():
    assert sniff_annexb_codec(b"\x00\x00\x00\x01\x40\x01") == "hevc"
    assert sniff_annexb_codec(b"\x00\x00\x00\x01\x67\x42") == "h264"
    a = b"\x00\x00\x00\x01\x40" + b"AAAA"
    assert extract_hevc_annexb(b"xx" + a).startswith(b"\x00\x00\x00\x01\x40")


def test_strip_media_headers_and_keyframe_au():
    from cs2pppp.tf import extract_hevc_keyframe_au, strip_media_frame_headers

    # fake media frame + VPS(32) SPS(33) PPS(34) IDR(19)
    # NAL header byte: type<<1  → VPS=0x40, SPS=0x42, PPS=0x44, IDR_W=0x26
    def nal(t: int, payload: bytes = b"xx") -> bytes:
        return b"\x00\x00\x00\x01" + bytes([(t << 1) & 0xFF]) + payload

    body = nal(32, b"V") + nal(33, b"S") + nal(34, b"P") + nal(19, b"IDRDATA")
    framed = b"\x01\xaf\xaf\xaf" + b"\x00" * 20 + body
    stripped = strip_media_frame_headers(framed)
    assert stripped.startswith(b"\x00\x00\x00\x01")
    assert b"\x01\xaf\xaf\xaf" not in stripped
    au = extract_hevc_keyframe_au(framed)
    assert au.startswith(b"\x00\x00\x00\x01")
    assert b"IDRDATA" in au
    assert b"\x01\xaf\xaf\xaf" not in au


def test_resolve_tf_item():
    items = [
        TfVideoItem("a.MOV", "/app/sd/VIDEO/a.MOV", 10, 0),
        TfVideoItem("b.MOV", "/app/sd/VIDEO/b.MOV", 20, 0),
    ]
    assert resolve_tf_item(items, "a.MOV").size_bytes == 10
    assert resolve_tf_item(items, "/app/sd/VIDEO/b.MOV").name == "b.MOV"
    with pytest.raises(SessionError):
        resolve_tf_item(items, "missing.MOV")
    with pytest.raises(SessionError):
        resolve_tf_item(items, "*.MOV")
