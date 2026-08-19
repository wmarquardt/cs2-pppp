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

    # multi-slice: trailing TRAIL VCL (type 1) must be kept with the IDR
    multi = (
        nal(32, b"V")
        + nal(33, b"S")
        + nal(34, b"P")
        + nal(19, b"IDR1")
        + nal(1, b"SLICE2")
        + nal(1, b"SLICE3")
        + nal(32, b"NEXTVPS")  # next AU — stop before this
    )
    au2 = extract_hevc_keyframe_au(multi)
    assert b"IDR1" in au2 and b"SLICE2" in au2 and b"SLICE3" in au2
    assert b"NEXTVPS" not in au2

    # Firmware that repeats VPS before every slice: extractor keeps the
    # *latest* VPS+one-slice AU, so TILE0 is dropped. stream_to_jpeg
    # must feed the whole burst or the JPEG is half a picture.
    tiled = (
        nal(32, b"V")
        + nal(33, b"S")
        + nal(34, b"P")
        + nal(19, b"TILE0")
        + nal(32, b"V2")
        + nal(33, b"S2")
        + nal(34, b"P2")
        + nal(19, b"TILE1")
    )
    au3 = extract_hevc_keyframe_au(tiled)
    assert b"TILE1" in au3
    assert b"TILE0" not in au3


def test_download_frame_payload_strip():
    from cs2pppp.tf import _download_frame_payload, _DOWNLOAD_FRAME_HDR

    # synthetic frame: magic + 25-byte hdr + "hello"
    hdr = bytearray(25)
    hdr[0:4] = b"\xa0\xaf\xaf\xaf"
    # seq = 7 at offset 8 LE
    hdr[8:12] = (7).to_bytes(4, "little")
    frame = bytes(hdr) + b"hello-mov"
    assert len(hdr) == _DOWNLOAD_FRAME_HDR
    seq, body = _download_frame_payload(frame)
    assert seq == 7
    assert body == b"hello-mov"
    assert _download_frame_payload(b"short") is None


def test_preview_defaults_prefer_stream():
    import inspect

    from cs2pppp.tf import tf_preview_frame

    params = inspect.signature(tf_preview_frame).parameters
    assert params["prefer_stream"].default is True
    assert params["seconds"].default == 3.5


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
