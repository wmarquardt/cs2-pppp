import json

from cs2pppp import encode_json, extract_json_strings
from cs2pppp.framing import try_decode_frame


def test_encode_extract_roundtrip():
    obj = {"cmd": "GetDevInfo"}
    text = json.dumps(obj, separators=(",", ":"))
    framed = encode_json(text, timezone_hours=-3)
    got = extract_json_strings(framed)
    assert got == [text]
    assert json.loads(got[0]) == obj


def test_frame_metadata():
    framed = encode_json('{"cmd":"X"}', timezone_hours=8)
    decoded = try_decode_frame(framed)
    assert len(decoded) == 1
    body, meta = decoded[0]
    assert body == b'{"cmd":"X"}'
    assert meta["timezone_hours"] == 8
    assert meta["length"] == len(body)


def test_multiple_frames_in_buffer():
    a = encode_json('{"a":1}')
    b = encode_json('{"b":2}')
    got = extract_json_strings(a + b)
    assert got == ['{"a":1}', '{"b":2}']


def test_brace_fallback_when_unframed():
    got = extract_json_strings(b'garbage{"cmd":"Y"}trailer')
    assert '{"cmd":"Y"}' in got
