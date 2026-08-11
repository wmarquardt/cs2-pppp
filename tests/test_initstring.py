import string

import pytest

import cs2pppp
from cs2pppp import decode_init_string
from cs2pppp.initstring import check_if_valid_init_string

# A synthetic LUT (no vendor bytes). The decoder is symmetric, so the
# round-trip validates the algorithm with any 54-byte table.
FAKE_LUT = bytes((i * 7 + 3) & 0xFF for i in range(54))

# Characters unaffected by str.upper() (the decoder uppercases its input).
_SAFE = string.ascii_uppercase + string.digits


@pytest.fixture(autouse=True)
def _tables():
    cs2pppp.configure_tables(lut=FAKE_LUT)
    yield
    cs2pppp.clear_tables()


def _encode(text: str) -> str:
    """Inverse of the decoder: build an encoded blob for a target string."""
    out = bytearray(text.encode("ascii"))
    enc = []
    for i, v in enumerate(out):
        running = 0x39
        for j in range(i):
            running ^= out[j]
        raw_n = (v ^ FAKE_LUT[i % 0x36] ^ running) & 0xFF
        for hi in _SAFE:
            for lo in _SAFE:
                if (ord(lo) + (ord(hi) << 4) + 0xAF) & 0xFF == raw_n:
                    enc.append(hi + lo)
                    break
            else:
                continue
            break
        else:  # pragma: no cover
            raise AssertionError(f"no char pair for byte {v}")
    return "".join(enc)


def test_decode_roundtrip():
    text = "203.0.113.10,203.0.113.11,203.0.113.12,"
    blob = _encode(text)
    decoded = decode_init_string(blob)
    assert decoded.servers == ("203.0.113.10", "203.0.113.11", "203.0.113.12")
    assert decoded.raw == text
    assert decoded.lib_ok is True


def test_decode_json_wrapper():
    text = "10.0.0.1,10.0.0.2,10.0.0.3,"
    blob = _encode(text)
    wrapped = '{"InitString":"%s"}' % blob
    decoded = decode_init_string(wrapped)
    assert decoded.servers == ("10.0.0.1", "10.0.0.2", "10.0.0.3")


def test_explicit_lut_arg_overrides_registry():
    text = "1.1.1.1,2.2.2.2,3.3.3.3,"
    blob = _encode(text)
    # passing the same table explicitly must also work
    decoded = decode_init_string(blob, lut=FAKE_LUT)
    assert decoded.servers == ("1.1.1.1", "2.2.2.2", "3.3.3.3")


def test_missing_table_raises():
    cs2pppp.clear_tables()
    with pytest.raises(cs2pppp.ConfigError):
        decode_init_string("AABB")


def test_odd_length_rejected():
    with pytest.raises(ValueError):
        decode_init_string("ABC")


def test_check_valid_rules():
    assert check_if_valid_init_string("AABB", "1.2.3.4,5.6.7.8,9.9.9.9,") is True
    assert check_if_valid_init_string("AABB", "1.2.3.4,5.6.7.8,") is False
    assert check_if_valid_init_string("AABB", "a,b,c") is False
