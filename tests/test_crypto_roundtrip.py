import os

import pytest

import cs2pppp
from cs2pppp import prop_enc, prop_dec, crc_enc, crc_dec, derive_key, xor_apply
from cs2pppp.crypto import PPPP_MAGIC, recover_key

# Synthetic tables (no vendor bytes). The ciphers are symmetric, so round-trips
# validate the algorithms with any correctly-sized tables.
FAKE_PROP = bytes((i * 3 + 1) & 0xFF for i in range(256))
FAKE_CRC = bytes((i * 5 + 2) & 0xFF for i in range(64))


@pytest.fixture(autouse=True)
def _tables():
    cs2pppp.configure_tables(prop_table=FAKE_PROP, crc_table=FAKE_CRC)
    yield
    cs2pppp.clear_tables()


def test_prop_roundtrip():
    data = os.urandom(84)
    ct = prop_enc(data)
    assert ct != data
    assert prop_dec(ct) == data


def test_prop_explicit_table():
    data = os.urandom(40)
    ct = prop_enc(data, table=FAKE_PROP)
    assert prop_dec(ct, table=FAKE_PROP) == data


def test_prop_empty_key_is_memcpy():
    data = b"hello"
    assert prop_enc(data, b"") == data
    assert prop_dec(data, b"") == data


def test_crc_roundtrip():
    data = b"\xf1\xd0\x00\x04abcd"
    ct = crc_enc(data)
    assert crc_dec(ct) == data
    assert crc_dec(b"not encrypted at all") is None


def test_missing_table_raises():
    cs2pppp.clear_tables()
    with pytest.raises(cs2pppp.ConfigError):
        prop_enc(b"abc")


def test_xor_self_inverse():
    key = derive_key(b"1.2.3.4,5.6.7.8,9.9.9.9,")
    data = os.urandom(32)
    assert xor_apply(xor_apply(data, key), key) == data


def test_recover_key_from_header():
    key = derive_key(b"some-init-bytes-here")
    plaintext = bytes([PPPP_MAGIC, 0x20, 0x00, 0x24]) + b"body"
    ct = xor_apply(plaintext, key)
    rec = recover_key(ct, plaintext[:4])
    assert rec.bytes4 == key.bytes4
