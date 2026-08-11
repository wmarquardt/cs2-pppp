from cs2pppp import parse_did, normalize_did, virtual_to_real, real_to_virtual
from cs2pppp.did import lib_accepts, lib_did_format, lib_check_valid_did


def test_virtual_to_real():
    assert virtual_to_real("G100000ZKMNP") == "GHBB-100000-ZKMNP"
    assert virtual_to_real("f000000zzzzz") == "FHBB-000000-ZZZZZ"


def test_real_to_virtual_roundtrip():
    real = "GHBB-100000-ZKMNP"
    assert real_to_virtual(real) == "G100000ZKMNP"
    assert virtual_to_real(real_to_virtual(real)) == real


def test_normalize_did_is_real_form():
    assert normalize_did("G100000ZKMNP") == "GHBB-100000-ZKMNP"
    assert normalize_did("GHBB-100000-ZKMNP") == "GHBB-100000-ZKMNP"


def test_parse_did():
    d = parse_did("G100000ZKMNP")
    assert d.real == "GHBB-100000-ZKMNP"
    assert d.virtual == "G100000ZKMNP"
    assert d.network == "mykj"
    assert d.lib_ok is True
    assert d.is_mykj


def test_lib_format_gate():
    assert lib_did_format("ghbb100000zkmnp") == "GHBB-100000-ZKMNP"
    assert lib_check_valid_did("GHBB-100000-ZKMNP") is True
    assert lib_check_valid_did("GHBB100000ZKMNP") is False  # no hyphens
    assert lib_accepts("GHBB-100000-ZKMNP") is True


def test_unknown_prefix():
    d = parse_did("Z123456ABCDE")
    assert d.network == "unknown"
    assert d.real == ""
