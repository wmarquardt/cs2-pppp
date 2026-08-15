"""Unit tests for session status parsers (no network)."""

from cs2pppp.sessions import (
    SessionStatus,
    parse_dev_info,
    parse_login_dev,
)


def test_parse_login_dev_ok():
    p = parse_login_dev(
        {
            "cmd": "LoginDev",
            "result": 0,
            "connectNum": 2,
            "deviceType": "1",
        }
    )
    assert p["ok"] is True
    assert p["result"] == 0
    assert p["connect_num"] == 2
    assert p["device_type"] == "1"


def test_parse_login_dev_negative_count():
    p = parse_login_dev({"result": 0, "connectNum": -1})
    assert p["ok"] is True
    assert p["connect_num"] == -1


def test_parse_login_dev_fail():
    p = parse_login_dev({"result": -1})
    assert p["ok"] is False
    assert p["connect_num"] is None


def test_parse_dev_info():
    d = parse_dev_info(
        {
            "cmd": "GetDevInfo",
            "ip": "192.168.1.10",
            "wifissid": "Home",
            "4G": 0,
            "imei": "860000000000001",
        }
    )
    assert d["device_ip"] == "192.168.1.10"
    assert d["wifissid"] == "Home"
    assert d["four_g"] == 0
    assert d["imei"] == "860000000000001"


def test_session_status_to_dict_no_clients():
    s = SessionStatus(
        login_ok=True,
        login_result=0,
        connect_num=1,
        device_type=None,
        login_raw={"result": 0, "connectNum": 1},
        device_ip=None,
        wifissid=None,
        four_g=None,
        imei=None,
        getdevinfo_raw=None,
        peer="1.2.3.4:32100",
        via="relay",
        loopback=False,
    )
    d = s.to_dict()
    assert d["client_list_available"] is False
    assert d["clients"] == []
    assert d["login"]["connect_num"] == 1
    assert d["session"]["peer"] == "1.2.3.4:32100"
