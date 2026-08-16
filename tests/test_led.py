"""Unit tests for SetLed (no network)."""

from cs2pppp.led import (
    LED_OFF,
    LED_ON,
    SetLedResult,
    ir_off,
    ir_on,
    parse_set_led_reply,
    set_led,
)


class _FakeSession:
    def __init__(
        self,
        *,
        replies=None,
        error=None,
        loopback=False,
        open_=True,
    ):
        self.loopback = loopback
        self.sock = object() if open_ else None
        self.peer = object() if open_ else None
        self._replies = list(replies or [])
        self._error = error
        self.sent = []

    def command(self, obj, *, read_timeout=4.0):
        self.sent.append(obj)
        if self._error is not None:
            raise self._error
        return list(self._replies)


def test_parse_set_led_reply_ok():
    obj = parse_set_led_reply('{"cmd":"SetLed","ledstatus":1}')
    assert obj is not None
    assert obj["ledstatus"] == 1


def test_parse_set_led_reply_other_cmd():
    assert parse_set_led_reply('{"cmd":"GetDevInfo"}') is None


def test_parse_set_led_reply_bad_json():
    assert parse_set_led_reply("not-json") is None


def test_set_led_refuses_loopback():
    r = set_led(_FakeSession(loopback=True), True)
    assert r.error
    assert "loopback" in r.error
    assert not r.fired


def test_set_led_session_not_open():
    r = set_led(_FakeSession(open_=False), True)
    assert r.error == "session not open"
    assert not r.fired


def test_ir_on_sends_ledstatus_1():
    sess = _FakeSession(replies=[])
    r = ir_on(sess, read_timeout=1.0)
    assert r.fired
    assert r.likely_ok
    assert r.enabled
    assert r.ledstatus == LED_ON
    assert sess.sent[0] == {"cmd": "SetLed", "ledstatus": LED_ON}
    assert "no SetLed reply" in r.notes[0]


def test_ir_off_sends_ledstatus_0():
    sess = _FakeSession(replies=[])
    r = ir_off(sess)
    assert r.fired
    assert not r.enabled
    assert sess.sent[0] == {"cmd": "SetLed", "ledstatus": LED_OFF}


def test_set_led_optional_reply():
    sess = _FakeSession(replies=['{"cmd":"SetLed","ledstatus":1}'])
    r = set_led(sess, True)
    assert r.fired
    assert r.likely_ok
    assert r.ledstatus == 1
    assert r.reply is not None


def test_set_led_channel_error_after_send():
    r = set_led(_FakeSession(error=RuntimeError("timeout")), True)
    assert r.fired
    assert not r.likely_ok
    assert "command error" in (r.notes[0] if r.notes else "")


def test_set_led_result_to_dict():
    d = SetLedResult(fired=True, likely_ok=True, enabled=True, ledstatus=1).to_dict()
    assert d["fired"] is True
    assert d["ledstatus"] == 1
    assert d["enabled"] is True
