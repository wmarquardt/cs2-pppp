"""Unit tests for AppointDev state=1 reboot (no network)."""

from cs2pppp.reboot import (
    APPOINT_REBOOT,
    RebootResult,
    parse_appoint_reply,
    reboot,
)


class _FakeSession:
    def __init__(
        self,
        *,
        replies=None,
        error=None,
        loopback=False,
        open_=True,
        post_replies=None,
    ):
        self.loopback = loopback
        self.sock = object() if open_ else None
        self.peer = object() if open_ else None
        self._replies = list(replies or [])
        self._error = error
        self._post_replies = list(post_replies) if post_replies is not None else ["{}"]
        self.sent = []

    def command(self, obj, *, read_timeout=4.0):
        self.sent.append(obj)
        if obj.get("cmd") == "GetDevInfo":
            return list(self._post_replies)
        if self._error is not None:
            raise self._error
        return list(self._replies)


def test_parse_appoint_reply_ok():
    obj = parse_appoint_reply('{"cmd":"AppointDev","state":1}')
    assert obj is not None
    assert obj["state"] == 1


def test_parse_appoint_reply_other_cmd():
    assert parse_appoint_reply('{"cmd":"GetDevInfo"}') is None


def test_parse_appoint_reply_bad_json():
    assert parse_appoint_reply("not-json") is None


def test_reboot_refuses_loopback():
    r = reboot(_FakeSession(loopback=True))
    assert r.error
    assert "loopback" in r.error
    assert not r.fired


def test_reboot_session_not_open():
    r = reboot(_FakeSession(open_=False))
    assert r.error == "session not open"
    assert not r.fired


def test_reboot_appoint_reply():
    sess = _FakeSession(
        replies=['{"cmd":"AppointDev","state":1}'],
        post_replies=[],
    )
    r = reboot(sess, read_timeout=1.0)
    assert r.fired
    assert r.likely_ok
    assert r.appoint_state == 1
    assert sess.sent[0] == {"cmd": "AppointDev", "state": APPOINT_REBOOT}
    assert "pwd" not in sess.sent[0]


def test_reboot_optional_pwd():
    sess = _FakeSession(replies=['{"cmd":"AppointDev","state":1}'], post_replies=[])
    reboot(sess, password="123456")
    assert sess.sent[0]["pwd"] == "123456"


def test_reboot_channel_death_after_send():
    r = reboot(_FakeSession(error=RuntimeError("timeout")))
    assert r.fired
    assert r.likely_ok
    assert "command error" in (r.notes[0] if r.notes else "")


def test_reboot_silent_reply_then_dead():
    r = reboot(_FakeSession(replies=[], post_replies=[]))
    assert r.fired
    assert r.likely_ok
    assert "no appoint reply" in r.notes


def test_reboot_result_to_dict():
    d = RebootResult(fired=True, likely_ok=True, appoint_state=1).to_dict()
    assert d["fired"] is True
    assert d["appoint_state"] == 1
