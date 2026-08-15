"""Unit tests for AppointDev state=2 factory reset (no network)."""

from cs2pppp.factory import APPOINT_FACTORY, factory_reset
from cs2pppp.reboot import APPOINT_REBOOT


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


def test_factory_sends_state_2_not_reboot():
    sess = _FakeSession(
        replies=['{"cmd":"AppointDev","state":1}'],
        post_replies=[],
    )
    r = factory_reset(sess, read_timeout=1.0)
    assert r.fired
    assert sess.sent[0] == {"cmd": "AppointDev", "state": APPOINT_FACTORY}
    assert sess.sent[0]["state"] != APPOINT_REBOOT
    assert "pwd" not in sess.sent[0]


def test_factory_optional_pwd():
    sess = _FakeSession(replies=['{"cmd":"AppointDev","state":1}'], post_replies=[])
    factory_reset(sess, password="123456")
    assert sess.sent[0]["pwd"] == "123456"


def test_factory_refuses_loopback():
    r = factory_reset(_FakeSession(loopback=True))
    assert r.error
    assert "factory reset" in r.error
    assert not r.fired


def test_factory_session_not_open():
    r = factory_reset(_FakeSession(open_=False))
    assert r.error == "session not open"
    assert not r.fired


def test_factory_channel_death_after_send():
    r = factory_reset(_FakeSession(error=RuntimeError("timeout")))
    assert r.fired
    assert r.likely_ok
