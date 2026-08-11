import pytest

from cs2pppp import Cs2Client, DirectoryConfig
from cs2pppp.errors import ConfigError
from cs2pppp.status import ProbeResult, Status


def test_no_servers_raises():
    with pytest.raises(ConfigError):
        Cs2Client()
    with pytest.raises(ConfigError):
        Cs2Client(servers=[])


def test_directory_config_empty_raises():
    with pytest.raises(ConfigError):
        DirectoryConfig(servers=())


def test_servers_stored():
    c = Cs2Client(servers=["203.0.113.10", "203.0.113.11"])
    assert c.servers == ("203.0.113.10", "203.0.113.11")
    assert c.port == 32100


def test_directory_config_takes_precedence():
    c = Cs2Client(
        servers=["1.1.1.1"],
        directory=DirectoryConfig(("2.2.2.2",), port=40000),
    )
    assert c.servers == ("2.2.2.2",)
    assert c.port == 40000


def test_probe_uses_injected_servers(monkeypatch):
    seen = {}

    def fake_probe(real, servers, *, port, timeout):
        seen["servers"] = servers
        seen["port"] = port
        return ProbeResult(Status.ONLINE, 0x00, servers[0])

    monkeypatch.setattr("cs2pppp.client._probe", fake_probe)
    c = Cs2Client(servers=["203.0.113.10", "203.0.113.11"], directory_port=32100)
    result = c.probe("G100000ZKMNP")
    assert seen["servers"] == ("203.0.113.10", "203.0.113.11")
    assert seen["port"] == 32100
    assert result.online


def test_no_default_servers_constant():
    # There must be no importable built-in server list.
    import cs2pppp

    for name in dir(cs2pppp):
        val = getattr(cs2pppp, name)
        if isinstance(val, (list, tuple)) and val and all(
            isinstance(x, str) for x in val
        ):
            # No attribute should look like a preset list of IP-ish strings.
            assert not all("." in x and x.count(".") == 3 for x in val), name
