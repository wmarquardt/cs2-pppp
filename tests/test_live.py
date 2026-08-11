"""Live tests against real hardware. Skipped unless CS2_LIVE=1.

    CS2_LIVE=1 CS2_SERVERS=ip1,ip2,ip3 CS2_DID=... pytest tests/test_live.py
"""

import os

import pytest

pytestmark = pytest.mark.live

_LIVE = os.environ.get("CS2_LIVE") == "1"


@pytest.mark.skipif(not _LIVE, reason="set CS2_LIVE=1 to run live tests")
def test_probe_live():
    from cs2pppp import Cs2Client

    client = Cs2Client(servers=os.environ["CS2_SERVERS"].split(","))
    result = client.probe(os.environ["CS2_DID"])
    assert result.status is not None


@pytest.mark.skipif(not _LIVE, reason="set CS2_LIVE=1 to run live tests")
def test_get_info_live():
    from cs2pppp import Cs2Client

    client = Cs2Client(servers=os.environ["CS2_SERVERS"].split(","))
    with client.device(
        os.environ["CS2_DID"], password=os.environ.get("CS2_PASSWORD", "")
    ) as dev:
        info = dev.get_info()
        assert "did" in info
