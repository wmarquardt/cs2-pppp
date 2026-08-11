"""Probe a device's directory status. Servers come from the environment.

    CS2_SERVERS=ip1,ip2,ip3 CS2_DID=G100000ZKMNP python examples/probe_status.py
"""

import os

from cs2pppp import Cs2Client

servers = os.environ["CS2_SERVERS"].split(",")
did = os.environ["CS2_DID"]

client = Cs2Client(servers=servers)
print(client.probe(did))
