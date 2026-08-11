"""Open an owned device and print its info. Servers come from the environment.

    CS2_SERVERS=ip1,ip2,ip3 CS2_DID=G100000ZKMNP CS2_PASSWORD=123456 \\
        python examples/get_info.py
"""

import json
import os

from cs2pppp import Cs2Client

servers = os.environ["CS2_SERVERS"].split(",")
did = os.environ["CS2_DID"]
password = os.environ.get("CS2_PASSWORD", "")

client = Cs2Client(servers=servers)
with client.device(did, password=password) as dev:
    print(json.dumps(dev.get_info(), indent=2, ensure_ascii=False))
