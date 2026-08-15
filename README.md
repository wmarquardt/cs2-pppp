# cs2pppp

A small, **zero-dependency (stdlib-only)** Python client for the **CS2 Network
PPPP** stack used by CS2-style IoT cameras.

> **`cs2pppp` is a stdlib Python client for the CS2 PPPP wire protocol and
> CS2-style app JSON, where directory servers are always supplied by the
> caller.**

It speaks the protocol wire formats:

- Directory lookup / Online–Offline–InvalidId probe
- UDP session (HELLO → wake → relay or direct punch → RDY → ALIVE → DRW)
- CS2 app-channel JSON framing on the DRW command channel
- High-level device helpers: login, get info, optional snapshot

## What it is *not*

- Not an A9/iLnk/Yi LAN library — those forks are **out of scope**.
- Not an admin/JWT client, IMEI→DID cloud lookup, or DID generator.
- It ships **no** directory IPs, InitStrings, cloud domains, or credentials.
  You always provide the directory servers.

## Install

```bash
pip install cs2pppp
```

Python ≥ 3.9. No required dependencies. (Snapshot decoding uses a system
`ffmpeg` if you call it — not needed for probe/session/info.)

## Providing directory servers

There are **no built-in defaults**. Supply servers when constructing the client.

Get them however you like — commonly by decoding an InitString you already
have (e.g. from your own app config), or from an environment variable:

```python
import os
from cs2pppp import Cs2Client, decode_init_string

# Option A: from env
servers = os.environ["CS2_SERVERS"].split(",")   # "ip1,ip2,ip3"
client = Cs2Client(servers=servers)

# Option B: decode a user-supplied InitString blob
decoded = decode_init_string(my_init_blob)       # never bundled by this lib
assert decoded.lib_ok
client = Cs2Client(servers=decoded.servers)
```

Structured config and a custom port are also supported:

```python
from cs2pppp import Cs2Client, DirectoryConfig
client = Cs2Client(directory=DirectoryConfig(servers=("203.0.113.10",), port=32100))
```

## Providing protocol tables

This library ships **no** byte tables. The InitString decode LUT and the two
cipher tables are the caller's responsibility — supply them the same way you
supply directory servers. Provide them from your own configuration and inject
them once:

```python
import cs2pppp
cs2pppp.configure_tables(
    lut="...",         # 54 bytes, hex or bytes  — used by decode_init_string
    prop_table="...",  # 256 bytes               — session handshake (0xF9)
    crc_table="...",   # 64 bytes                — crc_enc/crc_dec (research)
)
```

Or via environment variables (hex): `CS2PPPP_LUT`, `CS2PPPP_PROP_TABLE`,
`CS2PPPP_CRC_TABLE`. A function that needs a table you did not supply raises
`ConfigError`. You only need `prop_table` for a live session, `lut` for
`decode_init_string`, and `crc_table` for the CRC research helpers.

## Probe

```python
status = client.probe("G100000ZKMNP")
print(status)                 # e.g. "online (0x00 via 203.0.113.10)"
print(status.online, status.offline, status.invalid_id, status.raw_code)
```

| Wire   | Meaning       |
|--------|---------------|
| `0x00` | Online        |
| `0xFE` | Offline       |
| `0xFF` | InvalidId     |
| `0xFD` | InvalidPrefix |

## Device session

```python
# High-level device (context manager opens/closes the UDP session)
with client.device("G100000ZKMNP", password="123456") as dev:
    info = dev.get_info()          # dict from GetDevInfo (+ related)
    # dev.login()                  # already done if password given at open
    # dev.snapshot("out.jpg")      # optional; needs ffmpeg on PATH
    # files = dev.list_tf_videos() # TF/SD card recordings
    # dev.download_tf_file(files[0], "clip.mov")
    # dev.reboot()                 # AppointDev state=1; does not wipe Wi‑Fi
    # dev.factory_reset()          # AppointDev state=2; wipes settings / Wi‑Fi

# Low-level session
with client.session("G100000ZKMNP") as sess:
    sess.alive()
    replies = sess.request_json({"cmd": "GetDevInfo"})
    sess.send_json({"cmd": "LoginDev", "pwd": "123456"})
    raw = sess.recv(timeout=2.0)
    from cs2pppp import reboot, factory_reset
    reboot(sess)                   # same as dev.reboot()
    # factory_reset(sess)          # same as dev.factory_reset(); caller confirms
```

## TF / SD card videos

List and download recordings stored on the camera card (CS2-style app JSON):

```python
from cs2pppp import list_tf_videos, download_tf_file

with client.device("G100000ZKMNP", password="123456") as dev:
    items = dev.list_tf_videos()           # page starts at 1; bare or envelope JSON
    for it in items:
        print(it.name, it.size_bytes, it.patch)
    if items:
        dev.download_tf_file(items[0], f"/tmp/{items[0].name}")
```

Notes from live RE:

- List command: `GetTfVideoList` with `page` / `count` (apps often use **1-based** pages).
- Many firmwares stream **one bare JSON object per file** (`name`, `patch`, `size`,
  `time`) — not a single envelope with `cmd=GetTfVideoList`. Filtering replies by
  that command name drops all items.
- Download: `DownloadFile` on DRW channel 1, file bytes on **channel 3**.

The relay path is preferred by default (direct hole-punch often fails on CGNAT).
Pass `prefer="direct"` to try the direct punch first.

## DID helpers (format only)

```python
from cs2pppp import parse_did, normalize_did, virtual_to_real, real_to_virtual

normalize_did("G100000ZKMNP")     # "GHBB-100000-ZKMNP" (wire/real form)
virtual_to_real("G100000ZKMNP")   # "GHBB-100000-ZKMNP"
parse_did("GHBB-100000-ZKMNP")    # Did(real=..., virtual=..., network="mykj", ...)
```

The `PREFIX_MAP` (virtual letter → real prefix, e.g. `F→FHBB`) is exported as
data — it is protocol identity format, not a server list. There is **no**
offline check-digit generator: this library never claims a DID will be accepted
by a directory server.

## Security notes

- The PPPP transport "encryption" is weak obfuscation. `cs2pppp.crypto` exposes
  research helpers (`derive_key`, `xor_apply`, `recover_key`, `crack_key`,
  `crc_enc`/`crc_dec`) for analysing captures. They are **not** required for
  normal use.
- The `SSD@cs2-network.` session key is a universal, hardcoded protocol
  constant, not a secret.
- Prefer devices you **own**. DIDs and passwords are sensitive — treat them
  like credentials.

## Not affiliated

This project is not affiliated with CS2 Network or any device vendor.
Names are used only to describe protocol compatibility.

## License

MIT — see [LICENSE](LICENSE).
