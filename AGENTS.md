# AGENTS.md

## What this is

`cs2pppp` is a **stdlib-only** Python client for the CS2 Network PPPP wire
protocol and CS2-style app JSON. Callers use it to probe DIDs, open UDP
sessions, and talk JSON on the DRW command channel (login, device info,
TF/SD listing and download, soft reboot, factory reset, SetLed, optional snapshot).

Directory servers, InitStrings, and protocol byte tables are **always
injected by the caller**. This package ships none of them.

Python ≥ 3.9. Zero runtime dependencies. Live tests are gated by
`CS2_LIVE=1`.

Not affiliated with CS2 Network or any device vendor. Protocol names
exist only to describe wire compatibility.

## Clean-library rule (non-negotiable)

This is a **clean protocol library**. Do not add information about
manufacturers, vendors, brands, apps, cloud products, or any specific
hosted service.

Never commit, document, or hardcode:

- Manufacturer, OEM, or brand names (or obvious aliases)
- Specific consumer apps, cloud portals, or SaaS products
- Directory / tracker / STUN / relay IPs or hostnames
- Cloud domains, admin APIs, JWT issuers, IMEI→DID lookup services
- InitStrings, credentials, default passwords, or real DIDs
- Protocol LUTs / cipher tables as literals (caller supplies these)

Use RFC 5737 / 3849 documentation addresses (`203.0.113.x`, etc.) and
synthetic fixtures in tests and examples. Examples read servers from
the environment (`CS2_SERVERS`), never from a baked-in list.

If a change needs a vendor name or a real service endpoint to "work",
the change is out of scope. Keep the API generic: the caller already
knows their own servers, tables, and credentials.

## In scope

- Wire formats: directory probe, PPPP session, DRW, CS2-style app JSON
- High-level helpers that speak those formats (`Device`, `reboot`, `factory_reset`, `set_led`, TF)
- Caller-injected config (`Cs2Client(servers=...)`, `configure_tables`)
- DID **format** helpers (`parse_did`, `PREFIX_MAP`) — identity encoding,
  not a server list and not a DID generator
- Research crypto helpers for captures (`cs2pppp.crypto`) — no bundled
  tables

## Out of scope

- A9 / iLnk / Yi (or any other vendor-fork) LAN stacks
- Admin / JWT / account-cloud clients
- IMEI→DID cloud lookup
- Offline DID check-digit generators that claim a directory will accept them
- Default directory servers or bundled InitStrings

## Layout

- `src/cs2pppp/` — library
- `tests/` — unit tests; `tests/test_live.py` is hardware-gated
- `examples/` — env-driven scripts, no baked-in endpoints

Match existing style: small modules, stdlib only, no new dependencies
unless the user explicitly asks. Keep comments factual; do not narrate
vendors or services.
