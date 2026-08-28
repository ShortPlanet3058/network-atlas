# Privacy and Safety

## Everything stays local

There is no telemetry, no analytics, no cloud service and no account. The
application makes **no outbound network connections except the scans you ask for**.

This includes the vulnerability audit. Exploit correlation runs against `exploitdb`
on your own machine, so no service fingerprint leaves the host. The obvious
alternative — Nmap's `vulners` script — is deliberately **not** used: it POSTs the
CPE of every detected service to a third-party API, which would break that
guarantee.

## What it reads, and never sends

| Data | Where it stays |
|---|---|
| Device inventory, findings, event history | `~/.local/state/network-atlas/atlas.db` |
| Raw scanner output | `~/.local/state/network-atlas/scans/`, mode `0600` |
| Viewer log | `~/.local/state/network-atlas/viewer.log` |

In Docker, the `atlas-data` volume. Nothing is written inside the repository.

## Packet capture records no payload

Passive discovery captures only:

- broadcast and multicast discovery traffic (ARP, DHCP, mDNS, LLMNR, NetBIOS, SSDP)
- link-layer announcements (LLDP, CDP)
- ICMPv6 neighbour and router messages
- **TCP handshake packets only** — SYN and SYN+ACK

The capture filter admits nothing else, so no conversation content is recorded. The
temporary capture file is created mode `0600` and deleted after analysis.

## What it will not do

Network Atlas **only reads**. It does not:

- test credentials, default passwords, or attempt any authentication
- run exploits or send anything intended to change a device's state
- modify configuration on any device it finds
- attempt to evade detection

This is a deliberate boundary, not an unfinished feature. The tools to cross it are
installed on Kali and are not wired in. It is what makes the tool safe to leave
running continuously, and what keeps a finding a *report* rather than an action.

Consequently, a finding never claims a device is vulnerable — only that evidence
exists and is worth checking. Establishing exploitability requires testing, which
this tool does not do.

## Authorization

**Only scan networks you own or are explicitly authorized to administer.**
Scanning a network without permission is unlawful in many jurisdictions, and
running the scan inside a container changes nothing about that.

Two guardrails are built in:

- **Public ranges are refused** unless you pass `--allow-public`, which is an
  explicit statement that the range is yours.
- **Ranges over 4,096 addresses are refused** unless you pass `--allow-large`.

Use `make scan-dry` to see exactly what would be sent, without sending it.

## Monitoring does not start by itself

Continuous monitoring is **off until you turn it on**, even though the viewer could
technically begin on startup. Scanning sends packets to other people's devices, and
a tool should not start doing that because it happens to be running.

It also runs only while the viewer runs, so stopping the viewer stops the scanning.

## The viewer has no authentication

Anyone who can reach the port can read your entire inventory: device names,
addresses, open ports and findings. That is a detailed map of your network, and it is
exactly what an attacker would want.

So:

- It binds `127.0.0.1` by default.
- It **refuses any non-loopback bind** unless you pass `--allow-remote`.
- Mutating requests require a per-process CSRF token.
- Responses carry a strict CSP, `X-Frame-Options: DENY` and `no-store`.

If you need remote access, put it behind something that authenticates — an SSH
tunnel is the simplest:

```bash
ssh -L 8765:127.0.0.1:8765 user@host
```

## Credentials

SNMP credentials are read from **environment variables named in the config file**,
never stored in the file itself. `switches.json`, `config.json`, `.env` and `*.key`
are gitignored and blocked by the pre-commit hook.

## Keeping network data out of Git

The repository ships a privacy check that runs before every commit and push:

```bash
make install-hooks     # enable it
make privacy           # run it manually
```

It fails the commit if Git is tracking anything that commonly leaks network data:
`.db` files, `scans/`, `switches.json`, `.env`, private keys, absolute home paths,
or a SQLite header in any tracked file. If `gitleaks` is installed it runs too.

This exists because the natural artefacts of this tool — a scan of your own
network — are exactly what you must not publish.

## In a container

The process runs as an unprivileged user (uid 10001), not root. The container drops
every Linux capability and re-adds only `NET_RAW` and `NET_ADMIN`; a file capability
can never grant more than that bounding set permits.

Host networking is required for discovery to work at all, and it does mean the
container shares the host's network namespace. It does not gain access to other
containers' networks, and it does not affect them — see
[Docker](Docker#does-it-interfere-with-other-containers).

## Deleting everything

```bash
rm -rf ~/.local/state/network-atlas     # native
docker compose down --volumes           # docker
```

No data exists anywhere else.
