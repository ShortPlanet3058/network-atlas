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

## The viewer requires a login

Anyone who can reach the port would otherwise read your entire inventory: device
names, addresses, open ports and findings. The findings list in particular is a
ranked inventory of exploitable services on your network with remediation notes
attached — the single most useful document an attacker on the same LAN could find,
because it is their reconnaissance already done and prioritised.

So the web interface asks for a password:

- There is **one account**, `admin`. It is created the first time the server
  starts, with a random password printed to the terminal — so a fresh container
  shows its credentials in `docker logs` and nothing ships with a default
  password. It is reprinted on each start until the first successful sign-in, so
  a lost log does not lock you out of an account nobody has used yet; after that
  only a hash is kept and it is never shown again.
- Passwords are hashed with **scrypt** and a per-account salt.
- **Eight wrong guesses** from one address locks that address out for five
  minutes. The correct password is refused during the lockout too, or the limit
  would be decorative.
- A wrong username and a wrong password produce the **identical** message, so the
  form cannot be used to discover account names.
- Sessions are held **server-side** and can therefore be revoked. Changing the
  password signs every other browser out immediately.
- The session cookie is `HttpOnly` and `SameSite=Strict`. Mutating requests
  additionally require a per-process CSRF token, so a session cookie alone is not
  enough.
- The only paths reachable without signing in are the login form, the login
  endpoint, and `/healthz` — which returns `{"status": "ok"}` and nothing else.
- Responses carry a strict CSP, `X-Frame-Options: DENY` and `no-store`.

Lost the password? Reset it from the machine itself:

```bash
network-atlas account --reset-password
# in a container:
docker compose exec network-atlas network-atlas account --reset-password
```

There is no reset over HTTP, because a reset over HTTP is a way in.

## The command line is not authenticated

`network-atlas scan`, `passive`, `snmp` and the rest open the database directly
and never speak to the server, so they never ask for a password. That is
deliberate: running them means you already have the machine and the database,
which is strictly more access than the viewer grants. The password protects the
**network** interface, not the tool.

## Serving it to your network

The viewer still refuses a non-loopback bind unless you pass `--allow-remote`,
even though it now authenticates. Exposing your network map should be a decision
someone made on purpose, not a default they inherited.

Traffic is plain HTTP, so the password crosses your LAN in the clear and a session
cookie could be read by anyone capturing traffic on it. On a home or office
network you control that is usually an acceptable trade for not running a
certificate authority. If it is not, put the viewer behind a reverse proxy that
terminates TLS, or reach it through a tunnel instead:

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
