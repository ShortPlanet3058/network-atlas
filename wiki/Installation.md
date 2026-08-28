# Installation

Three routes. Docker is quickest; from source gives you the Wi-Fi survey and the
CLI as well.

## Docker

```bash
curl -O https://raw.githubusercontent.com/ShortPlanet3058/network-atlas/main/docker-compose.yml
docker compose up -d
```

Open <http://127.0.0.1:8765>. Nothing else needs installing — every scanning tool
is inside the image, pulled from
[`shortplanet/network-atlas`](https://hub.docker.com/r/shortplanet/network-atlas).

Requirements: Docker Engine and Compose v2. On Debian, `apt install docker.io
docker-compose` gives you both — note Debian packages compose as the standalone
`docker-compose` binary rather than the `docker compose` plugin. Either works.

**Full discovery needs a Linux host.** See [Docker](Docker) for why, and for what
to do on macOS or Windows.

## From source

### Requirements

| Purpose | Package |
|---|---|
| Runtime | `python3` (3.11 or newer) — standard library only, no `pip install` |
| Build/run helper | `make`, `iproute2` |
| Active scanning | `nmap` |
| Passive discovery | `tshark`, `dumpcap` (from `wireshark-common`) |
| Name resolution | `nbtscan`, `dnsutils`, `avahi-utils` |
| OS fingerprinting | `p0f` |
| The audit | `exploitdb` (provides `searchsploit`), `sslscan` |
| Wi-Fi survey (optional) | `aircrack-ng` (provides `airodump-ng`), `iw` |
| Legacy collectors (optional) | `arp-scan`, `snmp` |

All are present in Kali's `kali-linux-everything`. `exploitdb` is a Kali package
with no Debian equivalent; without it the audit still runs every other rule and
reports exploit correlation as unavailable.

### Install

```bash
git clone https://github.com/ShortPlanet3058/network-atlas.git
cd network-atlas
make doctor
```

`make doctor` lists which tools are present, the network it detected, and whether
it can send raw packets and capture traffic. Then:

```bash
make start
```

Open <http://127.0.0.1:8765>.

### Scanning without root

Nmap's raw-packet modes (`-sS`, `-O`, `--traceroute`) and packet capture normally
need root. On Kali both are already granted through file capabilities and group
membership, so Network Atlas probes for the capability rather than assuming a UID
and runs full-fidelity scans unprivileged.

If `make doctor` reports `passive_capture: false`, add yourself to the
`wireshark` group:

```bash
sudo usermod -aG wireshark "$USER"   # then log out and back in
```

If it reports `nmap_raw_packets: false`, grant the capabilities directly:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/lib/nmap/nmap
```

## Where data is stored

Under `~/.local/state/network-atlas/`:

| Path | Contents |
|---|---|
| `atlas.db` | The inventory, findings, events and history (SQLite) |
| `scans/` | Raw scanner output, one file per collection, mode `0600` |
| `viewer.log` | Viewer log |
| `viewer.pid` | PID of the backgrounded viewer |

In Docker this lives in the `atlas-data` volume instead. Nothing is written inside
the repository, and `.gitignore` plus a pre-commit hook keep scan data out of Git.

## Versions

Check what you are running:

```bash
python3 -m network_atlas --version
docker compose exec network-atlas python3 -m network_atlas --version
```

The viewer prints its version at startup and reports it at `/api/session`.

Images are published as both `latest` and an immutable version tag. To pin one:

```bash
ATLAS_IMAGE=shortplanet/network-atlas:1.0.0 docker compose up -d
```

## Upgrading

```bash
# Docker
docker compose pull && docker compose up -d

# From source
git pull && make restart
```

The database migrates itself on connect, so history, findings and their age are
all preserved across upgrades. Downgrading is not supported: a newer version may
have added columns an older one does not know about.
