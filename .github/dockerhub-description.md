# Network Atlas

**See everything on your local network, and what to fix about it.**

Discovers the devices on a network you administer, draws them as an interactive
map in your browser, works out what each one is, and audits what it finds for
exposed services, weak TLS and published vulnerabilities — with a concrete
remediation for every issue it raises.

Everything runs locally. No telemetry, no cloud service, and no service
fingerprint ever leaves the machine.

- **Source and full documentation:** https://github.com/ShortPlanet3058/network-atlas
- **Wiki:** https://github.com/ShortPlanet3058/network-atlas/wiki

## Quick start

```bash
docker pull shortplanet/network-atlas
```

Then, with compose:

```bash
curl -O https://raw.githubusercontent.com/ShortPlanet3058/network-atlas/main/docker-compose.yml
docker compose up -d
```

The first start prints the login. It is shown once:

```console
$ docker compose logs network-atlas | head -20
  ┌─────────────────────────────────────────────────┐
  │  Sign in to the viewer with these credentials.  │
  │  They are shown once. Store them now.           │
  ├─────────────────────────────────────────────────┤
  │  username   admin                               │
  │  password   32ymWclEDxCcettr                    │
  └─────────────────────────────────────────────────┘
```

Change it from the account button in the viewer, or reset it with:

```bash
docker compose exec network-atlas python3 -m network_atlas account --reset-password
```

The container serves on every interface, so the viewer is reachable from other
machines on your network. Set `ATLAS_HOST=127.0.0.1` to keep it on the host's own
loopback instead.

Open <http://127.0.0.1:8765> — or the machine's own address from another device —
sign in, then click **Scan network → Full sweep**.

Commands you run in a terminal never ask for this password. They open the
database directly; it protects the web interface, not the tool.

Or without compose:

```bash
docker run -d --name network-atlas \
  --network host \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  -v atlas-data:/data \
  shortplanet/network-atlas:latest
```

## Host networking is required

The container **must** share the host's network namespace. Network Atlas finds
devices by ARP scanning, by listening for broadcast discovery traffic, and by
reading the kernel neighbour table. On Docker's default bridge a container sits
behind NAT on its own layer-2 segment, so none of that reaches it — it would
discover the bridge gateway and nothing else.

If you run it without host networking, it detects that and tells you rather than
returning an empty map.

| Host | LAN discovery |
|---|---|
| **Linux** | Full — everything works |
| **macOS** (Docker Desktop) | Limited — "host" is a Linux VM, not your Mac |
| **Windows** (Docker Desktop / WSL2) | Limited — mirrored WSL2 networking helps |

For full discovery on macOS or Windows, run it on any Linux box on the network
you want to map. A Raspberry Pi is enough.

## Tags and architectures

| Tag | Points at |
|---|---|
| `latest` | Most recent release |
| `1.2.1` | That exact version, immutable |

`1.0.0` and `1.1.0` predate the login and serve the viewer without
authentication. Do not pin to them if the viewer will be reachable from your
network. `1.2.0` has the login but its sign-in page does not work — use `1.2.1`
or later.

Built for **`linux/amd64`** and **`linux/arm64`** — so it runs on a Raspberry Pi 3
or newer with a 64-bit OS, as well as on any x86 machine.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `ATLAS_PORT` | `8765` | Viewer port (the host's port, under host networking) |
| `ATLAS_HOST` | `0.0.0.0` | Bind address. `127.0.0.1` restricts it to the host itself |
| `NETWORK_ATLAS_DB` | `/data/atlas.db` | Database path |

The inventory, findings and event history live in `/data` — mount a volume there
to keep them across upgrades.

## Security notes

- Runs as an unprivileged user (uid 10001), not root. Capabilities are granted to
  the three binaries that need raw sockets, and the container drops every other
  capability.
- **The viewer requires a login.** One account, `admin`, is created on first
  start with a random password printed to the log — nothing ships with a default
  password. Eight wrong guesses lock the address out for five minutes.
- **Only scan networks you own or are authorized to administer.** Public address
  ranges are refused unless you explicitly confirm the range is yours.
- Network Atlas only ever reads. It does not test credentials, run exploits, or
  attempt to change any device.

## What is in the image

Kali-based, roughly 700 MB. Includes `nmap`, `tshark`, `p0f`, `nbtscan`,
`sslscan`, `searchsploit` with the offline exploit database (290 MB of it),
`avahi-utils`, `arp-scan` and `snmp` — so nothing needs installing on the host.

The Wi-Fi survey is not included: it needs monitor mode, which requires
`--privileged` and disconnects the wireless interface. Run that from a source
checkout on the host instead.
