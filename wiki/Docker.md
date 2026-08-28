# Docker

```bash
curl -O https://raw.githubusercontent.com/ShortPlanet3058/network-atlas/main/docker-compose.yml
docker compose up -d
```

Open <http://127.0.0.1:8765>. That is everything — the image
([`shortplanet/network-atlas`](https://hub.docker.com/r/shortplanet/network-atlas))
carries every scanning tool, so nothing else needs installing.

```bash
docker compose logs -f
docker compose exec network-atlas python3 -m network_atlas doctor
docker compose down          # the data volume is kept
```

To pull the image without running it:

```bash
docker pull shortplanet/network-atlas          # :latest
docker pull shortplanet/network-atlas:1.0.0    # a pinned version
```

From a clone of the repository, `make docker-up` does the same as compose but
builds from source instead of pulling.

## Host networking is required, not optional

Both compose files use `network_mode: host`. This is not a tuning choice.

Network Atlas finds devices by ARP scanning, by listening for broadcast discovery
traffic, and by reading the kernel neighbour table. On Docker's default bridge a
container sits behind NAT on its own layer-2 segment, so **none of that reaches
it**: it discovers the bridge gateway and nothing else.

Proof of the difference, same container, same commands:

```
bridge:  172.17.0.2/16    default via 172.17.0.1     ← the bridge
host:    192.168.1.101/24 default via 192.168.1.1    ← your actual LAN
```

**It tells you when it cannot see your network.** Rather than returning an empty
map, the container detects a NAT'd namespace and reports it three ways: a warning
at startup, a banner in the viewer, and a high-severity entry in Fix.

## Platform support

| Host | LAN discovery | Notes |
|---|---|---|
| **Linux** | Full | Host networking shares your real interfaces. Everything works. |
| **macOS** (Docker Desktop) | Limited | "Host" is a Linux VM, not your Mac. Broadcast discovery and LLDP/CDP will not see your LAN. |
| **Windows** (Docker Desktop / WSL2) | Limited | Same. Mirrored WSL2 networking improves it considerably. |

### Making it work anyway

**Linux — macvlan.** Worth considering even where host networking works: the
container gets its own MAC and its own LAN address, becoming a distinct device
rather than sharing the host's namespace.

```bash
make macvlan-create        # sizes itself from your LAN, reserves the last /29
docker compose -f docker-compose.macvlan.yml up -d
docker inspect network-atlas-macvlan \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

Two caveats: macvlan needs the host kernel to own the physical interface, so it
does nothing on Docker Desktop; and by design a host cannot reach its own macvlan
children, so browse to the container's LAN address rather than `127.0.0.1`. Make
sure your DHCP server does not hand out the reserved range. Undo with
`make macvlan-remove`.

**Windows 11 (22H2+) — mirrored WSL2.** In `%UserProfile%\.wslconfig`, then restart
WSL:

```ini
[wsl2]
networkingMode=mirrored
```

Mirrored mode gives WSL2 the host's interfaces instead of a NAT, which improves
multicast reach considerably. Verify with a passive listen before relying on it.

**macOS — a bridged Linux VM.** Docker Desktop's VM cannot be made to see your
LAN. Run a Linux VM with a *bridged* adapter (UTM, Parallels, VMware, or Lima with
`socket_vmnet`) so it is a real device on the network, then run Network Atlas
inside it.

**Simplest — put it on the network.** A Raspberry Pi or any always-on Linux box on
the subnet gives full discovery, continuous monitoring and a stable history. It is
also the only option that keeps working when your laptop leaves the building.

## Does it interfere with other containers?

No. Host networking is per-container: it changes that container's namespace and
nothing else. Verified while Network Atlas was running host-networked:

| Checked | Result |
|---|---|
| Default bridge subnet | unchanged, `172.17.0.0/16` |
| Container on the default bridge | normal |
| Container on a user-defined network | kept Docker's embedded DNS at `127.0.0.11` |
| Service discovery by container name | worked |
| External DNS from those containers | worked |

Your in-machine or LAN DNS is likewise unaffected.

Two consequences worth knowing:

**It uses the host's ports directly.** The one real conflict: a natively running
`make start` already holds 8765, so the container cannot bind it. `make docker-up`
checks first and tells you. To run both:

```bash
make docker-up PORT=8766
```

**It does not get Docker's embedded DNS.** A host-networked container uses the
host's `/etc/resolv.conf`, so it cannot resolve other containers by service name.
Network Atlas has no need to, but it is why such a container cannot join a compose
service mesh.

## Privileges

The application runs as an unprivileged user (`atlas`, uid 10001), not root.
Instead of elevating the process, the image grants three binaries the two
capabilities they use:

```
cap_net_raw,cap_net_admin+eip  /usr/lib/nmap/nmap
cap_net_raw,cap_net_admin+eip  /usr/bin/dumpcap
cap_net_raw,cap_net_admin+eip  /usr/sbin/arp-scan
```

The container drops every capability and re-adds only `NET_RAW` and `NET_ADMIN`.
That bounding set is the real constraint: a file capability can never grant more
than it permits.

Two things this is sensitive to, both learned the hard way:

- **Do not grant a binary a capability compose does not also add.** If a file's
  permitted set contains a capability outside the bounding set, `execve` fails with
  `EPERM` and the binary will not start at all. A test enforces that the two lists
  agree.
- **Do not set `no-new-privileges`.** It stops the kernel honouring file
  capabilities, so nmap loses raw sockets and every scan silently degrades to a
  connect scan with no OS detection. It looks like free hardening and costs a
  headline feature. A test enforces its absence.

Verify with `docker compose exec network-atlas python3 -m network_atlas doctor` —
`nmap_raw_packets` must be `true`.

## What the container cannot do

**The Wi-Fi survey.** It needs monitor mode, which means `--privileged`, direct
access to the physical wireless interface, and it disconnects that interface. Run
`make wifi` on the host instead.

**mDNS via `avahi-browse`** needs a running `avahi-daemon`, which the container
does not start — under host networking it would clash with the host's. This costs
nothing: the passive collector reads mDNS off the wire without it.

## Persistence

The inventory, findings, event history and raw scan output live in the `atlas-data`
volume at `/data`. Removing it discards your history, including how long a finding
has been open.

To use a host directory instead:

```yaml
volumes:
  - ./atlas-state:/data
```

The container user is uid 10001, so `chown 10001:10001 atlas-state` first.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `ATLAS_IMAGE` | `shortplanet/network-atlas:latest` | Which image to run |
| `ATLAS_PORT` | `8765` | Viewer port (the host's port, under host networking) |
| `NETWORK_ATLAS_DB` | `/data/atlas.db` | Database path inside the container |

```bash
ATLAS_PORT=8766 docker compose up -d
```

## Image

Roughly 700 MB, of which `exploitdb` alone is 290 MB — the offline exploit database
the audit correlates against. The base is `kalilinux/kali-rolling`, not Debian:
`exploitdb` has no Debian package.

To build a smaller image without exploit correlation, drop `exploitdb` from the
Dockerfile's package list. Every other audit rule keeps working and the feature
reports itself unavailable rather than failing.

## Image tags

| Tag | Points at |
|---|---|
| `latest` | The most recent published build |
| `X.Y.Z` | That exact version, immutable |

Pin a version if you want reproducible deployments:

```yaml
ATLAS_IMAGE=shortplanet/network-atlas:1.0.0
```

Upgrade with `docker compose pull && docker compose up -d`. Your data volume is
untouched, and the database migrates itself on start.

## Architectures

Published for **`linux/amd64`** and **`linux/arm64`**, so it runs on a Raspberry
Pi 3 or newer (64-bit OS), and on any x86 machine. Docker picks the right one
automatically.

A 64-bit OS is required on the Pi — check with `uname -m`, which should report
`aarch64`. A Pi running 32-bit Raspberry Pi OS reports `armv7l` and cannot run
this image.

## Building and publishing

```bash
make docker-build          # build locally for this machine
make version               # the version that would be published
docker login
make docker-push           # both :VERSION and :latest, multi-architecture
```

`docker-push` reads the version from `network_atlas.__version__`, so a published
tag can never disagree with what the image contains. It creates a
`docker-container` buildx builder if one does not exist — the default `docker`
driver cannot do multi-platform builds.

Publishing needs `docker buildx`:

```bash
sudo apt install docker-buildx
```

Without it, `docker-push` refuses rather than silently publishing something a Pi
cannot run. `make docker-push-single` is the deliberate escape hatch for a
single-architecture build.

Cross-building arm64 on an x86 machine runs under QEMU emulation, which is
correct but slow — expect the package-installation step to take several times
longer than a native build.

To tag the release in Git as well:

```bash
make release-tag           # tags vVERSION and pushes it
```

## Compose file layout

| File | Role |
|---|---|
| `docker-compose.yml` | Runs the published image. A single downloaded file pulls and runs. |
| `docker-compose.override.yml` | Ships in the repository, merged automatically. Builds from source under a local tag. |
| `docker-compose.macvlan.yml` | The macvlan alternative. |

So a clone builds, and a downloaded compose file pulls, with no flags either way.

## Compose on Debian

Debian packages compose v2 as the standalone `docker-compose` binary and **does not
ship the `docker compose` plugin**. Both are compose v2 and behave identically
here; the Makefile detects whichever you have. If you invoke compose directly, use
the form you installed. `make docker-setup` reports which it found.
