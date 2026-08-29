# Network Atlas

**See everything on your local network, and what to fix about it.**

Network Atlas discovers the devices on a network you administer, draws them as an
interactive map in your browser, works out what each one is, and audits what it
finds for exposed services, weak TLS and published vulnerabilities — with a
concrete remediation for every issue it raises.

Everything runs locally. No telemetry, no cloud service, and no service
fingerprint ever leaves the machine.

![Overview](https://raw.githubusercontent.com/ShortPlanet3058/network-atlas/main/.github/screenshot.png)

## What it does

- **Finds devices** by active scanning, by listening passively for the broadcast
  traffic devices emit anyway, and by reading the kernel's own neighbour tables —
  so it catches hosts that firewall themselves and never answer a probe.
- **Names and identifies them** from DNS, mDNS, NetBIOS, DHCP, a 56,000-entry
  vendor database, and OS fingerprinting — then explains its reasoning for each.
- **Maps how they connect.** Where a switch speaks LLDP or CDP, the map shows the
  physical port a device is plugged into.
- **Tells you what to fix**, ranked by severity, each finding with what was
  observed, why it matters, and how to resolve it.
- **Notices changes** — a device arriving, a port opening, an address moving to a
  different MAC — and keeps a timeline.

**[Full documentation is in the wiki →](https://github.com/ShortPlanet3058/network-atlas/wiki)**

## Install

### Docker (quickest)

```bash
curl -O https://raw.githubusercontent.com/ShortPlanet3058/network-atlas/main/docker-compose.yml
docker compose up -d
```

Open <http://127.0.0.1:8765> — or the machine's own address, since the container
serves to the whole network.

The first start creates the login and prints it once:

```bash
docker compose logs network-atlas | head -20
#   username   admin
#   password   32ymWclEDxCcettr
```

Store it then; only a hash is kept. Change it from the account button in the
viewer, or reset it with `docker compose exec network-atlas python3 -m
network_atlas account --reset-password`.

That pulls [`shortplanet/network-atlas`](https://hub.docker.com/r/shortplanet/network-atlas)
and needs nothing else installed — every scanning tool is inside the image.

Built for **amd64 and arm64**, so it runs on a Raspberry Pi 3 or newer with a
64-bit OS as well as on any x86 machine. Pin a version with
`ATLAS_IMAGE=shortplanet/network-atlas:1.1.0` if you want reproducible
deployments.

> **Linux hosts only for full discovery.** The container needs host networking to
> see your network, and on Docker Desktop for macOS or Windows that reaches only a
> Linux VM rather than your machine. Network Atlas detects this and tells you
> instead of returning an empty map. See
> [Docker](https://github.com/ShortPlanet3058/network-atlas/wiki/Docker).

### From source

Needs Python 3.11+, GNU Make, and the scanning tools — all present in Kali's
`kali-linux-everything`, or install them individually
([Installation](https://github.com/ShortPlanet3058/network-atlas/wiki/Installation)).

```bash
git clone https://github.com/ShortPlanet3058/network-atlas.git
cd network-atlas
make doctor      # check which tools are available
make start       # start the viewer
```

`make start` prints the login the first time it runs — username `admin` and a
random password, shown once. Open <http://127.0.0.1:8765>, sign in, then use
**Scan network** to collect data. No terminal needed after that.

## First run

Click **Scan network → Full sweep**. It reads the neighbour caches, scans the
detected subnet, resolves names, listens passively, then audits the result —
usually a few minutes. Everything appears as it goes.

The **Fix** tab is where the value is: each finding says what was found, why it
matters, and what to do about it.

## Authorization

Only scan networks you own or are explicitly authorized to administer. Network
Atlas refuses public address ranges unless you confirm the range is yours, and it
only ever reads — it does not test credentials, run exploits, or attempt to change
any device. See
[Privacy and Safety](https://github.com/ShortPlanet3058/network-atlas/wiki/Privacy-and-Safety).

## Documentation

| Page | What is in it |
|---|---|
| [Installation](https://github.com/ShortPlanet3058/network-atlas/wiki/Installation) | Every install route and its requirements |
| [Getting Started](https://github.com/ShortPlanet3058/network-atlas/wiki/Getting-Started) | Your first scan, walked through |
| [Web Interface](https://github.com/ShortPlanet3058/network-atlas/wiki/Web-Interface) | Every tab and panel |
| [Scanning](https://github.com/ShortPlanet3058/network-atlas/wiki/Scanning) | Scan types, what each one finds |
| [Findings](https://github.com/ShortPlanet3058/network-atlas/wiki/Findings) | Every audit rule and its remediation |
| [Monitoring](https://github.com/ShortPlanet3058/network-atlas/wiki/Monitoring) | Continuous monitoring and the timeline |
| [Docker](https://github.com/ShortPlanet3058/network-atlas/wiki/Docker) | Running in a container, networking caveats |
| [Command Reference](https://github.com/ShortPlanet3058/network-atlas/wiki/Command-Reference) | Every command and Make target |
| [How It Works](https://github.com/ShortPlanet3058/network-atlas/wiki/How-It-Works) | Architecture, classification, data model |
| [Troubleshooting](https://github.com/ShortPlanet3058/network-atlas/wiki/Troubleshooting) | When something does not work |
| [Privacy and Safety](https://github.com/ShortPlanet3058/network-atlas/wiki/Privacy-and-Safety) | What is stored, what it will not do |

## Development

```bash
make check           # tests plus the privacy scan
make install-hooks   # privacy checks before commit and push
```

The application uses only the Python standard library. See
[PRIVACY.md](PRIVACY.md) for how local data is stored and kept out of Git.

## License

MIT. See [LICENSE](LICENSE).
