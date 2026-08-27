# Network Atlas

Network Atlas turns discovery data from a Kali workstation into a persistent inventory and an interactive browser map. It uses only Python's standard library at runtime and calls the tools already present in `kali-linux-everything`.

It currently collects:

- IPv4/IPv6 addresses, MAC addresses and OUI vendors from Nmap and `arp-scan`
- Hostnames, open services, product versions, CPEs and OS/device matches from Nmap XML
- mDNS/DNS-SD advertisements from `avahi-browse`
- LLDP neighbours and direct switch-port observations from managed switches over read-only SNMP
- Layer-3 paths from Nmap traceroute
- First/last-seen timestamps, collection history and manual name/type overrides

Classification is evidence-based. The viewer shows its confidence and reasons, so an Apple MAC address alone is not silently declared to be a phone.

## Makefile commands

The Makefile keeps runtime data under `~/.local/state/network-atlas/` and provides the normal lifecycle:

```bash
make doctor
make install-hooks
make start
make status
make logs
make stop
```

Collection commands require an explicit target or interface:

```bash
make scan-dry TARGET=10.23.45.0/24
make scan-discovery TARGET=10.23.45.0/24
make scan-inventory TARGET=10.23.45.0/24
make arp INTERFACE=eth0
make mdns
make snmp SNMP_CONFIG=switches.json
```

Other useful commands are `make summary`, `make classify`, `make test`, and `make privacy`. `make install-hooks` enables automatic privacy checks before local commits and pushes. Run `make help` for the complete list. `switches.json` is deliberately ignored by Git; create it from `config.example.json` and keep its secrets in environment variables.

## Safety model

- The scanner accepts only an explicit CIDR.
- Public ranges and ranges larger than 4096 addresses are rejected unless separately confirmed.
- Commands are executed as argument arrays, never through a shell.
- Raw discovery files and the SQLite database remain local.
- The web viewer is read-only and binds to `127.0.0.1` by default.
- A non-loopback bind requires `--allow-remote`; the viewer does not yet include authentication.
- SNMP secrets are read from environment variables into a temporary mode-`0600` Net-SNMP configuration and are not stored in command history or the database.

Only scan networks you own or are explicitly authorized to administer.

## Quick start with demo data

From this directory:

```bash
python3 -m network_atlas --db /tmp/network-atlas-demo.db init
python3 -m network_atlas --db /tmp/network-atlas-demo.db import-nmap examples/demo-nmap.xml
python3 -m network_atlas --db /tmp/network-atlas-demo.db import-arp examples/demo-arp.txt
python3 -m network_atlas --db /tmp/network-atlas-demo.db import-mdns examples/demo-mdns.txt
python3 -m network_atlas --db /tmp/network-atlas-demo.db serve
```

Open <http://127.0.0.1:8765>.

Without `--db`, data is stored at `~/.local/state/network-atlas/atlas.db`. You can also set `NETWORK_ATLAS_DB`.

## Collect your network

First check the interface and routes:

```bash
ip -brief address
ip route
```

Validate an Nmap command without sending packets:

```bash
python3 -m network_atlas scan --target 10.23.45.0/24 --dry-run
```

Perform host discovery. `--sudo` elevates only Nmap, leaving the database owned by your normal user:

```bash
python3 -m network_atlas scan --sudo \
  --target 10.23.45.0/24 --profile discovery
```

Collect richer service and OS information:

```bash
python3 -m network_atlas scan --sudo \
  --target 10.23.45.0/24 --profile inventory
```

The inventory profile uses SYN scanning, OS detection and traceroute when run as root. Without root it falls back to a TCP connect scan and clearly reports that OS/traceroute were omitted.

Discover the directly attached broadcast domain and mDNS services:

```bash
python3 -m network_atlas arp --sudo --interface eth0
python3 -m network_atlas mdns
```

The mDNS collector uses the local Avahi service. If Kali reports that its daemon is not running:

```bash
sudo systemctl start avahi-daemon
python3 -m network_atlas mdns
```

Start the viewer:

```bash
python3 -m network_atlas serve
```

## Managed-switch topology

Copy `config.example.json` to a private configuration file and create a dedicated read-only SNMPv3 user on each managed switch. The JSON stores only environment-variable names:

```bash
export ATLAS_SWITCH1_AUTH='your-authentication-passphrase'
export ATLAS_SWITCH1_PRIV='your-privacy-passphrase'
python3 -m network_atlas snmp --config switches.json
```

The collector reads standard LLDP and bridge MIB tables. It creates high-confidence LLDP links and switch-port attachments. MAC addresses learned on a known LLDP uplink are excluded from direct attachments, because they belong somewhere downstream.

SNMPv2c is supported for legacy equipment but SNMPv3 is preferred. A v2c entry looks like:

```json
{
  "host": "10.23.45.3",
  "version": "2c",
  "community_env": "ATLAS_LEGACY_COMMUNITY"
}
```

## Correct a classification

Use a device ID, IP or MAC as the selector:

```bash
python3 -m network_atlas label 10.23.45.45 --name "Reception printer" --type printer
```

Manual values override future automatic classifications without deleting the collected evidence.

Recalculate the automatic rules after an update without rescanning:

```bash
python3 -m network_atlas classify
```

## Import existing results

```bash
python3 -m network_atlas import-nmap scan.xml
python3 -m network_atlas import-arp arp-scan.txt
python3 -m network_atlas import-mdns avahi-parsable.txt
```

Nmap output should be generated with `-oX`, for example:

```bash
sudo nmap -sS -sV -O --osscan-limit --top-ports 100 --traceroute \
  -oX scan.xml 10.23.45.0/24
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Current topology limitations

- Traceroute represents routed paths, not Ethernet cabling.
- Unmanaged switches cannot report their internal links.
- A forwarding-table observation is less authoritative than LLDP and may still be ambiguous on unusual switch stacks.
- Wi-Fi client-to-access-point mapping requires vendor/controller SNMP tables, which vary by manufacturer and are not yet implemented.
- Quiet phones and clients using private MAC addresses may remain unknown until they advertise a service or appear in DHCP/controller data.
