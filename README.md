# Network Atlas

Network Atlas discovers devices on an authorized local network and displays them in an interactive browser map. It builds a local inventory from Nmap, ARP, mDNS, and optional SNMP data, then classifies devices such as computers, phones, printers, routers, switches, and IoT equipment.

Everything runs locally. The database and scan output are stored under `~/.local/state/network-atlas/`; the project has no telemetry or cloud service.

## Dependencies

- Python 3.11 or newer
- GNU Make
- `ip` from `iproute2`
- Nmap
- `arp-scan` for local Ethernet discovery
- `avahi-browse` and `avahi-daemon` for mDNS discovery
- `snmpwalk` for optional managed-switch topology

These tools are included in Kali's `kali-linux-everything` package. Check their availability with:

```bash
make doctor
```

The Python application uses only the standard library, so no `pip install` is required.

## Run the viewer

```bash
cd network-atlas
make start
```

Open <http://127.0.0.1:8765>.

```bash
make status     # Check whether it is running
make logs       # Follow viewer logs
make restart    # Restart it
make stop       # Stop it
```

## Scan the network

Find your interface and subnet:

```bash
ip -brief address
ip route
```

Then run the collectors you need:

```bash
# Scan the primary local subnet with live progress
make scan

# Preview the detected target and Nmap command without sending packets
make scan-dry

# Scan a different authorized subnet or use the faster discovery profile
make scan TARGET=10.23.45.0/24
make scan-discovery TARGET=10.23.45.0/24

# Discover devices on the directly connected LAN
make arp INTERFACE=eth0

# Collect advertised names and services
make mdns
```

If mDNS reports that Avahi is not running, start it with `sudo systemctl start avahi-daemon`.

For managed switches, copy `config.example.json` to the ignored `switches.json`, configure read-only SNMP credentials through environment variables, and run:

```bash
make snmp SNMP_CONFIG=switches.json
```

Use `make help` to list every command. Only scan networks you own or are explicitly authorized to administer.

## Development

```bash
make install-hooks  # Enable privacy checks before commits and pushes
make test
make privacy
```

See [PRIVACY.md](PRIVACY.md) for details about local data storage and repository safeguards.
