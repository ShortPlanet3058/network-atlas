# Command Reference

Two interfaces over the same engine. The **CLI** is complete; **Make** targets are
convenience wrappers that supply the database path and sensible defaults.

Everything the web interface does is also a CLI command, and four things only the
CLI can do: the Wi-Fi survey (needs root), file imports (need a local path), SNMP
(needs a credentials file) and `doctor` (useful when the viewer will not start).

```bash
python3 -m network_atlas --help              # every command
python3 -m network_atlas <command> --help    # options for one
make help                                    # Make targets, grouped
```

In Docker, prefix any CLI command with:

```bash
docker compose exec network-atlas python3 -m network_atlas <command>
```

---

## Viewer

| Make | CLI | What it does |
|---|---|---|
| `make init` | `init` | Create or migrate the database. Safe to re-run; migrations preserve history. |
| `make start` | — | Start the viewer in the background. Refuses to double-start. |
| `make stop` | — | Stop it. Validates the PID belongs to Network Atlas before signalling. |
| `make restart` | — | `stop` then `start`. |
| `make status` | — | Prints `running (PID n)` or `stopped`. |
| `make logs` | — | Follow the viewer log. |
| `make run` | `serve` | Run in the foreground. Useful for debugging. |

`serve` options: `--host` (default `127.0.0.1`), `--port` (default `8765`),
`--allow-remote`.

**The viewer has no authentication.** It refuses any non-loopback bind unless you
pass `--allow-remote`, which is an acknowledgement that anyone who can reach the
port can read your whole inventory.

---

## Discovery

### `scan` — active scanning

```bash
make scan                                  # detected subnet, standard profile
make scan PROFILE=quick                    # who is online, seconds
make scan PROFILE=deep TARGET=10.0.0.0/24  # every port, slow
make scan-dry                              # print the command, send nothing
```

CLI: `scan [--target CIDR] [--profile quick|standard|deep] [--allow-public]
[--allow-large] [--timeout N] [--dry-run] [--quiet]`

| Profile | What it does | Cost |
|---|---|---|
| `quick` | Host discovery: ARP, ICMP and SYN probes | seconds |
| `standard` | Top 200 ports, service versions, OS detection, traceroute | minutes |
| `deep` | All 65,535 ports, aggressive version detection, default scripts | tens of minutes to hours |

The target is detected from your default route, so `TARGET` is only needed for a
different range. **Guardrails:** public ranges are refused without
`--allow-public`, and ranges over 4,096 addresses without `--allow-large`.

`--dry-run` prints the exact Nmap command without sending a packet — worth using
before a deep scan on an unfamiliar range.

### `passive` — listening only

```bash
make passive                        # 60s on the best interface
make passive DURATION=300 INTERFACE=eth0
```

CLI: `passive [--interface IFACE] [--duration SECONDS]`

Sends nothing. Captures only broadcast, multicast and TCP handshake packets — no
payload is ever recorded — and extracts:

- devices that never answer an active probe
- hostnames and platforms from DHCP, which is broadcast and so reaches you across
  a switch
- **physical topology from LLDP and CDP**, including the switch model and the
  exact port this host occupies, with no SNMP credentials
- DHCP leases: assigned address, duration, requested hostname
- passive OS fingerprints, uptime and hop distance via `p0f`
- traffic pairs: which device connects to which, on what port

Prefers a wired interface carrying the default route, because LLDP and CDP do not
cross Wi-Fi.

### `names` — name resolution

```bash
make names
```

CLI: `names [--target CIDR]`

Reverse DNS, mDNS and NetBIOS lookups for the known inventory. Cheap, independent
of any port being open, and usually the single biggest improvement to how readable
the map is.

### `neighbours` — kernel tables

```bash
make neighbours
```

Instant and silent. Imports the kernel's ARP and IPv6 neighbour caches — the only
collector that covers IPv6 by default.

### `web-identity` — read management pages

```bash
network-atlas web-identity
network-atlas web-identity --timeout 60
```

CLI: `web-identity [--timeout SECONDS]`

For every device already known to have a web port open (80, 443, 8080, 8443, 8000,
8888), fetches the landing page with `whatweb` and reads what the device says it
is. This is where exact model numbers come from: a page titled
`Brother DCP-L3550CDW series` names the printer far more precisely than any port
pattern can.

Only the landing page is requested. No login is attempted, no other path is
fetched, and nothing is submitted. Titles that are plainly not model designations
(`Loading...`, `Default Site`, `Welcome`) are recorded as evidence but never used
as a device's model.

Included automatically in `sweep`. Needs `whatweb`; the button is disabled in the
web interface when it is missing.

### `sweep` — everything, in order

```bash
make sweep
```

Runs caches → active scan → names → passive listen → audit. Each stage informs the
next. This is the recommended first run.

### `wifi` — Wi-Fi survey

```bash
make wifi                                   # asks for sudo, 60s
make wifi DURATION=120 INTERFACE=wlan0
```

CLI: `wifi [--interface IFACE] [--duration SECONDS] [--band a|b|g|bg|abg] [--yes]`

Maps each wireless client to the access point it is using, records signal strength,
and flags any SSID advertised by more than one BSSID — normal on a mesh, and also
what an impersonating access point looks like.

**Needs root, and disconnects the interface while it runs.** That is why it is
CLI-only and prompts before starting. The interface is restored afterwards even if
the survey fails.

### `snmp` — managed switches

```bash
cp config.example.json switches.json    # then edit; it is gitignored
make snmp
```

CLI: `snmp --config PATH [--timeout N] [--crawl] [--max-depth N]`

Collects LLDP neighbours, switch-port forwarding tables, and the device's own ARP
table — which lists every host it has resolved recently, including ones that
ignore your probes. Credentials come from environment variables named in the
config, never from the file itself.

**`--crawl` reaches switches you did not list.** LLDP is single-hop by design: the
frames carry a destination address switches are required not to forward, so
listening on the wire finds exactly one switch — the one this machine is plugged
into — however many the network has. But every switch hears its own neighbours, so
asking each one in turn walks the whole fabric:

```bash
network-atlas snmp --config switches.json --crawl
```

A neighbour is followed only when it advertises bridge or router capability,
publishes a management address, and that address is on a network this machine is
actually attached to. Anything else is reported under `skipped` and never queried.
Credentials are inherited from the switch that named the neighbour, since a site
normally shares one read-only community or user; a neighbour with its own entry in
`switches.json` is queried with that instead. The walk stops after three hops
(`--max-depth`) or 32 devices.

Without `--crawl`, only the switches listed in the config are queried.

**Unmanaged switches are inferred.** A dumb switch has no address, answers nothing
and appears in no scan, so the only evidence it exists is that several devices
share one port of a managed switch with no LLDP neighbour on it. Those devices are
attached to a node named `Unmanaged switch on <port>` instead of being drawn as
several devices in one socket. The port facing the rest of the network is excluded
by the gateway's hardware address appearing on it, so the whole network is not
mistaken for a hidden switch.

### `arp`, `mdns` — legacy collectors

CLI only; superseded but kept.

- `arp --interface IFACE [--sudo]` — `arp-scan` sweep. `scan PROFILE=quick` does
  the same with ARP ping and no sudo.
- `mdns [--timeout N]` — needs a running `avahi-daemon`. `passive` reads mDNS off
  the wire without it.

---

## Findings

| Make | CLI | What it does |
|---|---|---|
| `make audit` | `audit [--skip-tls]` | Check the inventory and record findings. |
| `make findings` | `findings [--severity LEVEL] [--json]` | List open findings with remediation. |

```bash
make findings SEVERITY=high
python3 -m network_atlas findings --json    # for scripting
```

The audit has three parts — inventory rules, offline exploit correlation, and TLS
posture. `--skip-tls` omits the only part that opens connections. See
[Findings](Findings) for every rule.

---

## Monitoring

| Make | CLI | What it does |
|---|---|---|
| `make monitor` | `monitor on` | Enable the recommended schedule. |
| `make monitor-off` | `monitor off` | Disable it. |
| — | `monitor status` | Show the schedule and when each task last ran. |
| `make events` | `events [--limit N]` | Show the change log. |

Monitoring runs only while the viewer runs, and is off until enabled. See
[Monitoring](Monitoring).

---

## Inventory maintenance

| Make | CLI | What it does |
|---|---|---|
| `make summary` | `summary` | Inventory summary as JSON. |
| `make classify` | `classify` | Re-run classification without scanning. Useful after editing rules. |
| `make doctor` | `doctor` | Tools present, network detected, capabilities available. |
| — | `prune` | Delete address-only rows left by range scans. Runs automatically after every collection. |
| — | `label SELECTOR [--name N] [--type T]` | Set a name or type override. `SELECTOR` is a device id, IP or MAC. |
| — | `import-nmap PATH` | Import existing Nmap XML. |
| — | `import-arp PATH` | Import saved `arp-scan` output. |
| — | `import-mdns PATH` | Import saved parsable `avahi-browse` output. |

---

## Container

See [Docker](Docker) for the networking requirements.

| Make | What it does |
|---|---|
| `make docker-setup` | Check this machine has what the container needs. Reversible; changes no daemon config. |
| `make docker-revert` | Remove the container, image and data volume, and undo what setup changed. |
| `make docker-pull` | Pull the published image instead of building. |
| `make docker-build` | Build the image from source. |
| `make docker-up` | Start it. Refuses if the port is taken, and says why. |
| `make docker-down` | Stop it. The data volume is kept. |
| `make docker-logs` | Follow container logs. |
| `make docker-shell` | Shell inside the running container. |
| `make docker-push` | Publish to Docker Hub. Multi-architecture when `buildx` is available. |
| `make docker-describe` | Upload the Docker Hub page description. Needs `DOCKERHUB_TOKEN`. |
| `make macvlan-create` | Create a macvlan network so the container gets its own LAN address. |
| `make macvlan-remove` | Remove it. |

---

## Development

| Make | What it does |
|---|---|
| `make test` | The offline test suite. |
| `make check` | Tests plus the privacy scan — what CI would run. |
| `make privacy` | Check tracked files and history for private data and secrets. |
| `make install-hooks` | Enable privacy checks before commit and push. |
| `make clean` | Remove Python caches. |

---

## Variables

Override any of these on the command line: `make scan TARGET=10.0.0.0/24 PROFILE=deep`

| Variable | Default | Used by |
|---|---|---|
| `TARGET` | detected subnet | `scan`, `names`, `sweep` |
| `PROFILE` | `standard` | `scan`, `sweep` |
| `INTERFACE` | auto-selected | `passive`, `wifi`, `macvlan-create` |
| `DURATION` | `60` | `passive`, `wifi` |
| `SEVERITY` | all | `findings` |
| `LIMIT` | `40` | `events` |
| `HOST` | `127.0.0.1` | `start`, `run` |
| `PORT` | `8765` | viewer and container alike |
| `SNMP_CONFIG` | `switches.json` | `snmp` |
| `DB` | `~/.local/state/network-atlas/atlas.db` | everything |
| `DOCKER_USER` | `shortplanet` | `docker-push`, `docker-pull` |
| `TAG` | `latest` | `docker-push` |
| `PLATFORMS` | `linux/amd64,linux/arm64` | `docker-push` |
| `DOCKERHUB_TOKEN` | _(none)_ | `docker-describe` |

`PORT` controls the native viewer and the container together — `make docker-up
PORT=8766` moves both.

`NETWORK_ATLAS_DB` in the environment overrides the database path for the CLI
directly, without Make.
