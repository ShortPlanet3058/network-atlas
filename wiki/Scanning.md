# Scanning

Network Atlas discovers devices four different ways because no single method finds
everything. A firewalled host ignores probes but still speaks DHCP. A switch has no
IP on your subnet but announces itself over LLDP. A sleeping phone appears in
neither until it wakes.

| Method | Finds | Sends packets? | Needs |
|---|---|---|---|
| **Active scan** | Hosts that answer, their ports, versions and OS | yes | raw packets for full fidelity |
| **Passive listen** | Quiet hosts, switch topology, DHCP platforms, traffic pairs | **no** | capture rights |
| **Neighbour caches** | Anything the kernel has already resolved, IPv4 and IPv6 | no | nothing |
| **Wi-Fi survey** | Which access point each wireless client uses | monitors only | root, drops the interface |

## Active scanning

```bash
make scan PROFILE=quick     # seconds
make scan                   # standard, minutes
make scan PROFILE=deep      # tens of minutes to hours
```

| Profile | Nmap behaviour |
|---|---|
| `quick` | `-sn` with ARP, ICMP echo, timestamp and SYN probes on common ports. Multiple probe types because a host that ignores ICMP often answers a SYN. |
| `standard` | Top 200 ports, `-sV` service versions, `-O` OS detection, traceroute. |
| `deep` | All 65,535 ports, `--version-all`, default NSE scripts. |

With raw-packet access it uses SYN scanning, OS fingerprinting and traceroute; if
capabilities are missing it falls back to a connect scan and says so in the result.
Check which you have with `make doctor`.

### Guardrails

- **Public ranges are refused** unless you pass `--allow-public`.
- **Ranges over 4,096 addresses are refused** unless you pass `--allow-large`.
- `make scan-dry` prints the exact command without sending anything.

Only devices that actually respond become inventory entries. A `/24` sweep probes
256 addresses; recording the ~230 that answered nothing would bury the ones that
exist.

## Passive listening

```bash
make passive DURATION=300
```

**Sends nothing at all.** It captures only broadcast, multicast and TCP handshake
packets — never payload — and gets a surprising amount from them:

### Devices that never answer

Anything that transmits during the window is demonstrably present, even if it
firewalls every probe. Some devices have no IP on your subnet at all and can only
be found this way.

### Switch topology, with no credentials

LLDP and CDP announcements carry the neighbour's model, system description and the
**exact port** you are plugged into. A real example from a home network:

```
SG3428X — "Omada 24-Port Gigabit L2+ Managed Switch with 4 10GE SFP+ Slots"
this host is on gigabitEthernet 1/0/5
```

Neither the switch nor that port relationship is discoverable by scanning.

Only a neighbour that actually forwards traffic becomes your uplink — IP phones
flood CDP too, and treating that as topology would hang your machine off a desk
phone.

### Platform identification from DHCP

Devices name their own operating system in their DHCP request, and **DHCP is
broadcast**, so this reaches you across a switch. `MSFT 5.0` is Windows,
`android-dhcp-13` is Android, `udhcp` is embedded Linux, `Roku`, `PlayStation 5`
and `LGE_DTV` identify themselves outright. Leases also give the assigned address,
duration and the hostname the device asked for.

### Traffic pairs

Which device connects to which, and on what port — the relationship layer the
topology map cannot show. Two devices on the same switch look identical whether
they talk constantly or never.

### Passive OS fingerprinting

`p0f` infers an OS from the shape of a TCP handshake, plus uptime, hop distance and
link type.

**Know its limit.** On a switched network or Wi-Fi, a host only sees traffic
addressed to it — other devices' unicast traffic never reaches your NIC. So `p0f`
covers this machine and whatever talks *to* it, and no more. Fingerprinting the
whole network passively needs a mirror/SPAN port, or for Network Atlas to run on
the gateway. DHCP is what carries the load for everything else.

### Interface choice

Prefers a **wired** interface carrying the default route, because LLDP and CDP do
not cross Wi-Fi and a switch port sees far more broadcast traffic than a wireless
association. Override with `INTERFACE=`.

## Neighbour caches

```bash
make neighbours
```

Instant, silent, and the only collector that covers **IPv6** by default — it reads
the kernel's ARP and NDP tables, which hold everything your machine has already
talked to.

## Wi-Fi survey

```bash
make wifi DURATION=120
```

Maps wireless clients to access points with signal strength, and flags SSIDs
advertised by more than one BSSID — normal on a mesh, and also what an
impersonating access point looks like.

**Needs root and disconnects the interface while it runs**, which is why it is
CLI-only and prompts first. The interface is restored afterwards even if it fails.

## Managed switches over SNMP

```bash
cp config.example.json switches.json    # gitignored; edit it
make snmp
```

Adds LLDP neighbours, switch-port forwarding tables, and the switch's own **ARP
table** — every host it has resolved recently, including ones that ignore your
probes. Credentials come from environment variables named in the config, never
from the file.

## Which to run

| Situation | Run |
|---|---|
| First time | `make sweep` — all of it, in the right order |
| Keeping it current | Turn on [Monitoring](Monitoring) |
| Full port inventory of one host | `make scan PROFILE=deep TARGET=192.168.1.50/32` |
| Something is on the network but invisible | `make passive DURATION=600` |
| Devices show as IP addresses | `make names` |
| Mapping physical switch ports | `make passive` on a wired interface, or `make snmp` |
| Wireless layout | `make wifi` |
