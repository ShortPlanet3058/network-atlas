# How It Works

## Shape of the thing

```
collectors ──► parsers/ingest ──► SQLite ──► classifier ──► findings ──► viewer
   nmap                                          │              │
   tshark          events.diff() ◄────────────────┘              │
   ip neigh                                                      │
   nbtscan          jobs + SSE ──────────────────────────────────┘
   searchsploit
   sslscan
```

Pure Python standard library. No web framework, no ORM, no build step, no
dependencies to install. The heavy lifting is done by the scanning tools, and this
is the layer that correlates and persists what they produce.

## Modules

| Module | Responsibility |
|---|---|
| `collectors` | Runs each external tool, streams progress, records the scan |
| `parsers` | Nmap XML, arp-scan text, avahi output |
| `passive` | tshark capture and extraction |
| `fingerprint` | p0f parsing, DHCP vendor-class and option-55 interpretation |
| `webid` | Reads a device's web management page with `whatweb` |
| `enrich` | Reverse DNS, mDNS, NetBIOS name resolution |
| `oui` | IEEE vendor lookup from the local registry |
| `netinfo` | Interfaces, routes, neighbours, container detection |
| `ingest` | Writes collector output into the model; builds topology |
| `classifier` | Decides what each device is, and records why |
| `findings` | Audit rules with remediation |
| `vulns` | Offline exploit correlation |
| `tlsaudit` | Certificate and protocol posture |
| `events` | Snapshot/diff change detection |
| `scheduler` | Periodic collection |
| `jobs` | Background job runner and event bus |
| `db` | Schema, migrations, queries |
| `server` | HTTP API, static files, server-sent events |
| `wireless` | Wi-Fi survey (monitor mode) |

## Data model

| Table | Holds |
|---|---|
| `devices` | One row per device, with identity, classification, ownership |
| `addresses` | Addresses per device, IPv4 and IPv6, with the interface seen on |
| `services` | Open ports with product, version and CPE |
| `observations` | Every raw signal, with source, confidence and timestamp |
| `edges` | Topology: attachment, route, LLDP, CDP, switch-port, wireless |
| `findings` | Audit results, keyed so they persist and resolve |
| `events` | The change log |
| `flows` | Observed traffic pairs |
| `scans` | Audit trail of every collection |
| `schedule` | Monitoring configuration |

SQLite in WAL mode. Schema changes are applied as additive migrations on connect,
so upgrading never loses history. Orphaned child rows are swept on connect too —
another tool deleting a device without foreign keys enabled would otherwise leave
references that break later collectors.

## Identity: what makes two observations the same device

Hard, and the source of most subtle bugs. The rules:

1. **MAC is the strongest key.** Same MAC, same device.
2. **An address alone is weaker.** DHCP reuses addresses, so an address seen with a
   new MAC is a *new* device, not a rename.
3. **One address cannot belong to two devices at once.** When a second claimant
   appears with a different MAC, the established holder keeps the address and the
   claim is recorded as evidence. Otherwise a spoofed or relayed announcement forks
   the map into two competing copies of one host.
4. **Relayed protocols are keyed on IP, not MAC.** mDNS, LLMNR, NetBIOS and SSDP
   get forwarded by access points, so the Ethernet source is the relay rather than
   the origin. Only ARP, DHCP, LLDP and CDP — which are genuinely link-local — key
   on the hardware address.
5. **This machine is one device**, even with several NICs.
6. **Link-local-only rows fold in.** A router answers on both IPv4 and an IPv6
   link-local address; if the link-local side is recorded before its MAC is known it
   would otherwise become a second router on the map.

## Classification

Every signal casts a **weighted vote** for a device type and records a reason. The
highest total wins, and the winning reasons are stored, so the interface can always
answer "why is this a printer?".

Evidence that identifies a device **directly** outranks inference:

| Weight | Evidence |
|---|---|
| ~1.4 | LLDP/CDP capability — the device declaring what it is |
| ~1.2 | Acts as the default gateway |
| ~1.0 | Hostname naming a device class; mDNS print service |
| ~0.95 | DHCP vendor class — the device naming its own platform |
| ~0.9 | A printing service, a SIP service; a web page naming a device class |
| ~0.55 | DHCP option 55 matching a known OS signature |
| ~0.5 | Vendor makes this kind of hardware |
| ~0.2 | A general-purpose OS |
| ~0.18 | Nmap's "general purpose", which says almost nothing |

Confidence reflects both how much evidence exists and how clearly it beat the
alternative, so a close two-way split never reads as certain.

Some deliberate corrections learned from real networks:

- **Nmap fingerprints OpenWrt and generic Linux nearly identically.** A Dell laptop
  reported as OpenWrt is a misfingerprint, so that reading only wins when the vendor
  also makes network hardware, or nothing else identifies the device.
- **"Cisco IOS" must not read as Apple iOS.** Network platforms are matched first.
- **"macOS 11 … or iOS 16"** is a Mac, not a phone. A desktop OS named first wins.
- **Manufacturer hostnames run words together** — `SHIELDANDROIDTV` needs substring
  matching, while short ambiguous tokens like `tv` keep word boundaries so
  `tvm-build-server` is not a television.
- **A randomized MAC is itself a signal.** Only phones, tablets and laptops
  randomize.
- **Nmap calls a Mac's AirPlay ports `rtsp`**, which is also what an IP camera
  serves. Only 554 and 8554 count as camera evidence; the AirPlay ports
  (5000, 7000, 7100, 49152, 62078) read as a computer instead.
- **A device cannot be two things at once.** A confirmed macOS host is not a camera
  or a printer, so a verdict incompatible with the OS family is penalised. Any one
  rule is also capped, so a device with eight matching ports cannot out-vote a
  first-party statement by repetition.
- **An mDNS query is not an advertisement.** Every Mac and Android browses for
  `_pdl-datastream._tcp`; reading queries as offers classified them all as printers.
  Only responses count.

### Names

A device usually has several names and they are not equally good. They are ranked,
and a better-sourced name is never overwritten by a worse one:

| Rank | Source |
|---|---|
| 90 | mDNS `fn=` — a name a person chose |
| 85 | SNMP `sysName` — set deliberately by an administrator |
| 80 | NetBIOS / SMB — the device's own configured name |
| 70 | The hostname it requests from DHCP |
| 60 | A reverse DNS record |
| 40 | An mDNS `.local` A record |
| 20 | A service instance name, which is often service-specific |

Without this, whichever collector happened to run last won, which is how an NVIDIA
Shield ends up listed as `SHIELD Android TV-192-168-1-65-esfileshare` when
`Shield Android TV AF29` was already known.

## Topology

Real edges, in increasing order of authority:

1. **`attachment`** — same routed segment as the gateway. The fallback that gives a
   flat network its shape.
2. **`route`** — a traceroute hop.
3. **`cdp`** / **`lldp`** — a neighbour that actually forwards traffic. Strongest,
   because the device itself said so.
4. **`switch-port`** — an SNMP forwarding-table entry.
5. **`wireless`** — a Wi-Fi association.

Nmap traceroute **cannot** supply topology on a flat segment: every host is one hop
away, the hop list collapses, and no edge is recorded. That is why the gateway
attachment edge is synthesised from the routing table — without it the map has no
structure at all.

The tree is built by letting stronger evidence overwrite weaker, then breaking any
cycle so the renderer cannot recurse forever.

## Change detection

Each collector takes a snapshot before importing and diffs against it afterwards.
Comparing states is the only way to detect a *transition* — a device leaving, a port
closing, an address changing hands — which is where most of the security value sits.

## Jobs and progress

Scans take minutes, so the HTTP request that starts one returns immediately. Jobs
run on worker threads, one at a time, and publish progress over server-sent events.

Progress comes from parsing the scanner's own output. Two details that matter:

- **Nmap writes its commentary to stdout, not stderr** — and `-oX -` suppresses it
  entirely, because the XML occupies stdout. So scans write XML to a file and
  progress is read from stdout.
- **Nmap's "About X% done" is per phase**, not overall. Each phase owns a share of
  the bar, so a bar at 40% means 40% of the scan rather than 40% of one of eight
  phases.

## The viewer

`http.server` from the standard library, with a strict CSP, `X-Frame-Options:
DENY`, no inline scripts or styles, and a per-process CSRF token required on every
mutating request. The frontend is plain JavaScript — no framework, no bundler.

The map is a DOM tree rather than a force-directed graph: it stays readable at any
size, never becomes a hairball, and works with keyboard navigation.

## Capabilities, not assumptions

Nmap's raw-packet modes and packet capture usually need root, but Kali grants them
through file capabilities. Network Atlas **probes** what it can actually do rather
than checking its UID — a euid check alone silently downgrades every scan to a
connect scan with no OS detection.
