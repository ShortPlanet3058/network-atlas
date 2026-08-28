# Network Atlas

Network Atlas discovers the devices on a network you administer, draws them as an
interactive map, works out what each one is, and audits what it finds — telling
you not just what is on your network but what to fix about it.

Everything runs locally. There is no telemetry and no cloud service, and no
service fingerprint ever leaves the machine.

## Start here

| If you want to… | Read |
|---|---|
| Install it | **[Installation](Installation)** |
| Run your first scan | **[Getting Started](Getting-Started)** |
| Understand the interface | **[Web Interface](Web-Interface)** |
| Know what each scan does | **[Scanning](Scanning)** |
| Act on what it found | **[Findings](Findings)** |
| Keep the map current | **[Monitoring](Monitoring)** |
| Run it in a container | **[Docker](Docker)** |
| Look up a command | **[Command Reference](Command-Reference)** |
| Understand the internals | **[How It Works](How-It-Works)** |
| Fix a problem | **[Troubleshooting](Troubleshooting)** |
| Know what is stored | **[Privacy and Safety](Privacy-and-Safety)** |

## In one paragraph

Network Atlas combines several kinds of discovery into one inventory. Active
scanning finds hosts that answer probes. Passive listening finds the ones that do
not, by watching the broadcast traffic devices emit anyway — and reads switch
topology from LLDP and CDP along the way. Name resolution turns addresses into
recognisable devices using DNS, mDNS, NetBIOS and DHCP. A classifier weighs every
signal to decide what each device is and records why. An audit then checks the
result for exposed services, weak TLS and published vulnerabilities, producing
findings with concrete remediation. Change detection compares each collection
against the last, so you see what moved rather than only what exists.

## Before you scan anything

Only scan networks you own or are explicitly authorized to administer. Network
Atlas refuses public address ranges unless you confirm the range is yours, and it
only ever reads: it does not test credentials, run exploits, or attempt to change
the state of any device. That boundary is deliberate — see
[Privacy and Safety](Privacy-and-Safety).
