# Getting Started

## Run a full sweep

With the viewer open at <http://127.0.0.1:8765>, click **Scan network** and choose
**Full sweep**. Leave the range blank — it detects your subnet from the default
route.

A sweep runs five stages in the order that makes each later one smarter:

| Stage | What it does | Typical time |
|---|---|---|
| Read address caches | Imports the kernel's ARP and IPv6 neighbour tables. Instant and silent. | seconds |
| Active scan | Probes the range for live hosts, open ports, service versions and OS. | minutes |
| Resolve names | DNS, mDNS and NetBIOS lookups for everything found. | under a minute |
| Passive listen | Watches broadcast traffic for devices that never answered, plus DHCP, LLDP and CDP. | as configured |
| Audit | Checks the result for exposed services, weak TLS and known vulnerabilities. | under a minute |

Progress streams into the header as it runs. You can keep using the interface.

## Read the result

**Overview** answers "what is on my network": a count of devices online, grouped
by what they are, and the most serious findings.

**Map** shows how they connect, as a tree rooted at your gateway. Where a switch
speaks LLDP or CDP, devices appear under the switch with the physical port
labelled. Click any device to open its detail panel.

**Fix** is where the value is. Every finding says what was observed, why it
matters, and what to do. Start at the top — it is ordered by severity.

## Name the things it could not identify

Some devices expose nothing useful and land as *Unidentified*. Open one, go to
**Details**, and set a name and type. Manual values override the classifier and
survive future scans.

While you are there, set **Owner** and mark whether you expect the device to be
present. Once you approve anything, Network Atlas starts flagging devices you have
not approved — which is how "a new device joined" becomes actionable rather than
merely visible.

## Keep it current

A single scan is a snapshot. Turn on **Monitoring** in the header and the viewer
keeps the map current on its own: address caches every 5 minutes, a passive listen
every 30, a quick sweep hourly.

It is **off until you turn it on**, deliberately — scanning sends packets to other
people's devices, so it does not start on its own. It also runs only while the
viewer runs.

With monitoring on, the **Timeline** fills with what changed: devices arriving and
leaving, ports opening, and any address that moved to a different MAC.

## What to do next

- Run a **Deep scan** on a device you care about for a full port inventory.
- Run the **Wi-Fi survey** from the terminal (`make wifi`) to map wireless clients
  to access points. It needs root and briefly disconnects the interface, which is
  why it is not a button.
- If you have a managed switch, configure [SNMP](Command-Reference) to pull
  its port topology and ARP table.

## A note on scope

Only scan networks you own or are authorized to administer. Network Atlas only
reads — it never tests credentials or attempts to change a device. See
[Privacy and Safety](Privacy-and-Safety).
