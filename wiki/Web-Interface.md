# Web Interface

The viewer runs at <http://127.0.0.1:8765> — and, from the container, on the
machine's own address so other devices on the network can reach it. It is
read-and-control: everything except the Wi-Fi survey and file imports can be done
from here.

It asks for a password first. See
[Getting Started](https://github.com/ShortPlanet3058/network-atlas/wiki/Getting-Started)
for where the initial one is printed.

Light theme is the default; the sun/moon button in the header switches to dark and
remembers your choice.

## Header

| Control | What it does |
|---|---|
| **Monitoring on/off** | Toggles continuous collection. Off by default. |
| **Scan network** | Opens the scan dialog. |
| **Reload** | Refetches everything without scanning. |
| **Theme** | Light ↔ dark. |
| **Account** | Change the password, or sign out. Changing it signs every other browser out. |

While a scan runs, a progress pill appears with the current stage and a stop
button. Progress is live, streamed from the scanner itself.

If Network Atlas is running somewhere that cannot reach the network it is meant to
map — a container on a NAT'd network — a red banner says so, because every panel
would otherwise just look empty.

## Overview

Five counters, then four cards.

- **Devices online**, **Identified**, **Open ports**, **Known links**, **To fix**.
- **What is on your network** — device types with counts. Click one to filter.
- **Your connection** — the range being scanned, the gateway, interfaces, and
  whether raw packets and passive capture are available.
- **What to fix first** — the most serious findings. Click through to Fix.
- **Recently seen** — the newest devices and services.

## Map

A tree, not a force graph — it stays readable at any size and never becomes a
hairball.

Three layouts:

| Layout | Arrangement |
|---|---|
| **Topology** | Rooted at Internet → gateway → switches → devices. Uses real evidence: LLDP, CDP, switch ports, routing. |
| **By type** | Grouped into computers, phones, printers and so on. |
| **By subnet** | Grouped by network segment. |

Infrastructure sorts first, then devices with the most children. Each row shows
the device name, type badge, address, vendor, system, open-port count and when it
was last seen. A dashed border marks the machine running Network Atlas. Where
known, the switch port appears as `port gigabitEthernet 1/0/5`.

Twisty arrows collapse branches; **Expand all** and **Collapse** act on
everything. The filter box matches names, addresses, MACs, vendors and types.

## Devices

A sortable table: device, type, address, vendor, system, port count, certainty and
last seen. Click a column to sort, a row to open the detail panel. Type chips
filter; the search box matches everything.

**Certainty** is the classifier's confidence, from the amount of evidence and how
clearly it beat the alternative. A close two-way split never reads as certain.

## Ports

Every open port on the network, grouped by service and ordered by how many devices
expose it. Services worth attention are marked and can be filtered to. Expand a
row to see which devices, and click through to any of them.

## Fix

Four counters — high, medium, low, and how many you have fixed — then the findings
themselves, most severe first.

Each expands to show:

- **Why this matters** — the consequence, in plain terms.
- **What was observed** — the evidence, verbatim.
- **How to fix it** — concrete steps for that device and service.

**Ignore this** hides a finding you have accepted; **Show ignored** brings them
back. **Re-check now** runs the audit again.

Findings you fix are marked resolved rather than deleted, so "this was open for
three weeks" stays in the record. See [Findings](Findings) for every rule.

## Timeline

What changed, newest first: devices appearing, leaving and returning, ports
opening and closing, names and vendors changing, and addresses moving to a
different MAC. Unseen entries are highlighted; **Mark all seen** clears that.
**Notable only** filters to medium and high severity.

Needs two collections to compare — the first one has no baseline.

## Activity

Scan history with status and detail, browser-started scans, and the monitoring
schedule with a toggle and interval for each task.

## Device detail

Click any device, anywhere.

| Tab | Contents |
|---|---|
| **Summary** | Certainty, why it was classified that way, identity (addresses, MAC, vendor, OS, owner, location, whether approved), how it connects, and who it talks to. |
| **Ports** | Every open port with product and version. |
| **Fix** | Findings for this device. |
| **Details** | Set name, type, owner, location, notes, and whether the device is expected. |

Relationships are clickable: the parent device, the devices connecting through it,
and its traffic peers.

**Approved / Not approved / Undecided** matters — once you approve anything,
unapproved devices become a finding. Until then the rule stays quiet rather than
nagging.
