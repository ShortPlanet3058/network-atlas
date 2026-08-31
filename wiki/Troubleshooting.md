# Troubleshooting

Start here:

```bash
make doctor
```

It reports which tools are present, the network it detected, and whether it can
send raw packets and capture traffic. In Docker:

```bash
docker compose exec network-atlas python3 -m network_atlas doctor
```

---

## The map is empty or nearly empty

### Running in a container?

If Network Atlas is in a container whose network is NAT'd, it discovers the
container's own bridge and nothing else. It detects this and says so — a startup
warning, a banner in the viewer, and a high-severity entry in Fix. If you see any
of those, read [Docker](Docker): you need host networking, macvlan, or a different
place to run it.

### Wrong target?

```bash
make scan-dry
```

Prints the detected range and the exact command without sending anything. If the
range is wrong, pass it explicitly: `make scan TARGET=192.168.1.0/24`.

### Devices that ignore probes

Plenty of devices firewall everything. Listen instead:

```bash
make passive DURATION=300
```

## `nmap_raw_packets: false`

Scans still work but fall back to a connect scan with no OS detection or
traceroute. Grant the capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/lib/nmap/nmap
```

In a container this usually means `no-new-privileges` is set somewhere, which stops
the kernel honouring file capabilities. Remove it — see
[Docker → Privileges](Docker#privileges).

## `passive_capture: false`

```bash
sudo usermod -aG wireshark "$USER"   # then log out and back in
```

Verify with `getcap /usr/bin/dumpcap` — it should show `cap_net_admin,cap_net_raw`.

## Passive listening finds nothing

Expected on a quiet network — it can only report what devices actually transmit. But
check:

- **Wireless interface?** LLDP and CDP do not cross Wi-Fi, and a wireless
  association sees far less broadcast traffic than a switch port. Use a wired
  interface if you have one: `make passive INTERFACE=eth0`.
- **Long enough?** Devices renew DHCP leases on their own schedule. Try
  `DURATION=600`.
- **Right interface?** `make doctor` shows which one it would choose.

## Devices show as IP addresses instead of names

```bash
make names
```

Reverse DNS, mDNS and NetBIOS. If a device still has no name, it may not have one —
set it by hand in the device's **Details** tab. Manual names override everything and
survive future scans.

## Something is classified wrong

Open it, read **Why this type** in the Summary tab — it lists the evidence that
decided it. Then either give it more evidence (a Standard scan for ports, a passive
listen for advertisements) or set the type manually in **Details**.

After editing classifier rules:

```bash
make classify        # re-runs classification without scanning
```

## The viewer will not start

```bash
make status
make logs
```

Common causes:

- **Port already in use.** Most often the container: it uses host networking, so
  it holds the host's port 8765 directly and cannot share it with a natively
  started viewer. `make status` says so when that is the case. Run one or the
  other — `make docker-down`, or `make start PORT=8766`.
- **Stale PID file.** `make stop` clears it; `make start` also handles this.
- **Database problem.** `make init` migrates and reports.

## I do not know the viewer password

If nobody has signed in yet, restart the viewer — the password is reprinted until
the account is first used. Otherwise only a hash is kept, so set a new one from
the machine itself:

```bash
make account-reset
# or
network-atlas account --reset-password
# in a container
docker compose exec network-atlas python3 -m network_atlas account --reset-password
```

Every signed-in browser is signed out. `make account` shows the username and when
it last signed in, without revealing anything secret.

There is deliberately no reset over HTTP: a password reset reachable from the
network is a way in.

## "Too many failed attempts"

Eight wrong passwords from one address locks that address out for five minutes,
and the correct password is refused during the lockout too — otherwise the limit
would not stop a guessing program. Wait it out, or restart the viewer, which
clears the lockout along with every session.

## The container restart-loops

```bash
docker compose logs
```

`Address already in use` means something else holds the port — most often a
natively running `make start`. Under host networking the container uses the host's
ports directly, so it cannot share.

```bash
make stop                  # stop the native viewer
# or
make docker-up PORT=8766   # run the container elsewhere
```

## `docker compose: command not found`

Debian packages compose v2 as the standalone `docker-compose` binary and does not
ship the plugin. Use `docker-compose` instead, or install
`docker-compose-plugin` from Docker's repository. `make` targets detect whichever
you have.

## Docker cannot pull the image

If `docker pull` times out while `curl https://registry-1.docker.io/v2/` works, the
daemon's connectivity differs from your shell's — check a VPN, a proxy, or
`/etc/docker/daemon.json`. Transient registry slowness is also common; retry before
concluding anything.

## A scan will not start: "a scan is already running"

Only one runs at a time, deliberately — concurrent scans of one segment distort each
other's timing. Wait, or stop the running one with the button in the header.

Monitoring submits scans too, so a scheduled task may be holding the slot.

## Findings I have fixed still show

The audit only re-derives them when it runs:

```bash
make audit
```

Inventory rules resolve immediately once the cause is gone. Exploit and TLS findings
refresh only on an audit, since they depend on their own probes.

## A finding I do not want

**Ignore this** in the Fix tab hides it without deleting it. **Show ignored** brings
it back. Use it for deliberate decisions, not for things you have not looked at.

## The Wi-Fi survey fails

- **"needs root"** — it does: monitor mode is privileged. Use `make wifi`, which
  invokes sudo.
- **"not a wireless interface"** — pass the right one: `make wifi INTERFACE=wlan0`.
- **Cannot enable monitor mode** — some drivers do not support it. Check
  `iw phy | grep -A8 "Supported interface modes"` for `monitor`.
- **It is not in the container**, by design. Run it on the host.

If it leaves the interface in monitor mode after a crash:
`sudo airmon-ng stop wlan0mon`.

## Timeline is empty

It needs two collections to compare — the first has no baseline. Run any collector
twice, or turn on [Monitoring](Monitoring).

## Exploit correlation reports nothing

- **Was it a `quick` scan?** Quick does host discovery only, so there are no service
  versions to correlate. Use `standard` or `deep`.
- **Is `searchsploit` installed?** `make doctor` will say. It comes from `exploitdb`,
  a Kali package with no Debian equivalent.

## Resetting

```bash
# native — this deletes all history
rm -rf ~/.local/state/network-atlas
make init

# docker
docker compose down --volumes
```

Both discard the inventory, findings and event history.
