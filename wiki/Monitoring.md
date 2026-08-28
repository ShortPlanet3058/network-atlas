# Monitoring

A single scan is a snapshot. Monitoring keeps the map current and turns the
inventory into a record of what changed.

## Turning it on

In the header of the web interface, or:

```bash
make monitor        # on
make monitor-off    # off
python3 -m network_atlas monitor status
```

**It is off until you turn it on.** Scanning sends packets to other people's
devices, so it does not start on its own just because the viewer is running.

Monitoring runs **only while the viewer runs**. With the container's
`restart: unless-stopped`, that means it resumes after a reboot.

## The schedule

Enabling monitoring turns on three tasks. Two more exist and stay off unless you
enable them individually in **Activity → Continuous monitoring**.

| Task | Default interval | On by default | Cost |
|---|---|---|---|
| Read address caches | 5 minutes | yes | none — silent |
| Listen passively | 30 minutes | yes | none — sends nothing |
| Quick sweep | 1 hour | yes | brief probe of the subnet |
| Resolve names | 6 hours | no | light |
| Check for issues | 12 hours | no | light, plus TLS connections |

The defaults are chosen so the cheap and silent passes run often and anything that
probes runs rarely. Each can be toggled and re-timed independently.

Scheduled work goes through the same job pipeline as a scan you start yourself —
same one-at-a-time limit, same live progress, same audit trail. A scheduled task
that would collide with a running scan is skipped and retried on the next tick.

## What gets recorded

Every collector compares a snapshot from before it ran against the state after, so
it reports what **changed** rather than only what exists.

| Event | Severity | Meaning |
|---|---|---|
| New device on the network | info, or medium if unapproved | First time it has been seen |
| Went offline / came back | info | Presence change |
| Port opened / closed | low / info | A service appeared or stopped |
| Changed name / vendor / system | low | Identity shifted |
| Reclassified | info | The classifier changed its mind |
| **Address moved to a different device** | **medium** | An address is now answered by different hardware |
| **Address conflict** | **high** | A device claimed an address already in use |

The last two are the ones worth watching. An address moving to a different MAC is
routine after a DHCP lease change and is also exactly what ARP spoofing looks
like — so it is always surfaced with both readings stated.

When two devices claim one address, Network Atlas keeps the established holder and
records the claim as evidence rather than forking the map into two competing copies
of one host.

## Reading the timeline

**Timeline** shows changes newest first. Unseen entries are highlighted; **Mark all
seen** clears that. **Notable only** filters to medium and high.

From the terminal:

```bash
make events
make events LIMIT=200
```

The timeline needs **two collections** to compare — the first has no baseline, so
it stays empty until the second run.

## History that accumulates

- **Devices** keep `first_seen` and `last_seen`, so you can tell a new arrival
  from something that has always been there.
- **Findings** keep their original `first_seen` across re-audits, so "this port has
  been open for three weeks" is visible. Fixed ones are marked resolved, not
  deleted.
- **Scans** keep a full audit trail with status, detail and any error.
- **Raw scanner output** is kept per collection under `scans/`, mode `0600`.

## Cost

The default set is deliberately cheap. Address caches and passive listening send
nothing at all. The hourly quick sweep is a host-discovery pass, not a port scan —
seconds on a `/24`.

If even that is more than you want, disable the quick sweep and keep the two
passive tasks: you will still see devices arriving and leaving, just without new
port information.
