# Findings

A finding says what is wrong, on which device, why it matters, and what to do about
it. Anything without a remediation would be noise, so every rule carries one.

Findings are **keyed and upserted**: one that persists keeps its original
`first_seen`, so you can see how long something has been open. One you fix is
marked **resolved** rather than deleted — the history is worth as much as the
finding.

Run the audit from **Fix → Re-check now**, or:

```bash
make audit                 # everything
make audit                 # (--skip-tls omits the TLS probes)
make findings              # read them
make findings SEVERITY=high
```

## Severity

| Level | Meaning |
|---|---|
| **high** | Act on this. Either definitively broken, or an exposure with a history of being exploited. |
| **medium** | Worth changing. A real weakness, or something that deserves a deliberate decision. |
| **low** | Review when convenient. Often legitimate, but worth knowing about. |

## Where findings come from

Three sources, with different confidence:

1. **Inventory rules** — derived from what is already known. Fully re-derived on
   every audit, so anything fixed resolves immediately.
2. **Exploit correlation** — offline, against the local exploit database.
   Refreshes only when the audit runs.
3. **TLS posture** — actively probes TLS ports. Definitive.

---

## Inventory rules

### Exposed services

Services that should not be reachable on a local network without a deliberate
decision, judged by port:

| Port | Severity | Finding | Remediation |
|---|---|---|---|
| `21` | medium | FTP is exposed | Replace with SFTP (over SSH) or disable the FTP service. |
| `23` | high | Telnet is exposed | Disable Telnet and use SSH instead. On embedded devices this is often on by default in the admin panel. |
| `69` | medium | TFTP is exposed | Disable TFTP unless it is actively needed for device provisioning, and firewall it to the provisioning host. |
| `111` | medium | RPC portmapper is exposed | Disable rpcbind if NFS is not in use, or restrict it to known clients. |
| `135` | low | Windows RPC endpoint mapper is exposed | Enable the Windows firewall for this network profile, or set the network to Private/Domain rather than Public sharing. |
| `139` | low | NetBIOS session service is exposed | Disable NetBIOS over TCP/IP in the adapter's advanced TCP/IP settings. |
| `445` | medium | SMB file sharing is exposed | Confirm sharing is intended. If it is, require SMB3, disable SMBv1, and restrict shares to specific accounts. |
| `512` | high | rexec is exposed | Disable the rexec/rsh/rlogin family entirely; they have no safe configuration. |
| `513` | high | rlogin is exposed | Disable the rexec/rsh/rlogin family entirely and use SSH. |
| `514` | high | rsh is exposed | Disable the rexec/rsh/rlogin family entirely and use SSH. |
| `1433` | medium | Microsoft SQL Server is reachable | Bind the instance to localhost, or firewall it to the application hosts that need it. |
| `3306` | medium | MySQL/MariaDB is reachable | Set bind-address=127.0.0.1, or firewall the port to the application hosts that need it. |
| `3389` | medium | Remote Desktop is exposed | Require Network Level Authentication, enforce strong passwords, and restrict the port to known hosts. |
| `5432` | medium | PostgreSQL is reachable | Set listen_addresses='localhost', or firewall the port to the application hosts that need it. |
| `5900` | high | VNC is exposed | Tunnel VNC over SSH and disable direct access, or require authentication and TLS. |
| `6379` | high | Redis is reachable | Bind to 127.0.0.1, set requirepass, and enable protected-mode. |
| `9200` | medium | Elasticsearch is reachable | Bind to localhost or enable authentication, and firewall the port. |
| `11211` | high | Memcached is reachable | Bind to 127.0.0.1 and disable the UDP listener. |
| `27017` | high | MongoDB is reachable | Enable authorization, bind to localhost, and firewall the port. |

### Unencrypted services

Flagged by service name where the protocol has no transport security:
`ftp`, `imap`, `pop3`, `rlogin`, `rsh`, `smtp`, `snmp`, `telnet`. The remediation is the encrypted equivalent, or disabling it.

### Management interfaces

A router, switch, access point, printer, camera or IoT device serving a web
interface on 80, 443, 8080 or 8443. Severity **low**, and often entirely
legitimate — but these are the devices most often left on factory credentials, so
the finding asks you to confirm the password was changed and the firmware is
current. One finding per device, listing its ports.

### IPv6 exposure

A device with a **globally routable** IPv6 address and open ports. Severity
**medium**. IPv4 NAT does not apply to IPv6, so a service you believe is internal
may be reachable from the internet unless your router firewalls it. The
remediation is to check that firewall and then verify from outside.

### Unidentified devices

A device online that nothing has been able to identify. Severity **low**. The
remediation suggests a Standard or Deep scan for its ports, or a passive listen for
the names it advertises — or setting the type by hand if you already know.

### Unapproved devices

**Stays quiet until you use it.** Once you mark any device as approved, every
device that is not approved becomes a finding — `medium` if you explicitly marked
it *Not approved*, `low` if simply unreviewed. This is what turns "a new device
joined" from a fact into something actionable.

Set approval in a device's **Details** tab.

### Container isolation

Severity **high**, and about Network Atlas rather than your network: it is running
somewhere that cannot reach the network it is meant to map — a container on a NAT'd
network. Without this the failure looks exactly like a network with nothing on it.
See [Docker](Docker).

---

## Exploit correlation

Nmap records a product and version for every service it fingerprints. Those are
matched against **exploitdb on your own machine**. No fingerprint leaves the
host — which is why `vulners.nse` is deliberately not used: it POSTs the CPE of
every detected service to a third-party API.

**The claim is deliberately weak.** Records are matched by product name and, where
possible, by the version appearing in the record's title. That is evidence worth
reading, not proof. **Nothing here reports a device as vulnerable**, because
exploitability cannot be established without testing it — which this tool does not
do.

How the severity is decided:

| Match | Severity | Wording |
|---|---|---|
| Version named, and a remote or web exploit exists | medium | "names this exact version" |
| Version named, local or denial-of-service only | low | "names this version, but only for local or denial-of-service issues" |
| Product matched, version not | low | "matches the product only, not the version" |

A version match needs at least `major.minor` — a bare major would match unrelated
products. Records whose title begins with the product name are shown first, so a
search for `nginx` leads with Nginx rather than Ingress-NGINX.

One finding per device and product, listing every port it was found on. Inspect
the matches yourself with `searchsploit <product>`.

---

## TLS posture

`sslscan` probes every TLS-capable port. These findings are definitive.

| Finding | Severity | Detected |
|---|---|---|
| Heartbleed | high | The service leaks process memory (CVE-2014-0160). Key material must be assumed compromised. |
| SSLv2 / SSLv3 offered | high | Broken by DROWN and POODLE. |
| TLS 1.0 / 1.1 offered | medium | Deprecated and disallowed by current standards. |
| Weak cipher suites accepted | medium | A client can be steered onto cryptography that no longer protects traffic. |
| Certificate expired | medium | Clients show warnings, which trains people to click through them. |
| Broken signature algorithm | medium | Signed with MD5 or SHA-1, for which practical collision attacks exist. |
| Certificate expires within 30 days | low | Renew before it lapses. |
| Self-signed certificate | low | Nothing verifies the identity. Common and often fine on internal appliances. |

---

## Ignoring a finding

**Ignore this** in the Fix tab hides one you have accepted. It is not deleted —
**Show ignored** brings it back, and it keeps accruing history. Use it for
deliberate decisions (a self-signed certificate on an appliance you control), not
to tidy away things you have not looked at.

## What the audit will not do

It never tests credentials, runs an exploit, or attempts to change a device. Every
check is a read. That is what makes it safe to leave monitoring on, and it is a
deliberate boundary — see [Privacy and Safety](Privacy-and-Safety).
