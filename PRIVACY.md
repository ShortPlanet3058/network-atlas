# Privacy model

Network Atlas is local-first and has no telemetry, analytics, cloud API, CDN, or account system.

The application communicates only with:

- an explicitly supplied scan target through local Nmap;
- the directly connected LAN through `arp-scan` and mDNS;
- switches explicitly listed in the local SNMP configuration;
- a browser connecting to the viewer, which binds to `127.0.0.1` by default.

The SQLite inventory, raw scan output, viewer logs, and PID file live under `~/.local/state/network-atlas/` by default—not in the repository. SNMP passwords are read from environment variables into a temporary mode-`0600` Net-SNMP configuration and are not written to Git or the inventory database.

Before publishing changes, run:

```bash
make privacy
```

Enable the included pre-commit and pre-push checks once per clone:

```bash
make install-hooks
```

This rejects tracked databases, scan directories, bytecode, private keys, local configuration, and absolute home-directory paths. When Gitleaks is installed, the same command also scans the working tree and Git history for credentials.

No automated check can determine whether every arbitrary hostname, IP address, or MAC address is real. Review staged changes before pushing, and never add local scan exports to `examples/`.
