from __future__ import annotations

import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import xml.etree.ElementTree as ET

from network_atlas import (
    collectors,
    events,
    findings,
    fingerprint,
    ingest,
    netinfo,
    jobs,
    oui,
    passive,
    scheduler,
    tlsaudit,
    vulns,
    wireless,
)
from network_atlas import classifier as classifier_module
from network_atlas.classifier import classify, classify_all, os_family
from network_atlas.db import AtlasDB
from network_atlas.parsers import (
    import_arp_scan,
    import_avahi,
    import_nmap_xml,
    unescape_avahi,
)
from network_atlas.snmp import _address_from_arp_suffix, parse_walk
from network_atlas.util import (
    clean_hostname,
    normalize_mac,
    utc_now,
    validate_target,
)


ROOT = Path(__file__).parents[1]


class AtlasTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = AtlasDB(Path(self.temp.name) / "atlas.db")

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def test_demo_import_and_classification(self) -> None:
        count = import_nmap_xml(self.db, ROOT / "examples" / "demo-nmap.xml")
        classify_all(self.db)
        self.assertEqual(count, 3)
        devices = self.db.devices()
        # Hostnames inside a local zone are stored as their first label, so every
        # collector agrees on one name and swapping sources logs no false change.
        printer = next(item for item in devices if item["hostname"] == "office-printer")
        router = next(item for item in devices if item["hostname"] == "gateway")
        server = next(item for item in devices if item["hostname"] == "home-server")
        self.assertEqual(printer["effective_type"], "printer")
        self.assertGreater(printer["confidence"], 0.9)
        self.assertEqual(router["effective_type"], "router")
        self.assertEqual(server["effective_type"], "server")
        self.assertEqual(self.db.summary()["links"], 2)

    def test_standard_nmap_doctype_is_allowed_but_custom_dtd_is_rejected(self) -> None:
        xml = (ROOT / "examples" / "demo-nmap.xml").read_bytes()
        with_doctype = xml.replace(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>",
        )
        self.assertEqual(import_nmap_xml(self.db, with_doctype), 3)
        malicious = with_doctype.replace(b"<!DOCTYPE nmaprun>", b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">')
        with self.assertRaises(ValueError):
            import_nmap_xml(self.db, malicious)

    def test_arp_scan_merges_by_mac_and_tracks_vendor(self) -> None:
        text = (ROOT / "examples" / "demo-arp.txt").read_text()
        self.assertEqual(import_arp_scan(self.db, text), 4)
        import_arp_scan(self.db, "192.168.50.99 b8:27:eb:00:00:20 Raspberry Pi Foundation")
        devices = self.db.devices()
        pi = next(item for item in devices if item["mac"] == "b8:27:eb:00:00:20")
        self.assertIn("192.168.50.20", pi["addresses"])
        self.assertIn("192.168.50.99", pi["addresses"])

    def test_reused_ip_with_new_mac_creates_new_device(self) -> None:
        import_arp_scan(self.db, "10.23.45.5 00:11:22:33:44:55 Vendor One")
        import_arp_scan(self.db, "10.23.45.5 00:11:22:33:44:66 Vendor Two")
        self.assertEqual(len(self.db.devices()), 2)

    def test_scan_scope_can_be_reconciled_offline(self) -> None:
        import_arp_scan(self.db, "10.23.45.5 00:11:22:33:44:55 Vendor One")
        import_arp_scan(self.db, "10.1.1.5 00:11:22:33:44:66 Vendor Two")
        changed = self.db.mark_network_offline(validate_target("10.23.45.0/24"))
        self.assertEqual(changed, 1)
        statuses = {
            item["mac"]: item["status"]
            for item in self.db.devices(online_only=False)
        }
        self.assertEqual(statuses["00:11:22:33:44:55"], "offline")
        self.assertEqual(statuses["00:11:22:33:44:66"], "online")
        # The default view is the point of the change: only live hosts appear.
        self.assertEqual(
            [item["mac"] for item in self.db.devices()], ["00:11:22:33:44:66"]
        )

    def test_down_hosts_are_not_recorded_as_devices(self) -> None:
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="up"/><address addr="10.23.45.5" addrtype="ipv4"/></host>'
            '<host><status state="down"/><address addr="10.23.45.6" addrtype="ipv4"/></host>'
            '<host><status state="down"/><address addr="10.23.45.7" addrtype="ipv4"/></host>'
            "</nmaprun>"
        )
        self.assertEqual(import_nmap_xml(self.db, xml.encode()), 1)
        addresses = [item["primary_address"] for item in self.db.devices()]
        self.assertEqual(addresses, ["10.23.45.5"])

    def test_prune_removes_scan_residue_but_keeps_identified_hosts(self) -> None:
        residue = self.db.ensure_device(address="10.23.45.9", status="offline")
        known = self.db.ensure_device(
            mac="00:11:22:33:44:77", address="10.23.45.10", status="offline"
        )
        self.db.commit()
        self.assertEqual(self.db.prune_ghosts(), 1)
        remaining = {item["id"] for item in self.db.devices(online_only=False)}
        self.assertNotIn(residue, remaining)
        self.assertIn(known, remaining)

    def test_os_family_disambiguates_cisco_ios_from_apple(self) -> None:
        self.assertEqual(os_family("Cisco IOS 15.2"), "network-os")
        self.assertEqual(os_family("iPhone OS 15"), "apple-mobile")
        self.assertEqual(
            os_family("Apple macOS 11 (Big Sur) - 13 (Ventura) or iOS 16"), "apple"
        )

    def test_network_os_guess_yields_to_a_named_device(self) -> None:
        # A Linux host mis-fingerprinted as OpenWrt must not become a router when
        # its own hostname and vendor say otherwise.
        kind, _confidence, _why, _family = classify({
            "os_name": "OpenWrt 21.02 (Linux 5.4)",
            "hostname": "debian-4",
            "vendor": "Dell Inc.",
            "services": [],
            "observations": [],
        })
        self.assertEqual(kind, "computer")
        # With no competing evidence the same fingerprint is decisive.
        kind, _confidence, _why, _family = classify({
            "os_name": "OpenWrt 21.02 (Linux 5.4)",
            "services": [],
            "observations": [],
        })
        self.assertEqual(kind, "router")

    def test_placeholder_and_multicast_macs_are_rejected(self) -> None:
        self.assertIsNone(normalize_mac("00:00:00:00:00:00"))
        self.assertIsNone(normalize_mac("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(normalize_mac("01:00:0c:cc:cc:cc"))
        self.assertEqual(normalize_mac("B4-22-00-B6-84-5B"), "b4:22:00:b6:84:5b")

    def test_nmap_hostnames_are_cleaned_like_every_other_source(self) -> None:
        # Nmap reports the PTR name verbatim while mDNS and NetBIOS are cleaned.
        # Left inconsistent, the sources overwrite each other on every scan and each
        # swap logs a spurious "name changed" event.
        xml = (
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="10.23.45.5" addrtype="ipv4"/>'
            '<hostnames><hostname name="workstation.home" type="PTR"/></hostnames>'
            "</host></nmaprun>"
        )
        import_nmap_xml(self.db, xml.encode())
        self.assertEqual(self.db.devices()[0]["hostname"], "workstation")

    def test_hostname_cleaning_strips_zones_and_junk(self) -> None:
        self.assertEqual(clean_hostname("sherlock.local"), "sherlock")
        self.assertEqual(clean_hostname("vault.lyrs.lan"), "vault")
        self.assertEqual(clean_hostname("WS-KAKASHI<20>"), "WS-KAKASHI")
        self.assertIsNone(clean_hostname("*"))
        self.assertIsNone(clean_hostname("__MSBROWSE__"))
        # A public FQDN keeps its domain, which is meaningful outside a local zone.
        self.assertEqual(clean_hostname("nas.example.com"), "nas.example.com")

    def test_avahi_escapes_are_decoded(self) -> None:
        self.assertEqual(unescape_avahi(r"MacBook\032Air"), "MacBook Air")
        self.assertEqual(unescape_avahi(r"\091LG\093\032webOS"), "[LG] webOS")

    def test_oui_lookup_and_randomized_detection(self) -> None:
        # Skips cleanly on a host without the Nmap or arp-scan vendor database.
        if oui.size() == 0:
            self.skipTest("no local OUI database")
        self.assertTrue(oui.lookup("b4:22:00:b6:84:5b"))
        self.assertTrue(oui.is_randomized("ce:70:13:a3:53:47"))
        self.assertIsNone(oui.lookup("ce:70:13:a3:53:47"))

    def test_orphaned_child_rows_do_not_break_later_collectors(self) -> None:
        # Another client deleting a device without foreign keys enabled leaves an
        # addresses row behind. ensure_device used to crash reading its vanished row.
        device_id = self.db.ensure_device(mac="00:11:22:33:44:88", address="10.23.45.20")
        self.db.commit()
        self.db.conn.execute("PRAGMA foreign_keys = OFF")
        self.db.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        self.db.conn.commit()
        self.assertEqual(
            self.db.conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0], 1
        )
        # Re-observing the same address must succeed rather than raise.
        again = self.db.ensure_device(address="10.23.45.20", status="online")
        self.db.commit()
        self.assertIsInstance(again, int)
        self.assertEqual(self.db._purge_orphans(), 0)

    def test_purge_orphans_clears_every_child_table(self) -> None:
        device_id = self.db.ensure_device(mac="00:11:22:33:44:99", address="10.23.45.21")
        other_id = self.db.ensure_device(mac="00:11:22:33:44:aa", address="10.23.45.22")
        self.db.add_service(device_id, "tcp", 80, name="http")
        self.db.add_observation(device_id, "test", "key", "value")
        self.db.add_edge(device_id, other_id, "attachment")
        self.db.commit()
        self.db.conn.execute("PRAGMA foreign_keys = OFF")
        self.db.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        self.db.conn.commit()
        self.assertEqual(self.db._purge_orphans(), 4)
        for table in ("addresses", "services", "observations", "edges"):
            remaining = self.db.conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE "
                + ("source_device_id=?" if table == "edges" else "device_id=?"),
                (device_id,),
            ).fetchone()[0]
            self.assertEqual(remaining, 0, table)

    def test_a_second_claimant_cannot_take_a_live_address(self) -> None:
        # A relayed or spoofed announcement must not fork the map into two copies
        # of one host, which is what produced a phantom second gateway.
        holder = self.db.ensure_device(
            mac="00:11:22:33:44:01", address="10.23.45.1", status="online"
        )
        intruder = self.db.ensure_device(
            mac="00:11:22:33:44:02", address="10.23.45.1", status="online"
        )
        self.db.commit()
        self.assertNotEqual(holder, intruder)
        owners = [
            row["device_id"]
            for row in self.db.conn.execute(
                "SELECT device_id FROM addresses WHERE address='10.23.45.1'"
            )
        ]
        self.assertEqual(owners, [holder])
        # The contested claim is kept as evidence rather than silently dropped.
        conflicts = self.db.conn.execute(
            "SELECT value FROM observations WHERE device_id=? AND key='address_claim'",
            (intruder,),
        ).fetchall()
        self.assertEqual(len(conflicts), 1)
        self.assertIn("00:11:22:33:44:01", conflicts[0]["value"])

    def test_an_offline_holder_releases_its_address(self) -> None:
        holder = self.db.ensure_device(
            mac="00:11:22:33:44:03", address="10.23.45.2", status="online"
        )
        self.db.update_device(holder, status="offline")
        self.db.commit()
        successor = self.db.ensure_device(
            mac="00:11:22:33:44:04", address="10.23.45.2", status="online"
        )
        self.db.commit()
        owners = {
            row["device_id"]
            for row in self.db.conn.execute(
                "SELECT device_id FROM addresses WHERE address='10.23.45.2'"
            )
        }
        self.assertIn(successor, owners)

    def test_hostname_rules_handle_run_together_manufacturer_names(self) -> None:
        # Vendors ship names with the words jammed together, so a word-boundary
        # match alone misses them; ambiguous short tokens must still be bounded.
        expected = {
            "SHIELDANDROIDTV": "media",
            "LGwebOSTV": "media",
            "FIRETVSTICK": "media",
            "chromecast-audio": "media",
            "DISKSTATION": "storage",
            "PLAYSTATION5": "game-console",
            "MacBook-Air-de-raph": "computer",
            "JULIE-PC": "computer",
            "iPhone-de-Paul": "phone",
            # Negatives: these must not be swept up by a loose substring.
            "tvm-build-server": "server",
            "paddle-01": "unknown",
        }
        for hostname, kind in expected.items():
            actual, _confidence, _why, _family = classify(
                {"hostname": hostname, "services": [], "observations": []}
            )
            self.assertEqual(actual, kind, hostname)

    def _replay(self, lines):
        """Feed verbatim Nmap output through the progress parser."""
        state, events = {}, []
        for line in lines:
            collectors._report_line(
                line, lambda percent, detail: events.append((percent, detail)), state
            )
        return events

    def test_every_nmap_progress_line_produces_an_event(self) -> None:
        # Progress is regex-driven off Nmap's stdout and breaks silently; these are
        # verbatim lines from Nmap 7.99 under -v --stats-every.
        lines = (
            "Initiating ARP Ping Scan at 17:10",
            "Scanning 17 hosts [200 ports/host]",
            "Initiating SYN Stealth Scan at 17:10",
            "Discovered open port 443/tcp on 192.168.1.1",
            "Completed ARP Ping Scan at 17:10, 0.06s elapsed (1 total hosts)",
            "Stats: 0:00:14 elapsed; 0 hosts completed (17 up), 17 undergoing Service Scan",
            "Service scan Timing: About 47.06% done; ETC: 17:12 (0:00:07 remaining)",
            "Initiating OS detection (try #1) against 3 hosts",
            "Initiating Traceroute at 17:12",
            "NSE: Script scanning 3 hosts.",
            "Nmap scan report for 192.168.1.50",
            "Nmap done: 8 IP addresses (3 hosts up) scanned in 95.20 seconds",
        )
        for line in lines:
            self.assertTrue(self._replay([line]), f"no event for: {line}")

    def test_progress_is_phase_scaled_and_monotonic(self) -> None:
        # Nmap's percentage is per phase, so reporting it raw would show 47% with
        # six phases still to run. The bar must scale it and never go backwards.
        events = self._replay([
            "Initiating ARP Ping Scan at 20:30",
            "Initiating SYN Stealth Scan at 20:30",
            "SYN Stealth Scan Timing: About 60.00% done; ETC: 20:32",
            "Completed SYN Stealth Scan at 20:31, 30s elapsed (200 total ports)",
            "Initiating Service scan at 20:31",
            "Service scan Timing: About 50.00% done; ETC: 20:33",
            "Initiating OS detection (try #1) against 3 hosts",
            "Initiating Traceroute at 20:33",
            "NSE: Script scanning 3 hosts.",
            "Nmap done: 8 IP addresses (3 hosts up) scanned in 95.20 seconds",
        ])
        bars = [percent for percent, _detail in events if percent >= 0]
        self.assertEqual(bars, sorted(bars), "progress went backwards")
        self.assertEqual(bars[-1], 100.0)
        # A phase at 60% must not be reported as 60% of the whole scan.
        syn = next(p for p, d in events if "SYN Stealth Scan: 60%" in d)
        self.assertLess(syn, 45.0)

    def test_unreachable_hosts_are_not_announced_as_found(self) -> None:
        # --reason writes "[host down, received no-response]", so an exact match on
        # "[host down]" silently announced every dead address as a discovery.
        for line in (
            "Nmap scan report for 192.168.1.48 [host down, received no-response]",
            "Nmap scan report for 192.168.1.1 [host down]",
        ):
            details = [detail for _percent, detail in self._replay([line])]
            self.assertFalse(
                [d for d in details if "Found host" in d], f"announced a down host: {line}"
            )
        found = [d for _p, d in self._replay(["Nmap scan report for 192.168.1.50"])]
        self.assertIn("Found host 192.168.1.50", found)

    def test_scan_profiles_use_raw_packet_flags_when_available(self) -> None:
        for profile in collectors.PROFILES:
            command = collectors.nmap_command("10.23.45.0/24", profile)
            self.assertIn("10.23.45.0/24", command)
            self.assertIn("-oX", command)
            # Progress reporting must be requested or the viewer shows nothing.
            self.assertIn("--stats-every", command)
        # XML must go to a file when one is given: `-oX -` takes stdout, which is
        # where Nmap reports progress, and silences it completely.
        to_file = collectors.nmap_command("10.23.45.0/24", "standard", xml_path="/tmp/x.xml")
        self.assertEqual(to_file[to_file.index("-oX") + 1], "/tmp/x.xml")
        with self.assertRaises(ValueError):
            collectors.nmap_command("10.23.45.0/24", "nonsense")

    def test_passive_error_paths_raise_a_real_exception(self) -> None:
        # These raise sites are only reached at runtime, so a missing class name
        # imports cleanly and then fails mid-scan with a NameError instead.
        original = passive.shutil.which
        try:
            passive.shutil.which = lambda name: None
            with self.assertRaises(passive.PassiveError):
                passive.capture("eth0", 10)
        finally:
            passive.shutil.which = original
        self.assertTrue(issubclass(passive.PassiveError, RuntimeError))

    def test_passive_rejects_unsafe_interface_names(self) -> None:
        for bad in ("eth0; rm -rf /", "eth0 && curl evil", "", "eth0|nc"):
            with self.assertRaises(ValueError):
                passive._validate_interface(bad)
        self.assertEqual(passive._validate_interface("eth0"), "eth0")
        self.assertEqual(passive._validate_interface("wlp3s0"), "wlp3s0")

    def test_job_validation_rejects_bad_requests_before_queueing(self) -> None:
        # A malformed request must be refused outright, not accepted and then
        # failed once it starts, and never masked by the concurrency check.
        for kind, parameters in (
            ("scan", {"profile": "turbo"}),
            ("passive", {"duration": 99999}),
            ("passive", {"interface": "eth0; rm -rf /"}),
        ):
            with self.assertRaises((jobs.UnknownJobError, ValueError)):
                jobs._validate(kind, parameters)
        with self.assertRaises(ValueError):
            jobs._validate("scan", {"target": "8.8.8.0/24"})
        # Valid requests pass untouched.
        jobs._validate("scan", {"profile": "deep", "target": "192.168.1.0/24"})
        jobs._validate("passive", {"duration": 60, "interface": "eth0"})

    def test_sweep_stages_map_onto_separate_progress_bands(self) -> None:
        # Each stage of a sweep reports its own 0-100%, so without banding the bar
        # restarts at every stage instead of advancing once end to end.
        class Recorder:
            def __init__(self) -> None:
                self.seen: list[float] = []

            def report(self, percent: float, detail: str) -> None:
                if percent >= 0:
                    self.seen.append(percent)

        recorder = Recorder()
        for low, high in ((6.0, 62.0), (62.0, 74.0), (74.0, 99.0)):
            band = jobs._band(recorder, low, high)
            for stage_percent in (0, 25, 50, 100):
                band(stage_percent, "stage")
            self.assertAlmostEqual(recorder.seen[-1], high)
        self.assertEqual(recorder.seen, sorted(recorder.seen), "progress went backwards")
        # A stage reporting out-of-range values must stay inside its band.
        band = jobs._band(recorder, 10.0, 20.0)
        band(-500, "detail-only")
        band(9999, "over")
        self.assertLessEqual(recorder.seen[-1], 20.0)

    def test_link_local_only_rows_fold_into_the_device_that_owns_the_mac(self) -> None:
        # A router is reached over IPv4 and over IPv6 link-local. If the link-local
        # side lands before its MAC is known it becomes a second row, and the map
        # shows one router twice.
        router = self.db.ensure_device(
            mac="38:07:16:12:bc:ef", address="192.168.1.254", status="online"
        )
        stray = self.db.ensure_device(
            address="fe80::3a07:16ff:fe12:bcef", family="ipv6", status="online"
        )
        self.db.add_observation(stray, "route", "default_gateway", "IPv6 default", 0.9)
        self.db.commit()
        self.assertNotEqual(router, stray)

        original = ingest.netinfo.neighbours
        try:
            ingest.netinfo.neighbours = lambda: [{
                "address": "fe80::3a07:16ff:fe12:bcef",
                "mac": "38:07:16:12:bc:ef",
                "interface": "eth0", "family": "ipv6",
                "state": "REACHABLE", "reachable": True, "link_local": True,
            }]
            self.assertEqual(ingest.fold_link_local_duplicates(self.db), 1)
        finally:
            ingest.netinfo.neighbours = original

        remaining = {item["id"] for item in self.db.devices(online_only=False)}
        self.assertNotIn(stray, remaining)
        self.assertIn(router, remaining)
        merged = next(item for item in self.db.devices() if item["id"] == router)
        self.assertIn("fe80::3a07:16ff:fe12:bcef", merged["addresses"])
        self.assertIn("192.168.1.254", merged["addresses"])
        # Evidence from the folded row must survive the merge.
        keys = [row["key"] for row in self.db.conn.execute(
            "SELECT key FROM observations WHERE device_id=?", (router,))]
        self.assertIn("default_gateway", keys)

    def test_a_routable_address_is_never_folded_away(self) -> None:
        # Only link-local-only rows may fold; a real address means a real device.
        keeper = self.db.ensure_device(address="192.168.1.77", status="online")
        self.db.ensure_device(mac="38:07:16:12:bc:e0", address="192.168.1.78", status="online")
        self.db.commit()
        original = ingest.netinfo.neighbours
        try:
            ingest.netinfo.neighbours = lambda: [{
                "address": "192.168.1.77", "mac": "38:07:16:12:bc:e0",
                "interface": "eth0", "family": "ipv4",
                "state": "REACHABLE", "reachable": True, "link_local": False,
            }]
            self.assertEqual(ingest.fold_link_local_duplicates(self.db), 0)
        finally:
            ingest.netinfo.neighbours = original
        self.assertIn(keeper, {item["id"] for item in self.db.devices(online_only=False)})

    def test_hidden_attribute_beats_component_display_rules(self) -> None:
        """The viewer hides panels with the `hidden` attribute, which only works
        through a user-agent `display: none` that ANY author `display` outranks.
        Several components set their own (`.modal` is `display: grid`), so without
        an explicit override the scan dialog's full-screen backdrop never went away.
        """
        static = ROOT / "network_atlas" / "static"
        css = (static / "style.css").read_text()
        html = (static / "index.html").read_text()
        app = (static / "app.js").read_text()

        self.assertRegex(
            css, r"\[hidden\]\s*\{[^}]*display:\s*none\s*!important",
            "missing the [hidden] override; elements with an author display will not hide",
        )

        # Every element toggled via `hidden` must still have a display to return to.
        toggled = set(re.findall(r'\$\("#([a-zA-Z0-9_-]+)"\)\.hidden', app))
        toggled |= set(re.findall(r'id="([a-zA-Z0-9_-]+)"[^>]*\shidden', html))
        self.assertIn("scan-modal", toggled)
        self.assertIn("drawer", toggled)
        for element_id in toggled:
            self.assertRegex(
                html, r'id="' + re.escape(element_id) + r'"',
                f"#{element_id} is toggled in JS but absent from the markup",
            )

    # -- events -----------------------------------------------------------
    def _seed_pair(self):
        first = self.db.ensure_device(
            mac="00:11:22:33:aa:01", address="10.23.45.11", hostname="alpha", status="online"
        )
        second = self.db.ensure_device(
            mac="00:11:22:33:aa:02", address="10.23.45.12", hostname="beta", status="online"
        )
        self.db.commit()
        return first, second

    def test_events_detect_arrival_departure_and_ports(self) -> None:
        first, _second = self._seed_pair()
        before = events.snapshot(self.db)
        # A new device, a port on an existing one, and one going away.
        self.db.ensure_device(mac="00:11:22:33:aa:03", address="10.23.45.13", status="online")
        self.db.add_service(first, "tcp", 22, name="ssh")
        self.db.update_device(_second, status="offline")
        self.db.commit()
        emitted = {event["kind"] for event in events.diff(self.db, before)}
        self.assertIn("device-appeared", emitted)
        self.assertIn("port-opened", emitted)
        self.assertIn("device-left", emitted)
        # And they are persisted for the timeline.
        self.assertGreaterEqual(len(self.db.events()), 3)

    def test_events_flag_an_address_changing_hands(self) -> None:
        # The security-relevant transition: one address, a different MAC.
        original = self.db.ensure_device(
            mac="00:11:22:33:bb:01", address="10.23.45.20", status="online"
        )
        self.db.commit()
        before = events.snapshot(self.db)
        self.db.update_device(original, status="offline")
        self.db.commit()
        successor = self.db.ensure_device(
            mac="00:11:22:33:bb:02", address="10.23.45.20", status="online"
        )
        self.db.commit()
        self.assertNotEqual(original, successor)
        kinds = {event["kind"] for event in events.diff(self.db, before)}
        self.assertIn("address-reassigned", kinds)
        record = next(
            item for item in self.db.events() if item["kind"] == "address-reassigned"
        )
        self.assertEqual(record["severity"], "medium")

    def test_no_events_when_nothing_changed(self) -> None:
        self._seed_pair()
        before = events.snapshot(self.db)
        self.assertEqual(events.diff(self.db, before), [])

    # -- findings ---------------------------------------------------------
    def test_exposed_service_findings_carry_a_remediation(self) -> None:
        device_id = self.db.ensure_device(
            mac="00:11:22:33:cc:01", address="10.23.45.30", hostname="nas", status="online"
        )
        self.db.add_service(device_id, "tcp", 23, name="telnet")
        self.db.commit()
        findings.evaluate(self.db)
        rows = [row for row in self.db.findings() if row["kind"] == "exposed-service"]
        self.assertTrue(rows)
        telnet = next(row for row in rows if row["port"] == 23)
        self.assertEqual(telnet["severity"], "high")
        # Every finding must say what to do about it, or it is just noise.
        for row in self.db.findings():
            self.assertTrue(row["remediation"], f"{row['kind']} has no remediation")
            self.assertTrue(row["detail"], f"{row['kind']} has no explanation")

    def test_findings_resolve_when_the_issue_goes_away(self) -> None:
        device_id = self.db.ensure_device(
            mac="00:11:22:33:cc:02", address="10.23.45.31", status="online"
        )
        self.db.add_service(device_id, "tcp", 23, name="telnet")
        self.db.commit()
        findings.evaluate(self.db)
        opened = next(row for row in self.db.findings() if row["port"] == 23)
        first_seen = opened["first_seen"]

        # Re-running keeps first_seen rather than resetting the age of the issue.
        findings.evaluate(self.db)
        again = next(row for row in self.db.findings() if row["port"] == 23)
        self.assertEqual(again["first_seen"], first_seen)

        self.db.conn.execute("DELETE FROM services WHERE device_id=?", (device_id,))
        self.db.commit()
        findings.evaluate(self.db)
        self.assertFalse([row for row in self.db.findings() if row["port"] == 23])
        resolved = self.db.findings(include_resolved=True)
        self.assertTrue([row for row in resolved if row["resolved_at"]])

    def test_unapproved_rule_stays_quiet_until_approval_is_used(self) -> None:
        self.db.ensure_device(mac="00:11:22:33:cc:03", address="10.23.45.32", status="online")
        self.db.commit()
        findings.evaluate(self.db)
        self.assertFalse(
            [row for row in self.db.findings() if row["kind"] == "unapproved-device"],
            "should not nag before the user has approved anything",
        )
        approved = self.db.ensure_device(
            mac="00:11:22:33:cc:04", address="10.23.45.33", status="online"
        )
        self.db.update_device(approved, approved=1)
        self.db.commit()
        findings.evaluate(self.db)
        self.assertTrue(
            [row for row in self.db.findings() if row["kind"] == "unapproved-device"]
        )

    def test_muted_findings_are_hidden_but_kept(self) -> None:
        device_id = self.db.ensure_device(
            mac="00:11:22:33:cc:05", address="10.23.45.34", status="online"
        )
        self.db.add_service(device_id, "tcp", 23, name="telnet")
        self.db.commit()
        findings.evaluate(self.db)
        row = next(item for item in self.db.findings() if item["port"] == 23)
        self.db.set_finding_muted(row["id"], True)
        self.assertFalse([item for item in self.db.findings() if item["port"] == 23])
        self.assertTrue(
            [item for item in self.db.findings(include_muted=True) if item["port"] == 23]
        )

    # -- exploit correlation ---------------------------------------------
    def test_product_normalization_and_candidate_terms(self) -> None:
        self.assertEqual(vulns._normalize_product("OpenSSH 8.4p1 Debian"), "openssh")
        self.assertEqual(vulns._normalize_product("Samba smbd 4.13.13"), "samba")
        # Apache alone is ambiguous, so the daemon word is kept as a fallback term.
        self.assertIn("apache httpd", vulns._candidate_terms("Apache httpd 2.4.51"))
        # The recognisable product can hide in a parenthetical.
        self.assertIn("webmin", vulns._candidate_terms("MiniServ 1.830 (Webmin httpd)"))
        # Too generic to correlate at all.
        self.assertEqual(vulns._candidate_terms("tcpwrapped"), [])

    def test_version_matching_rejects_a_bare_major(self) -> None:
        # A bare "4" once matched "Sambar Server 4.x" -- a different product -- and
        # was reported as an exact version match.
        self.assertFalse(vulns._version_matches("4", "Sambar Server 4.x/5.0 - Default Password"))
        self.assertTrue(vulns._version_matches("2.3.4", "vsftpd 2.3.4 - Backdoor"))
        self.assertFalse(vulns._version_matches("2.3.4", "vsftpd 2.0.5 - Memory Consumption"))
        # Patch suffixes and series matches are both meaningful.
        self.assertTrue(vulns._version_matches("9.6p1", "OpenSSH 9.6 - Something"))
        self.assertTrue(vulns._version_matches("1.4.53", "lighttpd 1.4.x - Denial of Service"))

    def test_exploit_records_are_ranked_by_product_prefix(self) -> None:
        records = [
            {"Title": "Ingress-NGINX 4.11.0 - Remote Code Execution"},
            {"Title": "Nginx 1.20 - Local Privilege Escalation"},
        ]
        ranked = vulns._rank(records, "nginx")
        self.assertTrue(ranked[0]["Title"].lower().startswith("nginx"))

    # -- TLS --------------------------------------------------------------
    def test_tls_findings_from_sslscan_xml(self) -> None:
        xml = """<document><ssltest host="10.23.45.40" port="443">
          <protocol type="ssl" version="3" enabled="1"/>
          <protocol type="tls" version="1.2" enabled="1"/>
          <heartbleed sslversion="TLSv1.2" vulnerable="1"/>
          <cipher status="accepted" sslversion="TLSv1.2" bits="56"
                  cipher="DES-CBC-SHA" strength="weak"/>
          <certificate type="short">
            <signature-algorithm>sha1WithRSAEncryption</signature-algorithm>
            <subject>nas.lan</subject>
            <self-signed>true</self-signed>
            <expired>true</expired>
            <not-valid-after>Jan  1 00:00:00 2020 GMT</not-valid-after>
          </certificate>
        </ssltest></document>"""
        device_id = self.db.ensure_device(
            mac="00:11:22:33:dd:01", address="10.23.45.40", hostname="nas", status="online"
        )
        self.db.commit()
        created = tlsaudit._evaluate(
            self.db, device_id, "nas", "10.23.45.40", 443,
            ET.fromstring(xml), "2026-01-01T00:00:00Z",
        )
        self.db.commit()
        self.assertGreaterEqual(created, 5)
        kinds = {row["kind"] for row in self.db.findings()}
        self.assertIn("tls-protocol", kinds)
        self.assertIn("tls-vulnerability", kinds)
        self.assertIn("tls-ciphers", kinds)
        self.assertIn("tls-certificate", kinds)
        heartbleed = next(
            row for row in self.db.findings() if row["kind"] == "tls-vulnerability"
        )
        self.assertEqual(heartbleed["severity"], "high")

    # -- p0f --------------------------------------------------------------
    def test_p0f_output_is_parsed_and_attributed(self) -> None:
        output = """
.-[ 10.23.45.50/443 -> 10.23.45.1/52778 (syn+ack) ]-
|
| server   = 10.23.45.50/443
| os       = Linux 5.x
| dist     = 0
| link     = Ethernet or modem
|
`----
"""
        original = fingerprint.subprocess.run
        try:
            fingerprint.subprocess.run = lambda *a, **k: type(
                "R", (), {"stdout": output, "stderr": "", "returncode": 0}
            )()
            parsed = fingerprint.analyze(ROOT / "README.md")
        finally:
            fingerprint.subprocess.run = original
        self.assertIn("10.23.45.50", parsed)
        self.assertEqual(parsed["10.23.45.50"]["os"], "Linux 5.x")
        self.assertEqual(parsed["10.23.45.50"]["role"], "server")
        # A server-side fingerprint describes the remote host, so it scores higher.
        entries = fingerprint.to_observations(parsed)["10.23.45.50"]
        os_entry = next(item for item in entries if item[0] == "p0f_os")
        self.assertGreater(os_entry[2], 0.6)

    def test_dhcp_vendor_class_identifies_platforms(self) -> None:
        # DHCP is broadcast, so unlike TCP this signal survives a switch -- it is
        # the passive OS evidence that actually reaches us on a normal network.
        expected = {
            "MSFT 5.0": ("windows", None),
            "android-dhcp-13": ("android", "phone"),
            "dhcpcd-9.4.1": ("linux", None),
            "udhcp 1.36.1": ("embedded", "iot"),
            "AAPLBM": ("apple", None),
            "Roku": (None, "media"),
            "PlayStation 5": (None, "game-console"),
            "HP LaserJet 400": (None, "printer"),
            "ArubaAP": (None, "access-point"),
        }
        for vendor_class, (family, kind) in expected.items():
            result = fingerprint.classify_dhcp(vendor_class)
            self.assertIsNotNone(result, vendor_class)
            self.assertEqual(result["os_family"], family, vendor_class)
            self.assertEqual(result["device_type"], kind, vendor_class)
        # An unknown string is common and must not be forced into a guess.
        self.assertIsNone(fingerprint.classify_dhcp("some-unknown-client"))
        self.assertIsNone(fingerprint.classify_dhcp(""))
        self.assertIsNone(fingerprint.classify_dhcp(None))

    def test_classification_from_dhcp_alone(self) -> None:
        for vendor_class, kind in (
            ("android-dhcp-13", "phone"),
            ("Roku", "media"),
            ("HP LaserJet 400", "printer"),
            ("PlayStation 5", "game-console"),
            ("MSFT 5.0", "computer"),
        ):
            actual, _confidence, why, _family = classify({
                "services": [],
                "observations": [{"key": "dhcp_vendor_class", "value": vendor_class}],
            })
            self.assertEqual(actual, kind, vendor_class)
            # A reason that reads "detected: None" is worse than no reason.
            self.assertNotIn("None", why[0], vendor_class)

    def test_classification_reasons_never_say_none(self) -> None:
        # Reasons are shown to the user verbatim in the device drawer.
        for data in (
            {"observations": [{"key": "dhcp_vendor_class", "value": "AAPLBM"}]},
            {"observations": [{"key": "dhcp_vendor_class", "value": "udhcp 1.0"}]},
            {"os_name": "Android 13", "observations": []},
            {"observations": []},
        ):
            data.setdefault("services", [])
            _kind, _confidence, why, _family = classify(data)
            for reason in why:
                self.assertNotIn("None", reason, data)

    # -- container image --------------------------------------------------
    def test_dockerfile_installs_every_tool_the_code_shells_out_to(self) -> None:
        """The image must not drift from the code's external dependencies.

        Every collector resolves its binary with shutil.which() at runtime and
        degrades quietly when it is absent, so a tool missing from the image would
        not fail the build or raise -- the feature would just silently never work.
        """
        dockerfile = ROOT / "Dockerfile"
        if not dockerfile.is_file():
            self.skipTest("no Dockerfile")
        content = dockerfile.read_text()

        # Binary -> Debian package that provides it. Tools intentionally left out
        # of the image are mapped to None, with the reason in the comment.
        expected = {
            "python3": "python3",
            "ip": "iproute2",
            "nmap": "nmap",
            "arp-scan": "arp-scan",
            "tshark": "tshark",
            "dumpcap": "tshark",
            "nbtscan": "nbtscan",
            "dig": "dnsutils",
            "avahi-browse": "avahi-utils",
            "avahi-resolve": "avahi-utils",
            "p0f": "p0f",
            "searchsploit": "exploitdb",
            "sslscan": "sslscan",
            "whatweb": "whatweb",
            "snmpwalk": "snmp",
            "setcap": "libcap2-bin",
            "getcap": "libcap2-bin",
            # Monitor mode needs the host's physical interface and drops the
            # connection, so the Wi-Fi survey is host-only by design.
            "airmon-ng": None,
            "airodump-ng": None,
            "iw": None,
            # Capabilities replace elevation inside the container.
            "sudo": None,
        }

        discovered: set[str] = set()
        for module in (ROOT / "network_atlas").glob("*.py"):
            text = module.read_text()
            discovered |= set(re.findall(r'shutil\.which\("([a-z0-9_.-]+)"\)', text))
            discovered |= set(re.findall(r'_require\("([a-z0-9_.-]+)"\)', text))

        unmapped = sorted(discovered - expected.keys())
        self.assertFalse(
            unmapped,
            f"code depends on {unmapped} but the test does not say which package "
            "provides them; add them to the image or record why they are excluded",
        )
        for binary in sorted(discovered):
            package = expected[binary]
            if package is None:
                continue
            self.assertIn(
                package, content,
                f"{binary} is used by the code but {package} is not installed in the image",
            )

    def test_dockerfile_and_compose_stay_host_networked_and_unprivileged(self) -> None:
        """Two properties the container cannot work without, and one it must not have."""
        dockerfile = ROOT / "Dockerfile"
        compose = ROOT / "docker-compose.yml"
        if not dockerfile.is_file() or not compose.is_file():
            self.skipTest("no container files")
        image = dockerfile.read_text()
        # Comments explain why some settings are deliberately absent, so they must
        # not be searched for those settings' names.
        stack = "\n".join(
            line for line in compose.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )

        # Host networking: on the default bridge the container is behind NAT on its
        # own segment, so ARP scans and broadcast discovery reach nothing.
        self.assertIn("network_mode: host", stack)
        # Unprivileged: capabilities on the binaries, not root for the process.
        self.assertIn("USER atlas", image)
        self.assertIn("setcap", image)
        self.assertNotIn("privileged: true", stack)
        # tshark needs NET_ADMIN, which is not in Docker's default capability set.
        self.assertIn("NET_ADMIN", stack)
        self.assertIn("cap_drop", stack)

        # no-new-privileges must stay off: it stops the kernel honouring file
        # capabilities, so nmap loses raw sockets and every scan quietly falls
        # back to an unprivileged connect scan. The dropped bounding set is the
        # real constraint. Asserted so it cannot be re-added as a "hardening" win.
        self.assertNotIn("no-new-privileges", stack)

        # Granting a capability the bounding set does not include makes the
        # binary unexecutable: execve returns EPERM before it runs.
        for granted in re.findall(r"setcap ([a-z_,]+)\+eip", image):
            for capability in granted.split(","):
                self.assertIn(
                    capability.removeprefix("cap_").upper(), stack,
                    f"{capability} is granted on a binary but not added in compose, "
                    "which makes that binary fail to exec with EPERM",
                )

    def test_isolated_container_is_detected_and_reported(self) -> None:
        """A container that cannot reach the LAN must say so, not return an empty map.

        On Docker's default bridge, and on Docker Desktop for macOS/Windows, the
        network namespace is NAT'd: discovery describes the container's own
        segment. Left undetected this looks exactly like a network with nothing on
        it, which is the most misleading failure this tool can have.
        """
        original = findings.netinfo.container_info
        try:
            findings.netinfo.container_info = lambda: {
                "in_container": True, "runtime": "docker", "wsl": False,
                "network_isolated": True,
                "isolation_reason": "the container is on a private bridge network",
            }
            findings.evaluate(self.db)
        finally:
            findings.netinfo.container_info = original
        rows = [row for row in self.db.findings() if row["kind"] == "container-isolated"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        # It must name a way out, not just report the problem.
        self.assertIn("host networking", rows[0]["remediation"])
        self.assertIn("macvlan", rows[0]["remediation"])

    def test_healthy_deployment_raises_no_isolation_finding(self) -> None:
        original = findings.netinfo.container_info
        try:
            for environment in (
                {"in_container": False, "runtime": None, "wsl": False,
                 "network_isolated": False, "isolation_reason": None},
                {"in_container": True, "runtime": "docker", "wsl": False,
                 "network_isolated": False, "isolation_reason": None},
            ):
                self.db.conn.execute("DELETE FROM findings")
                self.db.commit()
                findings.netinfo.container_info = lambda env=environment: env
                findings.evaluate(self.db)
                self.assertFalse(
                    [r for r in self.db.findings() if r["kind"] == "container-isolated"],
                    environment,
                )
        finally:
            findings.netinfo.container_info = original

    def test_isolation_detection_needs_a_container(self) -> None:
        # The bridge-network heuristic must never fire on a real host whose LAN
        # legitimately sits in 172.16.0.0/12.
        info = netinfo.container_info()
        if not info["in_container"]:
            self.assertFalse(info["network_isolated"])
            self.assertIsNone(info["isolation_reason"])

    def test_version_has_one_source_of_truth(self) -> None:
        """Two places to edit means a release can ship disagreeing version numbers."""
        import network_atlas

        self.assertRegex(network_atlas.__version__, r"^\d+\.\d+\.\d+")
        pyproject = (ROOT / "pyproject.toml").read_text()
        # pyproject must derive the version, not restate it.
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "network_atlas.__version__"}', pyproject)
        self.assertNotRegex(
            pyproject, r'^version\s*=\s*"',
            "pyproject.toml restates the version instead of deriving it",
        )

    def test_publish_target_tags_the_real_version(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        # The tag must come from the code, never from a hand-typed default.
        self.assertIn("network_atlas.__version__", makefile)
        self.assertIn("$(REPOSITORY):$(VERSION)", makefile)
        self.assertIn("$(REPOSITORY):latest", makefile)
        # arm64 is what makes a Raspberry Pi deployment possible.
        self.assertIn("linux/arm64", makefile)
        # Multi-platform needs a docker-container builder; the default driver
        # cannot do it, and failing late wastes a long build.
        self.assertIn("--driver docker-container", makefile)

    def test_makefile_has_no_duplicate_targets(self) -> None:
        """A duplicated target silently overrides the earlier recipe."""
        import collections

        names = [
            line.split(":")[0]
            for line in (ROOT / "Makefile").read_text().splitlines()
            if re.match(r"^[a-zA-Z0-9_-]+:", line)
        ]
        duplicates = [name for name, count in collections.Counter(names).items() if count > 1]
        self.assertFalse(duplicates, f"duplicate Make targets: {duplicates}")

    def test_makefile_detects_either_compose_shape(self) -> None:
        """Debian packages compose v2 as `docker-compose` and not as a CLI plugin.

        Hard-coding `docker compose` would break every container target on a stock
        Debian host, where that subcommand does not exist.
        """
        makefile = ROOT / "Makefile"
        if not makefile.is_file():
            self.skipTest("no Makefile")
        content = makefile.read_text()
        self.assertRegex(
            content, r"COMPOSE \?=.*docker compose version.*docker-compose",
            "COMPOSE must fall back to the standalone binary when the plugin is absent",
        )
        # Container targets must go through the detected variable, never the
        # literal subcommand.
        def invokes_compose(line: str) -> bool:
            if not line.startswith("\t") or "docker compose" not in line:
                return False
            # The capability probe must name the plugin literally, and printed
            # text merely mentions it; neither is an invocation.
            if "docker compose version" in line:
                return False
            return not any(word in line for word in ("printf", "echo"))

        container_recipes = [
            line for line in content.splitlines() if invokes_compose(line)
        ]
        self.assertFalse(
            container_recipes,
            f"these recipes hard-code `docker compose` instead of $(COMPOSE): {container_recipes}",
        )

    def test_viewer_port_is_configurable_in_compose(self) -> None:
        """Host networking uses the host's ports, so the port must be overridable.

        A natively running viewer already holds 8765; without an override the
        container simply restart-loops on "Address already in use".
        """
        for name in ("docker-compose.yml", "docker-compose.macvlan.yml"):
            path = ROOT / name
            if not path.is_file():
                continue
            self.assertIn("ATLAS_PORT", path.read_text(), name)
        makefile = (ROOT / "Makefile").read_text()
        # docker-up must refuse to start into a conflict rather than loop.
        self.assertIn("already in use", makefile)

    def test_macvlan_compose_is_a_complete_alternative(self) -> None:
        compose = ROOT / "docker-compose.macvlan.yml"
        if not compose.is_file():
            self.skipTest("no macvlan compose file")
        stack = "\n".join(
            line for line in compose.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        # Its whole purpose is an own-address network instead of the host's.
        self.assertIn("atlas-lan", stack)
        self.assertNotIn("network_mode: host", stack)
        # Same capability contract as the host-networked path.
        self.assertIn("NET_RAW", stack)
        self.assertIn("NET_ADMIN", stack)
        self.assertIn("cap_drop", stack)
        self.assertNotIn("no-new-privileges", stack)
        self.assertNotIn("privileged: true", stack)

    def test_airplay_is_not_mistaken_for_a_camera(self) -> None:
        """AirPlay runs over RTSP, so Nmap reports macOS 5000/7000 as "rtsp".

        Matching the service name alone classified every Mac with AirPlay enabled
        as a security camera, and scored it higher than a real camera did.
        """
        airplay = [
            {"port": port, "protocol": "tcp", "name": "rtsp", "product": "",
             "version": "", "extra": "", "cpe": ""}
            for port in (5000, 7000)
        ]
        for hostname in (None, "raphs-air", "mac-mini-bureau"):
            data = {
                "services": airplay, "observations": [],
                "os_name": "Apple macOS 11 (Big Sur) - 13 (Ventura) or iOS 16",
            }
            if hostname:
                data["hostname"] = hostname
            kind, _confidence, _why, _family = classify(data)
            self.assertEqual(kind, "computer", f"hostname={hostname}")

        # A real camera on the standard port is still a camera.
        kind, _c, _w, _f = classify({
            "hostname": "front-door", "observations": [],
            "services": [{"port": 554, "protocol": "tcp", "name": "rtsp",
                          "product": "", "version": "", "extra": "", "cpe": ""}],
        })
        self.assertEqual(kind, "camera")

    def test_hostname_cam_needs_a_qualifier(self) -> None:
        # "cam" alone is Cameron or Camille at least as often as a camera.
        computer, _c, _w, _f = classify(
            {"hostname": "cameron-laptop", "services": [], "observations": []}
        )
        self.assertEqual(computer, "computer")
        camera, _c, _w, _f = classify(
            {"hostname": "cam-front", "services": [], "observations": []}
        )
        self.assertEqual(camera, "camera")

    def test_operating_system_rules_out_incompatible_types(self) -> None:
        # Appliances do not run macOS or Windows, so a service-shaped guess must
        # not outrank the platform itself.
        for os_name in ("Apple macOS 13", "Microsoft Windows 11"):
            kind, _c, _w, _f = classify({
                "os_name": os_name, "observations": [],
                "services": [{"port": 554, "protocol": "tcp", "name": "rtsp",
                              "product": "", "version": "", "extra": "", "cpe": ""}],
            })
            self.assertEqual(kind, "computer", os_name)
        # But a network OS must NOT penalise "computer": Nmap reads generic Linux
        # as OpenWrt often enough that doing so turns laptops back into routers.
        kind, _c, _w, _f = classify({
            "os_name": "OpenWrt 21.02 (Linux 5.4)", "hostname": "debian-4",
            "vendor": "Dell Inc.", "services": [], "observations": [],
        })
        self.assertEqual(kind, "computer")

    def test_repeated_service_evidence_is_capped(self) -> None:
        """One rule must not multiply with the number of matching ports."""
        one = [{"port": 9100, "protocol": "tcp", "name": "jetdirect",
                "product": "", "version": "", "extra": "", "cpe": ""}]
        many = one + [
            {"port": port, "protocol": "tcp", "name": "ipp", "product": "",
             "version": "", "extra": "", "cpe": ""}
            for port in (515, 631)
        ]
        _k1, single, _w, _f = classify({"services": one, "observations": []})
        _k2, triple, _w, _f = classify({"services": many, "observations": []})
        self.assertLess(
            triple - single, 0.2,
            "three printing ports should not treble the printing evidence",
        )

    def test_mdns_model_strings_identify_hardware(self) -> None:
        # The device stating its own hardware model, which nothing infers better.
        expected = {
            "SHIELD Android TV": "media",
            "MacBookPro18,3": "computer",
            "iPhone15,2": "phone",
            "AppleTV6,2": "media",
            "Brother MFC-L2750DW series": "printer",
            "DiskStation DS920+": "storage",
            "PlayStation 5": "game-console",
            "AXIS P3245": "camera",
        }
        for model, kind in expected.items():
            result = classifier_module.classify_model(model)
            self.assertIsNotNone(result, model)
            self.assertEqual(result[0], kind, model)
        self.assertIsNone(classifier_module.classify_model("Some Unknown Thing"))
        self.assertIsNone(classifier_module.classify_model(None))

        # And it overrides a wrong service-based guess.
        kind, _c, _w, _f = classify({
            "services": [{"port": 5000, "protocol": "tcp", "name": "rtsp",
                          "product": "", "version": "", "extra": "", "cpe": ""}],
            "observations": [{"key": "mdns_model", "value": "MacBookPro18,3"}],
        })
        self.assertEqual(kind, "computer")

    def test_mdns_txt_records_are_split_into_pairs(self) -> None:
        # A TXT record holds several strings; tshark joins them with commas, and a
        # value can itself contain one.
        pairs = passive._split_txt(
            "id=abc,rm=,ve=05,md=SHIELD Android TV,fn=Shield Android TV AF29,ca=463365"
        )
        parsed = dict(pair.split("=", 1) for pair in pairs if "=" in pair)
        self.assertEqual(parsed["md"], "SHIELD Android TV")
        self.assertEqual(parsed["fn"], "Shield Android TV AF29")
        self.assertEqual(passive._split_txt(""), [])

    def test_mdns_txt_read_takes_every_occurrence(self) -> None:
        """The interesting TXT string is rarely the first one in the record.

        With tshark's default occurrence=f only "id=..." came through and every
        model and friendly name was silently dropped.
        """
        import inspect

        body = inspect.getsource(passive.analyze)
        self.assertIn('occurrence="a"', body)

    def test_one_online_device_per_address(self) -> None:
        """Enforced after collection, not only at write time.

        mark_network_offline() marks a whole range offline before every import, so
        a second device can take an address during that window and both end up
        online afterwards.
        """
        first = self.db.ensure_device(
            mac="00:11:22:33:77:01", address="10.23.45.60", status="online"
        )
        second = self.db.ensure_device(mac="00:11:22:33:77:02", status="online")
        # Simulate the window: the holder is briefly offline, so the write is allowed.
        self.db.update_device(first, status="offline")
        self.db.commit()
        self.db.ensure_device(
            mac="00:11:22:33:77:02", address="10.23.45.60", status="online"
        )
        self.db.update_device(first, status="online")
        self.db.commit()
        owners = [
            row["device_id"]
            for row in self.db.conn.execute(
                "SELECT device_id FROM addresses WHERE address='10.23.45.60'"
            )
        ]
        self.assertEqual(len(owners), 2, "precondition: both hold it")

        self.assertEqual(self.db.resolve_address_conflicts(), 1)
        owners = [
            row["device_id"]
            for row in self.db.conn.execute(
                """SELECT a.device_id FROM addresses a JOIN devices d ON d.id=a.device_id
                   WHERE a.address='10.23.45.60' AND d.status='online'"""
            )
        ]
        self.assertEqual(len(owners), 1)
        self.assertEqual(owners[0], second, "most recently seen should keep it")

    # -- scheduler --------------------------------------------------------
    def test_monitoring_is_off_until_switched_on(self) -> None:
        # Scanning sends packets to other people's devices; it must never start
        # by itself just because the viewer is running.
        scheduler.ensure_defaults(self.db)
        self.assertFalse(scheduler.monitoring_active(self.db))
        self.assertTrue(all(not entry["enabled"] for entry in scheduler.entries(self.db)))
        changed = scheduler.set_monitoring(self.db, True)
        self.assertTrue(scheduler.monitoring_active(self.db))
        self.assertEqual(set(changed), {"neighbours", "passive", "scan"})
        scheduler.set_monitoring(self.db, False)
        self.assertFalse(scheduler.monitoring_active(self.db))

    def test_schedule_rejects_unknown_tasks_and_silly_intervals(self) -> None:
        scheduler.ensure_defaults(self.db)
        with self.assertRaises(ValueError):
            scheduler.set_enabled(self.db, "bogus", True)
        with self.assertRaises(ValueError):
            scheduler.set_interval(self.db, "scan", 5)
        with self.assertRaises(ValueError):
            scheduler.set_interval(self.db, "scan", 999999999)
        scheduler.set_interval(self.db, "scan", 900)
        entry = next(e for e in scheduler.entries(self.db) if e["kind"] == "scan")
        self.assertEqual(entry["interval_seconds"], 900)

    def test_due_calculation(self) -> None:
        import time
        now = time.time()
        self.assertFalse(scheduler._due({"enabled": False, "interval_seconds": 60}, now))
        self.assertTrue(
            scheduler._due({"enabled": True, "interval_seconds": 60, "last_run_at": None}, now)
        )
        self.assertFalse(
            scheduler._due(
                {"enabled": True, "interval_seconds": 3600,
                 "last_run_at": utc_now()}, now
            )
        )

    # -- flows and wireless ----------------------------------------------
    def test_flows_separate_internal_peers_from_the_outside(self) -> None:
        first, second = self._seed_pair()
        original = ingest.netinfo.local_networks
        try:
            ingest.netinfo.local_networks = lambda: [
                {"network": "10.23.45.0/24", "interface": "eth0",
                 "family": "ipv4", "source": None, "addresses": 256}
            ]
            count = ingest.import_flows(self.db, [
                {"source": "10.23.45.11", "target": "10.23.45.12", "port": 445, "count": 3},
                {"source": "10.23.45.11", "target": "8.8.8.8", "port": 443, "count": 9},
            ])
        finally:
            ingest.netinfo.local_networks = original
        self.assertEqual(count, 2)
        rows = self.db.flows()
        internal = next(row for row in rows if row["port"] == 445)
        external = next(row for row in rows if row["port"] == 443)
        self.assertEqual(internal["target_device_id"], second)
        self.assertEqual(internal["external"], 0)
        self.assertIsNone(external["target_device_id"])
        self.assertEqual(external["external"], 1)
        self.assertEqual(external["target_address"], "8.8.8.8")

    def test_wireless_survey_csv_is_parsed_into_associations(self) -> None:
        csv_text = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
            "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "AA:BB:CC:DD:EE:01, 2026-01-01 00:00:00, 2026-01-01 00:01:00, 6, 130, WPA2, "
            "CCMP, PSK, -42, 120, 0, 0.0.0.0, 8, HomeWiFi, \n"
            "\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "1a:2b:3c:4d:5e:6f, 2026-01-01 00:00:00, 2026-01-01 00:01:00, -55, 40, "
            "AA:BB:CC:DD:EE:01, HomeWiFi\n"
        )
        path = Path(self.temp.name) / "survey-01.csv"
        path.write_text(csv_text)
        parsed = wireless.parse_csv(path)
        self.assertEqual(len(parsed["access_points"]), 1)
        self.assertEqual(parsed["access_points"][0]["ssid"], "HomeWiFi")
        self.assertEqual(parsed["access_points"][0]["channel"], 6)
        self.assertEqual(len(parsed["stations"]), 1)
        self.assertEqual(parsed["stations"][0]["bssid"], "aa:bb:cc:dd:ee:01")

        imported = ingest.import_wireless(self.db, parsed)
        self.assertEqual(imported["access_points"], 1)
        self.assertEqual(imported["associations"], 1)
        classify_all(self.db)
        access_point = next(
            item for item in self.db.devices() if item["mac"] == "aa:bb:cc:dd:ee:01"
        )
        # A beaconing BSSID is an access point by definition.
        self.assertEqual(access_point["effective_type"], "access-point")

    def test_wireless_flags_ssids_on_multiple_bssids(self) -> None:
        rogues = wireless.rogue_access_points([
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:01"},
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:02"},
            {"ssid": "Guest", "bssid": "aa:bb:cc:dd:ee:03"},
            {"ssid": None, "bssid": "aa:bb:cc:dd:ee:04"},
        ])
        self.assertEqual(len(rogues), 1)
        self.assertEqual(rogues[0]["ssid"], "Home")
        self.assertEqual(rogues[0]["count"], 2)

    def test_snmp_arp_suffix_yields_the_address(self) -> None:
        self.assertEqual(_address_from_arp_suffix("1.192.168.1.254"), "192.168.1.254")
        self.assertIsNone(_address_from_arp_suffix("1.224.0.0.1"))
        self.assertIsNone(_address_from_arp_suffix("1.192.168.1"))

    def test_mdns_print_service_classifies_printer(self) -> None:
        text = (ROOT / "examples" / "demo-mdns.txt").read_text()
        self.assertEqual(import_avahi(self.db, text), 2)
        classify_all(self.db)
        devices = self.db.devices()
        printer = next(item for item in devices if "192.168.50.45" in item["addresses"])
        media = next(item for item in devices if "192.168.50.70" in item["addresses"])
        self.assertEqual(printer["effective_type"], "printer")
        self.assertEqual(media["effective_type"], "media")

    def test_snmp_numeric_walk_parser(self) -> None:
        content = (
            '.1.0.8802.1.1.2.1.4.1.1.9.0.5.1 = STRING: "core-switch"\n'
            '.1.0.8802.1.1.2.1.4.1.1.9.0.7.1 = STRING: "access-point"\n'
        )
        parsed = parse_walk(content, "1.0.8802.1.1.2.1.4.1.1.9")
        self.assertEqual(parsed["0.5.1"], "core-switch")
        self.assertEqual(parsed["0.7.1"], "access-point")

    def test_target_guardrails(self) -> None:
        self.assertEqual(str(validate_target("10.23.45.42/24")), "10.23.45.0/24")
        with self.assertRaises(ValueError):
            validate_target("8.8.8.0/24")
        with self.assertRaises(ValueError):
            validate_target("10.0.0.0/8")

    def test_mac_normalization(self) -> None:
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(normalize_mac("not-a-mac"))

    def test_partial_manual_label_preserves_existing_values(self) -> None:
        import_arp_scan(self.db, "10.23.45.5 00:11:22:33:44:55 Vendor One")
        self.db.set_manual_label("10.23.45.5", "Desk machine", "computer")
        self.db.set_manual_label("10.23.45.5", None, "server")
        device = self.db.devices()[0]
        self.assertEqual(device["manual_name"], "Desk machine")
        self.assertEqual(device["manual_type"], "server")

    def test_hostname_precedence_keeps_the_best_name(self) -> None:
        """A name a person chose must survive a later, worse-sourced name."""
        import_arp_scan(self.db, "10.23.45.9 aa:bb:cc:dd:ee:01 Nvidia")
        device_id = self.db.find_device_by_address("10.23.45.9")
        assert device_id is not None

        # Arrival order deliberately puts the worst source last.
        self.assertTrue(self.db.set_hostname(device_id, "Shield Android TV AF29", "friendly"))
        self.assertFalse(self.db.set_hostname(device_id, "SHIELDANDROIDTV", "netbios"))
        self.assertFalse(
            self.db.set_hostname(
                device_id, "SHIELD Android TV-192-168-1-65-esfileshare", "service"
            )
        )
        self.assertEqual(self.db.devices()[0]["hostname"], "Shield Android TV AF29")

    def test_hostname_precedence_upgrades_a_weak_name(self) -> None:
        import_arp_scan(self.db, "10.23.45.10 aa:bb:cc:dd:ee:02 Vendor")
        device_id = self.db.find_device_by_address("10.23.45.10")
        assert device_id is not None
        self.db.set_hostname(device_id, "_googlecast._tcp-instance", "service")
        self.db.set_hostname(device_id, "living-room-tv", "friendly")
        self.assertEqual(self.db.devices()[0]["hostname"], "living-room-tv")
        # Equal rank still refreshes, so a renamed device is picked up.
        self.db.set_hostname(device_id, "kitchen-tv", "friendly")
        self.assertEqual(self.db.devices()[0]["hostname"], "kitchen-tv")

    def test_ensure_device_cannot_downgrade_a_hostname(self) -> None:
        device_id = self.db.ensure_device(
            address="10.23.45.11", hostname="office-printer", name_source="dhcp"
        )
        self.db.ensure_device(
            address="10.23.45.11",
            hostname="office-printer-192-168-1-4-ipp",
            name_source="service",
        )
        row = self.db.conn.execute(
            "SELECT hostname FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        self.assertEqual(row["hostname"], "office-printer")

    def test_dhcp_param_list_signatures(self) -> None:
        from network_atlas.fingerprint import DHCP_PARAM_LISTS, classify_param_list
        from network_atlas.passive import _request_list

        sequences = [sequence for sequence, _, _, _ in DHCP_PARAM_LISTS]
        self.assertEqual(len(sequences), len(set(sequences)), "duplicate signature")

        macos = classify_param_list("1,121,3,6,15,119,252,95,44,46")
        assert macos is not None
        self.assertEqual(macos["os_family"], "apple")
        android = classify_param_list("1,3,6,15,26,28,51,58,59,43")
        assert android is not None
        self.assertEqual(android["device_type"], "phone")
        # The shared opening is not distinctive, so it must yield no claim.
        self.assertIsNone(classify_param_list("1,3,6,15"))
        self.assertIsNone(classify_param_list(None))
        # tshark emits the raw items; order carries the fingerprint.
        self.assertEqual(_request_list("1, 3,6 ,15"), "1,3,6,15")
        self.assertEqual(_request_list("1,3,junk,6"), "1,3,6")
        self.assertEqual(_request_list(""), "")

    def test_param_list_alone_identifies_a_phone(self) -> None:
        """Option 55 must carry the OS when nothing else names it."""
        ios = {
            "vendor": "Apple",
            "services": [],
            "observations": [
                {"key": "dhcp_param_list", "value": "1,121,3,6,15,119,252", "source": "dhcp"}
            ],
        }
        kind, _confidence, reasons, family = classify(ios)
        self.assertEqual(kind, "phone")
        self.assertEqual(family, "apple")
        self.assertTrue(any("DHCP option list" in reason for reason in reasons))

    def test_repeated_observations_collapse_to_one_row(self) -> None:
        """Re-scanning must refresh a fact, not append a copy of it."""
        device_id = self.db.ensure_device(address="10.23.45.12")
        self.db.add_observation(device_id, "web", "web_server", "debut/1.30", 0.6, "2026-01-01T00:00:00Z")
        self.db.add_observation(device_id, "web", "web_server", "debut/1.30", 0.4, "2026-02-01T00:00:00Z")
        self.db.add_observation(device_id, "web", "web_server", "openresty", 0.6, "2026-02-01T00:00:00Z")
        rows = self.db.conn.execute(
            "SELECT value, confidence, observed_at FROM observations"
            " WHERE device_id=? AND key='web_server' ORDER BY value",
            (device_id,),
        ).fetchall()
        self.assertEqual([row["value"] for row in rows], ["debut/1.30", "openresty"])
        # The newer sighting wins on time; the stronger one wins on confidence.
        self.assertEqual(rows[0]["observed_at"], "2026-02-01T00:00:00Z")
        self.assertEqual(rows[0]["confidence"], 0.6)

    def test_samba_os_string_is_recorded_as_a_dialect(self) -> None:
        """Samba reports an SMB dialect, not its host OS."""
        xml = r"""<?xml version="1.0"?><nmaprun>
          <host><status state="up"/>
            <address addr="10.23.45.13" addrtype="ipv4"/>
            <hostscript><script id="smb-os-discovery" output="ignored">
              <elem key="os">Windows 6.1</elem>
              <elem key="lanmanager">Samba 4.9.1</elem>
              <elem key="server">SHIELDANDROIDTV\x00</elem>
              <elem key="workgroup">WORKGROUP\x00</elem>
            </script></hostscript>
          </host></nmaprun>"""
        path = Path(self.temp.name) / "smb.xml"
        path.write_text(xml)
        import_nmap_xml(self.db, path)
        device_id = self.db.find_device_by_address("10.23.45.13")
        assert device_id is not None
        recorded = {
            row["key"]: row["value"]
            for row in self.db.conn.execute(
                "SELECT key, value FROM observations WHERE device_id=?", (device_id,)
            )
        }
        self.assertEqual(recorded.get("smb_dialect"), "Windows 6.1")
        self.assertNotIn("smb_os", recorded)
        # The nulls SMB pads its fields with must not survive into a name.
        self.assertEqual(recorded.get("smb_computer_name"), "SHIELDANDROIDTV")
        self.assertEqual(recorded.get("smb_workgroup"), "WORKGROUP")

    def test_real_smb_os_is_still_trusted(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun>
          <host><status state="up"/>
            <address addr="10.23.45.14" addrtype="ipv4"/>
            <hostscript><script id="smb-os-discovery" output="ignored">
              <elem key="os">Windows 10 Pro 19041</elem>
              <elem key="lanmanager">Windows 10 Pro 6.3</elem>
            </script></hostscript>
          </host></nmaprun>"""
        path = Path(self.temp.name) / "smb-windows.xml"
        path.write_text(xml)
        import_nmap_xml(self.db, path)
        device_id = self.db.find_device_by_address("10.23.45.14")
        assert device_id is not None
        recorded = {
            row["key"]: row["value"]
            for row in self.db.conn.execute(
                "SELECT key, value FROM observations WHERE device_id=?", (device_id,)
            )
        }
        self.assertEqual(recorded.get("smb_os"), "Windows 10 Pro 19041")

    def _snmp_config(self, host: str = "192.168.1.52") -> dict[str, str]:
        """A minimal valid v2c config; the community never leaves the test."""
        import os

        os.environ["ATLAS_TEST_COMMUNITY"] = "public"
        self.addCleanup(os.environ.pop, "ATLAS_TEST_COMMUNITY", None)
        return {"host": host, "version": "2c", "community_env": "ATLAS_TEST_COMMUNITY"}

    def _fake_snmp(self, tables: dict[str, dict[str, str]]) -> None:
        """Replace the SNMP walk with canned tables for the duration of a test."""
        from network_atlas import snmp as snmp_module

        original = snmp_module._walk
        self.addCleanup(setattr, snmp_module, "_walk", original)

        def fake_walk(host: str, oid: str, config_dir: str, timeout: int) -> dict[str, str]:
            return dict(tables.get(oid, {}))

        snmp_module._walk = fake_walk

    def test_several_devices_on_one_port_imply_an_unmanaged_switch(self) -> None:
        """An unmanaged switch answers nothing, so sharing a port is the only clue."""
        from network_atlas import snmp as snmp_module

        self._fake_snmp({
            snmp_module.SYS_NAME: {"0": "SG3428X"},
            snmp_module.SYS_DESCR: {"0": "Pharos OS"},
            snmp_module.IF_NAME: {"3": "Gi1/0/3", "7": "Gi1/0/7"},
            snmp_module.BRIDGE_PORT_IFINDEX: {"3": "3", "7": "7"},
            snmp_module.BRIDGE_FDB_PORT: {
                # Three devices behind port 3, one behind port 7.
                "0.170.187.204.0.0.1": "3",
                "0.170.187.204.0.0.2": "3",
                "0.170.187.204.0.0.3": "3",
                "0.170.187.204.0.0.9": "7",
            },
        })
        result = snmp_module.collect_switch(self.db, self._snmp_config())
        self.assertEqual(result["inferred_switches"], 1)
        # Three endpoints behind the hidden switch, one directly on the switch.
        self.assertEqual(result["attachment_links"], 4)

        hidden = self.db.conn.execute(
            "SELECT id, hostname, device_type FROM devices WHERE synthetic_key IS NOT NULL"
        ).fetchall()
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0]["hostname"], "Unmanaged switch on Gi1/0/3")
        self.assertEqual(hidden[0]["device_type"], "switch")

        behind = self.db.conn.execute(
            "SELECT COUNT(*) AS n FROM edges WHERE source_device_id=? AND edge_type=?",
            (hidden[0]["id"], "inferred-attachment"),
        ).fetchone()
        self.assertEqual(behind["n"], 3)

        # Running twice must not produce a second hidden switch.
        snmp_module.collect_switch(self.db, self._snmp_config())
        self.assertEqual(
            self.db.conn.execute(
                "SELECT COUNT(*) AS n FROM devices WHERE synthetic_key IS NOT NULL"
            ).fetchone()["n"],
            1,
        )

    def test_the_uplink_port_is_not_mistaken_for_a_hidden_switch(self) -> None:
        """Otherwise the whole network hangs off one port of one switch."""
        from network_atlas import snmp as snmp_module

        # The gateway is known and its MAC is learned on port 1.
        import_arp_scan(self.db, "192.168.1.1 aa:aa:aa:00:00:01 Router Vendor")
        original_gateways = snmp_module.netinfo.gateways
        self.addCleanup(setattr, snmp_module.netinfo, "gateways", original_gateways)
        snmp_module.netinfo.gateways = lambda: [{"address": "192.168.1.1"}]

        self._fake_snmp({
            snmp_module.SYS_NAME: {"0": "SG3428X"},
            snmp_module.IF_NAME: {"1": "Gi1/0/1", "4": "Gi1/0/4"},
            snmp_module.BRIDGE_PORT_IFINDEX: {"1": "1", "4": "4"},
            snmp_module.BRIDGE_FDB_PORT: {
                "0.170.170.170.0.0.1": "1",   # the gateway
                "0.187.187.187.0.0.2": "1",   # reached through the gateway
                "0.187.187.187.0.0.3": "1",
                "0.204.204.204.0.0.9": "4",
            },
        })
        result = snmp_module.collect_switch(self.db, self._snmp_config())
        self.assertEqual(result["inferred_switches"], 0)
        self.assertEqual(result["attachment_links"], 1)
        uplink = self.db.conn.execute(
            "SELECT value FROM observations WHERE key='switch_uplink_port'"
        ).fetchone()
        self.assertIsNotNone(uplink)
        self.assertIn("Gi1/0/1", uplink["value"])

    def test_crawl_follows_lldp_management_addresses(self) -> None:
        """LLDP is single-hop, so each switch must be asked for its own view."""
        from network_atlas import snmp as snmp_module

        seen: list[tuple[str, str | None]] = []
        topology = {
            "192.168.1.52": ["192.168.1.53"],
            "192.168.1.53": ["192.168.1.54", "192.168.1.52"],
            "192.168.1.54": [],
        }

        def fake_collect(db, config, *, timeout=30):
            host = config["host"]
            seen.append((host, config.get("community_env")))
            return {
                "host": host, "sys_name": host, "lldp_links": 1,
                "attachment_links": 0, "inferred_switches": 0, "arp_entries": 0,
                "neighbours": [
                    {"address": address, "sys_name": None, "capabilities": "bridge"}
                    for address in topology[host]
                ],
            }

        original = snmp_module.collect_switch
        self.addCleanup(setattr, snmp_module, "collect_switch", original)
        snmp_module.collect_switch = fake_collect
        self.addCleanup(
            setattr, snmp_module.netinfo, "local_networks", snmp_module.netinfo.local_networks
        )
        snmp_module.netinfo.local_networks = lambda: [{"network": "192.168.1.0/24"}]

        result = snmp_module.crawl_switches(
            self.db, [{"host": "192.168.1.52", "community_env": "ATLAS_RO"}]
        )
        self.assertEqual(result["switches_reached"], 3)
        self.assertEqual(
            sorted(host for host, _ in seen),
            ["192.168.1.52", "192.168.1.53", "192.168.1.54"],
        )
        # Credentials are inherited from the switch that named the neighbour.
        self.assertTrue(all(env == "ATLAS_RO" for _, env in seen))

    def test_crawl_refuses_to_leave_the_local_networks(self) -> None:
        from network_atlas import snmp as snmp_module

        def fake_collect(db, config, *, timeout=30):
            return {
                "host": config["host"], "sys_name": None, "lldp_links": 0,
                "attachment_links": 0, "inferred_switches": 0, "arp_entries": 0,
                "neighbours": [
                    {"address": "203.0.113.9", "sys_name": None, "capabilities": "router"}
                ],
            }

        original = snmp_module.collect_switch
        self.addCleanup(setattr, snmp_module, "collect_switch", original)
        snmp_module.collect_switch = fake_collect
        self.addCleanup(
            setattr, snmp_module.netinfo, "local_networks", snmp_module.netinfo.local_networks
        )
        snmp_module.netinfo.local_networks = lambda: [{"network": "192.168.1.0/24"}]

        result = snmp_module.crawl_switches(self.db, [{"host": "192.168.1.52"}])
        self.assertEqual(result["switches_reached"], 1)
        self.assertEqual(
            [entry["host"] for entry in result["skipped"]], ["203.0.113.9"]
        )

    def test_crawl_is_off_unless_asked_for(self) -> None:
        """Querying a device nobody listed needs an explicit opt-in."""
        from network_atlas import snmp as snmp_module

        def fake_collect(db, config, *, timeout=30):
            return {
                "host": config["host"], "sys_name": None, "lldp_links": 0,
                "attachment_links": 0, "inferred_switches": 0, "arp_entries": 0,
                "neighbours": [
                    {"address": "192.168.1.53", "sys_name": None, "capabilities": "bridge"}
                ],
            }

        original = snmp_module.collect_switch
        self.addCleanup(setattr, snmp_module, "collect_switch", original)
        snmp_module.collect_switch = fake_collect
        result = snmp_module.crawl_switches(
            self.db, [{"host": "192.168.1.52"}], max_depth=0
        )
        self.assertEqual(result["switches_reached"], 1)

    def test_lldp_management_address_decoding(self) -> None:
        from network_atlas.snmp import _management_address_from_suffix as decode

        self.assertEqual(decode("0.1.1.1.4.192.168.1.52"), "192.168.1.52")
        self.assertEqual(
            decode("0.1.1.2.16." + ".".join(["32", "1", "13", "184"] + ["0"] * 11 + ["1"])),
            "2001:db8::1",
        )
        self.assertIsNone(decode("0.1.1.1.4.224.0.0.1"))
        self.assertIsNone(decode("0.1.1.6.4.1.2.3.4"))
        self.assertIsNone(decode("0.1.1"))

    def test_a_silent_switch_explains_the_topology_gap(self) -> None:
        from network_atlas import findings as findings_module

        import_arp_scan(self.db, "10.23.45.52 aa:bb:cc:00:52:00 TP-Link")
        device_id = self.db.find_device_by_address("10.23.45.52")
        assert device_id is not None
        self.db.set_manual_label("10.23.45.52", None, "switch")
        findings_module.evaluate(self.db)
        kinds = {row["kind"] for row in self.db.findings()}
        self.assertIn("switch-topology-gap", kinds)

        # Once the switch has answered SNMP, the gap is closed and the finding goes.
        self.db.add_observation(device_id, "snmp", "snmp_sysname", "SG3428X", 0.9)
        findings_module.evaluate(self.db)
        open_kinds = {row["kind"] for row in self.db.findings() if not row["resolved_at"]}
        self.assertNotIn("switch-topology-gap", open_kinds)

    def test_an_inferred_switch_does_not_raise_the_topology_gap(self) -> None:
        """An unmanaged switch can never answer SNMP, so it is not a gap."""
        from network_atlas import findings as findings_module

        self.db.ensure_inferred_device(
            "unmanaged-switch:1:3",
            hostname="Unmanaged switch on Gi1/0/3",
            device_type="switch",
        )
        findings_module.evaluate(self.db)
        kinds = {row["kind"] for row in self.db.findings()}
        self.assertNotIn("switch-topology-gap", kinds)

    def test_snmp_error_reports_the_cause_not_the_mib_warnings(self) -> None:
        from network_atlas.snmp import _snmp_error

        stderr = (
            "MIB search path: /usr/share/snmp/mibs\n"
            "Cannot find module (SNMPv2-MIB): At line 1 in (none)\n"
            "Cannot find module (IF-MIB): At line 1 in (none)\n"
            "Timeout: No Response from 192.168.1.52\n"
        )
        self.assertEqual(_snmp_error(stderr, ""), "Timeout: No Response from 192.168.1.52")
        self.assertEqual(
            _snmp_error("Cannot find module (IP-MIB): At line 1 in (none)", ""),
            "no response",
        )
        self.assertEqual(_snmp_error("", "Authentication failure"), "Authentication failure")

    def test_image_does_not_inherit_the_base_images_provenance(self) -> None:
        """LABEL inherits anything not overridden.

        Left alone, the published image reports the Kali base image's build date
        and git revision as its own, which misstates where it came from. This is
        invisible until someone inspects a built image, so it is guarded here.
        """
        dockerfile = ROOT / "Dockerfile"
        if not dockerfile.is_file():
            self.skipTest("no Dockerfile")
        content = dockerfile.read_text()
        for label in ("revision", "created"):
            self.assertIn(
                f"org.opencontainers.image.{label}=", content,
                f"the image would inherit the base image's {label} label",
            )
        for argument in ("VCS_REF", "BUILD_DATE"):
            self.assertIn(f"ARG {argument}", content)

        makefile = (ROOT / "Makefile").read_text()
        # Every path that produces a publishable image must stamp the same values.
        publish_targets = makefile.count("--build-arg VCS_REF=")
        self.assertGreaterEqual(publish_targets, 2, "a build path stamps no revision")

        override = ROOT / "docker-compose.override.yml"
        if override.is_file():
            self.assertIn("VCS_REF", override.read_text(),
                          "a compose build would stamp no revision")

    def test_real_world_network_and_media_signatures(self) -> None:
        openwrt = {"os_name": "OpenWrt 21.02 (Linux 5.4)", "services": [], "observations": []}
        yealink = {
            "vendor": "Yealink(Xiamen) Network Technology",
            "services": [
                {"port": 5060, "name": "sip", "product": "Yealink SIP-T41S VoIP phone sipd"}
            ],
            "observations": [],
        }
        shield = {
            "os_name": "Android 5 (Linux 3.10)",
            "nmap_device_type": "phone",
            "os_accuracy": 100,
            "vendor": "Nvidia",
            "services": [{"port": 8008}, {"port": 8009}],
            "observations": [],
        }
        self.assertEqual(classify(openwrt)[0], "router")
        self.assertEqual(classify(yealink)[0], "phone")
        self.assertEqual(classify(shield)[0], "media")


class ViewerAuthTestCase(unittest.TestCase):
    """The viewer's authentication gate, exercised over real HTTP.

    Worth the weight of a live server: this gate is the only thing between the
    LAN and the findings list, and a mocked handler would not catch a routing
    mistake that leaves a path reachable.
    """

    PASSWORD = "a-sufficiently-long-password"

    def setUp(self) -> None:
        from network_atlas import auth, server
        from network_atlas.jobs import JobManager

        self.auth = auth
        self.server_module = server
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "atlas.db"
        with AtlasDB(self.db_path) as db:
            salt, hashed = auth.hash_password(self.PASSWORD)
            db.create_account(auth.DEFAULT_USERNAME, hashed, salt)
            # One device, so an authenticated read has something to return and a
            # leak would be visible rather than an empty list either way.
            import_arp_scan(db, "10.23.45.7 aa:bb:cc:dd:ee:77 Test Vendor")

        self.sessions = auth.SessionStore()
        handler = type(
            "TestAtlasHandler",
            (server.AtlasHandler,),
            {
                "db_path": self.db_path,
                "jobs": JobManager(self.db_path),
                "scheduler": None,
                "sessions": self.sessions,
                # The handler logs every request to stderr; silence for the suite.
                "log_message": lambda self, *args, **kwargs: None,
                "log_error": lambda self, *args, **kwargs: None,
            },
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        # A short poll interval only so shutdown() returns promptly: the default
        # of 0.5s made teardown, not the requests, the cost of this whole class.
        thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    # -- helpers --------------------------------------------------------------
    def call(self, path, method="GET", body=None, cookie=None, token=None):
        request = urllib.request.Request(f"{self.base}{path}", method=method)
        if body is not None:
            request.data = json.dumps(body).encode()
            request.add_header("Content-Type", "application/json")
        if cookie:
            request.add_header("Cookie", cookie)
        if token:
            request.add_header("X-Atlas-Token", token)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def sign_in(self, password=None):
        """Return (cookie, csrf token) for a signed-in browser."""
        status, _, headers = self.call(
            "/api/login", "POST",
            {"username": "admin", "password": password or self.PASSWORD},
        )
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";")[0]
        _, payload, _ = self.call("/api/session", cookie=cookie)
        return cookie, json.loads(payload)["token"]

    # -- the boundary ---------------------------------------------------------
    def test_public_routes_are_exactly_these(self) -> None:
        """The whole security boundary, asserted in one place.

        This set is what an anonymous caller can reach. Widening it is how an API
        ends up exposed, so the test states the full contents rather than checking
        that particular members are present.
        """
        self.assertEqual(
            set(self.server_module.PUBLIC_ROUTES),
            {"/login", "/login.html", "/api/login", "/healthz"},
        )

    def test_every_api_route_refuses_an_anonymous_caller(self) -> None:
        for route in (
            "/api/devices", "/api/findings", "/api/session", "/api/summary",
            "/api/graph", "/api/jobs", "/api/tree", "/api/events", "/api/services",
            "/api/schedule", "/api/flows", "/api/scans",
        ):
            with self.subTest(route=route):
                status, payload, _ = self.call(route)
                self.assertEqual(status, 401, f"{route} answered {status}")
                self.assertNotIn(b"aa:bb:cc:dd:ee:77", payload)

    def test_anonymous_writes_are_refused(self) -> None:
        for route, body in (
            ("/api/scan", {"kind": "neighbours"}),
            ("/api/account/password", {"current_password": "x", "new_password": "y"}),
            ("/api/logout", {}),
        ):
            with self.subTest(route=route):
                status, _, _ = self.call(route, "POST", body)
                self.assertEqual(status, 401)

    def test_pages_serve_the_login_form_when_signed_out(self) -> None:
        for route in ("/", "/index.html", "/app.js", "/login"):
            with self.subTest(route=route):
                status, payload, _ = self.call(route)
                self.assertEqual(status, 200)
                self.assertIn(b"<title>Sign in", payload)

    def test_healthz_is_public_and_reveals_nothing(self) -> None:
        status, payload, _ = self.call("/healthz")
        self.assertEqual(status, 200)
        # Liveness only: no version, no counts, no device data.
        self.assertEqual(json.loads(payload), {"status": "ok"})

    # -- signing in -----------------------------------------------------------
    def test_wrong_username_and_wrong_password_are_indistinguishable(self) -> None:
        """Differing messages would confirm which account names exist."""
        _, wrong_password, _ = self.call(
            "/api/login", "POST", {"username": "admin", "password": "not-the-password"}
        )
        _, wrong_username, _ = self.call(
            "/api/login", "POST", {"username": "nobody", "password": self.PASSWORD}
        )
        self.assertEqual(json.loads(wrong_password), json.loads(wrong_username))

    def test_login_issues_a_hardened_cookie(self) -> None:
        _, _, headers = self.call(
            "/api/login", "POST", {"username": "admin", "password": self.PASSWORD}
        )
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_login_is_not_case_sensitive_in_the_username(self) -> None:
        status, _, _ = self.call(
            "/api/login", "POST", {"username": "ADMIN", "password": self.PASSWORD}
        )
        self.assertEqual(status, 200)

    def test_a_session_unlocks_the_inventory(self) -> None:
        cookie, _ = self.sign_in()
        status, payload, _ = self.call("/api/devices", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"aa:bb:cc:dd:ee:77", payload)

    def test_a_write_needs_both_the_session_and_the_csrf_token(self) -> None:
        """The cookie proves who; the token proves the app, not another site."""
        cookie, token = self.sign_in()
        # A label write rather than a scan: this exercises the same gate without
        # starting a collector that would race the test's own connection.
        body = {"selector": "10.23.45.7", "name": "Labelled", "type": "computer"}
        status, _, _ = self.call("/api/label", "POST", body, cookie=cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.call("/api/label", "POST", body, cookie=cookie, token=token)
        self.assertEqual(status, 200)

    def test_repeated_failures_lock_the_client_out(self) -> None:
        for _ in range(self.auth.MAX_FAILURES):
            self.call("/api/login", "POST", {"username": "admin", "password": "wrong"})
        # The correct password must also be refused, or the lockout is decorative.
        status, _, _ = self.call(
            "/api/login", "POST", {"username": "admin", "password": self.PASSWORD}
        )
        self.assertEqual(status, 429)

    # -- changing the password ------------------------------------------------
    def test_changing_the_password_revokes_other_sessions(self) -> None:
        other_cookie, _ = self.sign_in()
        cookie, token = self.sign_in()
        status, _, headers = self.call(
            "/api/account/password", "POST",
            {"current_password": self.PASSWORD, "new_password": "another-long-password"},
            cookie=cookie, token=token,
        )
        self.assertEqual(status, 200)
        # The browser that made the change keeps working, on a fresh session.
        self.assertEqual(self.call("/api/devices", cookie=cookie)[0], 401)
        renewed = headers["Set-Cookie"].split(";")[0]
        self.assertEqual(self.call("/api/devices", cookie=renewed)[0], 200)
        # Every other browser is signed out.
        self.assertEqual(self.call("/api/devices", cookie=other_cookie)[0], 401)
        # And the old password no longer works.
        self.assertEqual(
            self.call("/api/login", "POST",
                      {"username": "admin", "password": self.PASSWORD})[0],
            401,
        )

    def test_a_weak_replacement_password_is_refused(self) -> None:
        cookie, token = self.sign_in()
        status, payload, _ = self.call(
            "/api/account/password", "POST",
            {"current_password": self.PASSWORD, "new_password": "short"},
            cookie=cookie, token=token,
        )
        self.assertEqual(status, 400)
        self.assertIn("at least", json.loads(payload)["error"])

    def test_the_current_password_must_be_correct(self) -> None:
        cookie, token = self.sign_in()
        status, _, _ = self.call(
            "/api/account/password", "POST",
            {"current_password": "wrong", "new_password": "another-long-password"},
            cookie=cookie, token=token,
        )
        self.assertEqual(status, 403)

    def test_logout_clears_the_cookie_and_the_session(self) -> None:
        cookie, token = self.sign_in()
        status, _, headers = self.call("/api/logout", "POST", {}, cookie=cookie, token=token)
        self.assertEqual(status, 204)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.call("/api/devices", cookie=cookie)[0], 401)


class AccountTestCase(unittest.TestCase):
    """Account rules that need no server."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = AtlasDB(Path(self.temp.name) / "atlas.db")
        self.addCleanup(self.db.close)

    def test_only_one_account_can_exist(self) -> None:
        from network_atlas import auth

        salt, hashed = auth.hash_password("a-long-enough-password")
        self.db.create_account("admin", hashed, salt)
        with self.assertRaises(ValueError):
            self.db.create_account("someone-else", hashed, salt)

    def test_password_hashing_is_salted_and_verifiable(self) -> None:
        from network_atlas import auth

        first_salt, first = auth.hash_password("the-same-password")
        second_salt, second = auth.hash_password("the-same-password")
        # Distinct salts, so identical passwords do not produce identical hashes.
        self.assertNotEqual(first_salt, second_salt)
        self.assertNotEqual(first, second)
        self.assertTrue(auth.verify_password("the-same-password", first_salt, first))
        self.assertFalse(auth.verify_password("another-password", first_salt, first))
        self.assertFalse(auth.verify_password("", first_salt, first))

    def test_usernames_are_validated_and_lowercased(self) -> None:
        from network_atlas import auth

        self.assertEqual(auth.normalize_username("  Admin "), "admin")
        for bad in ("a", "-leading", "has space", "x" * 40, "", "wi;ld"):
            with self.subTest(username=bad), self.assertRaises(auth.AuthError):
                auth.normalize_username(bad)

    def test_password_strength_floor(self) -> None:
        from network_atlas import auth

        with self.assertRaises(auth.AuthError):
            auth.check_password_strength("short")
        auth.check_password_strength("x" * auth.MIN_PASSWORD_LENGTH)
        with self.assertRaises(auth.AuthError):
            # An unbounded input would make scrypt a denial-of-service vector.
            auth.check_password_strength("x" * (auth.MAX_PASSWORD_LENGTH + 1))

    def test_a_failed_bind_does_not_consume_the_password(self) -> None:
        """A taken port must not cost a credential.

        The account was created before the socket was bound, while its password was
        printed after -- so a port collision created an account whose password
        nobody had ever seen, recoverable only by resetting it.
        """
        import socket

        from network_atlas import server

        path = Path(self.temp.name) / "contended.db"
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        self.addCleanup(holder.close)
        port = holder.getsockname()[1]

        with self.assertRaises(RuntimeError) as caught:
            server.serve(path, host="127.0.0.1", port=port)
        self.assertIn("already in use", str(caught.exception))

        # No account, so the next start still prints a password the user can read.
        with AtlasDB(path) as db:
            self.assertFalse(db.account_exists())

    def test_first_start_creates_the_account_and_returns_the_password(self) -> None:
        """The password is shown once because only its hash is kept."""
        from network_atlas import auth, server

        path = Path(self.temp.name) / "fresh.db"
        password = server.ensure_account(path)
        self.assertIsNotNone(password)
        with AtlasDB(path) as db:
            account = db.account()
            self.assertEqual(account["username"], auth.DEFAULT_USERNAME)
            self.assertTrue(
                auth.verify_password(
                    password, account["password_salt"], account["password_hash"]
                )
            )
            # The password itself is nowhere in the row.
            self.assertNotIn(password.encode(), bytes(account["password_hash"]))
        # A second start must not mint a new password over the existing account.
        self.assertIsNone(server.ensure_account(path))


if __name__ == "__main__":
    unittest.main()
