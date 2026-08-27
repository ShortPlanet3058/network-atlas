from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from network_atlas.classifier import classify, classify_all
from network_atlas.db import AtlasDB
from network_atlas.parsers import import_arp_scan, import_avahi, import_nmap_xml
from network_atlas.snmp import parse_walk
from network_atlas.util import normalize_mac, validate_target


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
        printer = next(item for item in devices if item["hostname"] == "office-printer.lab.internal")
        router = next(item for item in devices if item["hostname"] == "gateway.lab.internal")
        server = next(item for item in devices if item["hostname"] == "home-server.lab.internal")
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
        statuses = {item["mac"]: item["status"] for item in self.db.devices()}
        self.assertEqual(statuses["00:11:22:33:44:55"], "offline")
        self.assertEqual(statuses["00:11:22:33:44:66"], "online")

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


if __name__ == "__main__":
    unittest.main()
