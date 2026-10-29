"""python3 -m unittest discover -s tests -v"""
import json, sys, unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "firewall"))
import netdetect as nd      # noqa: E402
import firewall_audit as fa  # noqa: E402


class NetDetectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = nd.load_config(str(ROOT / "config.json"))
        z = nd.Zones(cfg["internal_networks"])
        flows = nd.load_flows(ROOT / "sample_data/conn.log")
        dns = nd.read_zeek(ROOT / "sample_data/dns.log")
        cls.f = (nd.detect_scans(flows, cfg, z) + nd.detect_beacons(flows, cfg, z) + nd.detect_exfil(flows, cfg, z)
                 + nd.detect_policy(flows, cfg, z) + nd.detect_dns_tunnel(dns, cfg))

    def ids(self, rule):
        return [x for x in self.f if x.rule_id == rule]

    def test_all_planted_scenarios_and_nothing_else(self):
        self.assertEqual(len(self.f), 7)

    def test_scans(self):
        srcs = {x.entities["src"] for x in self.ids("NET-001")}
        self.assertEqual(srcs, {"203.0.113.50", "10.10.20.66"})

    def test_beacon_detected_allowlist_respected(self):
        b = self.ids("NET-002")
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0].entities["dst"], "198.51.100.66")

    def test_exfil(self):
        self.assertEqual(self.ids("NET-003")[0].severity, "critical")

    def test_policy(self):
        self.assertEqual({x.entities["dst_port"] for x in self.ids("NET-004")}, {445, 3389})

    def test_dns_tunnel(self):
        self.assertEqual(self.ids("NET-005")[0].entities["domain"], "c2.example")

    def test_entropy(self):
        self.assertLess(nd.shannon("aaaa"), 1)
        self.assertGreater(nd.shannon("k3j9x2m7q8w1z5"), 3.5)


class FirewallTests(unittest.TestCase):
    def audit(self, name):
        return fa.audit(json.loads((ROOT / "firewall" / name).read_text()), date(2026, 10, 29))

    def test_sample_findings(self):
        checks = {f["check"] for f in self.audit("sample_ruleset.json")}
        self.assertEqual(checks, {f"FW-{i:03d}" for i in range(1, 11)})

    def test_conflicting_shadow(self):
        f = [x for x in self.audit("sample_ruleset.json") if x["check"] == "FW-004" and x["rule_id"] == 50]
        self.assertEqual(f[0]["severity"], "high")

    def test_disabled_rule_ignored_for_exposure(self):
        self.assertFalse([x for x in self.audit("sample_ruleset.json") if x["rule_id"] == 120 and x["check"] == "FW-002"])

    def test_hardened_clean(self):
        self.assertEqual(self.audit("hardened_ruleset.json"), [])


if __name__ == "__main__":
    unittest.main()
