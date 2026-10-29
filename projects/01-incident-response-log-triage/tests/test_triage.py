"""Unit tests: python3 -m unittest discover -s tests -v"""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import triage  # noqa: E402


class TriageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = triage.load_config(str(ROOT / "config.json"))
        cls.events = (triage.parse_linux(ROOT / "sample_logs/auth.log", cls.cfg)
                      + triage.parse_windows(ROOT / "sample_logs/windows_security.csv", cls.cfg))
        cls.findings = triage.run_detections(cls.events, cls.cfg)
        cls.ids = [f.rule_id for f in cls.findings]

    def test_events_parsed(self):
        self.assertGreater(len(self.events), 100)

    def test_invalid_user_not_double_counted(self):
        fails = [e for e in self.events if e.event == "login_failure" and e.src_ip == "203.0.113.45"]
        self.assertEqual(len(fails), 40)

    def test_brute_force_detected(self):
        ips = {f.entities["src_ip"] for f in self.findings if f.rule_id == "IR-001"}
        self.assertIn("203.0.113.45", ips)
        self.assertIn("198.51.100.200", ips)

    def test_single_typo_not_flagged(self):
        ips = {f.entities.get("src_ip") for f in self.findings}
        self.assertNotIn("10.20.1.33", ips)

    def test_spray_detected(self):
        self.assertIn("IR-002", self.ids)

    def test_compromise_detected(self):
        users = {f.entities["user"] for f in self.findings if f.rule_id == "IR-003"}
        self.assertEqual(users, {"deploy", "Administrator"})

    def test_priv_group_and_log_clear(self):
        self.assertIn("IR-006", self.ids)
        self.assertIn("IR-007", self.ids)

    def test_sorted_by_severity(self):
        order = [triage.SEVERITY_ORDER[f.severity] for f in self.findings]
        self.assertEqual(order, sorted(order))


if __name__ == "__main__":
    unittest.main()
