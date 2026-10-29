"""python3 -m unittest discover -s tests -v"""
import json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import phish_analyzer as pa  # noqa: E402
import timeline  # noqa: E402

CFG = {**pa.DEFAULT_CFG, **{k: v for k, v in json.loads((ROOT / "config.json").read_text()).items() if not k.startswith("_")}}
S = ROOT / "samples"


class AnalyzerTests(unittest.TestCase):
    cred = pa.analyze(S / "01_credential_phish.eml", CFG)
    bec = pa.analyze(S / "02_bec_vendor_fraud.eml", CFG)
    news = pa.analyze(S / "03_legit_newsletter.eml", CFG)

    def test_verdicts(self):
        self.assertEqual((self.cred["verdict"], self.bec["verdict"], self.news["verdict"]),
                         ("MALICIOUS", "MALICIOUS", "LIKELY BENIGN"))

    def test_lookalikes(self):
        self.assertEqual(pa.lookalike("c0rp.example", ["corp.example"]), "corp.example")
        self.assertEqual(pa.lookalike("payflow-billing.example", ["payflow.example"]), "payflow.example")
        self.assertIsNone(pa.lookalike("intranet.corp.example", ["corp.example"]))
        self.assertEqual(pa.lookalike("rnicrosoft.example", ["microsoft.example"]), "microsoft.example")

    def test_link_mismatch_and_smuggling(self):
        details = " ".join(s["detail"] for s in self.cred["signals"])
        self.assertIn("Link text shows 'portal.corp.example'", details)
        self.assertIn("HTML smuggling", details)
        self.assertIn("T1027.006", self.cred["attack"])

    def test_double_extension(self):
        self.assertIn("double extension", self.cred["attachments"][0]["notes"])

    def test_bec(self):
        self.assertIn("T1656", self.bec["attack"])
        self.assertTrue(any("Reply-To" in s["detail"] for s in self.bec["signals"]))

    def test_ip_ioc_typed(self):
        types = {(i["type"], i["value"]) for i in self.cred["iocs"]}
        self.assertIn(("ipv4-addr", "198.51.100.23"), types)
        self.assertNotIn(("domain-name", "198.51.100.23"), types)

    def test_stix(self):
        b = pa.stix_bundle([self.cred, self.bec, self.news])
        self.assertEqual(b["type"], "bundle")
        self.assertTrue(all(o["spec_version"] == "2.1" for o in b["objects"]))
        self.assertFalse(any("intranet.corp.example" in o.get("pattern", "") for o in b["objects"]))


class TimelineTests(unittest.TestCase):
    def test_scope(self):
        with tempfile.TemporaryDirectory() as d:
            res = [pa.analyze(p, CFG) for p in sorted(S.glob("*.eml"))]
            pj = Path(d) / "p.json"; pj.write_text(json.dumps(res))
            L = ROOT / "logs"
            timeline.main(["--phish", str(pj), "--trace", str(L / "message_trace.csv"), "--proxy", str(L / "proxy.csv"),
                           "--signins", str(L / "signins.csv"), "--edr", str(L / "edr_events.csv"), "--out", d])
            r = json.loads((Path(d) / "incident_scope.json").read_text())
            stage = {x["user"]: x["highest_stage"] for x in r["impact"]}
            self.assertEqual(stage["jdoe"], "compromised")
            self.assertEqual(stage["tnguyen"], "submitted_credentials")
            self.assertEqual(stage["mlee"], "clicked")
            self.assertNotIn("rgarcia", stage)                 # quarantined, never exposed
            self.assertEqual(r["new_iocs"], ["203.0.113.88"])


if __name__ == "__main__":
    unittest.main()
