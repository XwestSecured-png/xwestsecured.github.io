"""python3 -m unittest discover -s tests -v"""
import json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "supplychain"))
import secrets_scan, sbom, vuln_check  # noqa: E402

APP = ROOT / "sample_app"


class SecretsTests(unittest.TestCase):
    f = secrets_scan.scan(APP)

    def test_all_planted_found(self):
        self.assertEqual({x["rule_id"] for x in self.f},
                         {"SEC-PRIVKEY", "SEC-AWS-SECRET", "SEC-AWS-AKID", "SEC-DB-URI", "SEC-JWT", "SEC-GENERIC"})

    def test_no_false_positives(self):
        lines = {(x["file"], x["line"]) for x in self.f}
        src = (APP / "src/settings.py").read_text().splitlines()
        for i, l in enumerate(src, 1):
            if any(k in l for k in ("os.environ", "changeme", "your_password", "nosecret")):
                self.assertNotIn(("src/settings.py", i), lines, l)

    def test_redaction(self):
        for x in self.f:
            self.assertIn("…", x["match"]) if len(x["match"]) > 4 else None
            self.assertNotIn("wJalrXUtnFEMI/K7MDENG", x["match"])

    def test_sarif_shape(self):
        s = secrets_scan.to_sarif(self.f)
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(len(s["runs"][0]["results"]), len(self.f))

    def test_entropy(self):
        self.assertLess(secrets_scan.entropy("aaaaaaaa"), 1)


class SBOMTests(unittest.TestCase):
    bom = sbom.build(APP, "sample-app", "1.4.2")

    def test_cyclonedx(self):
        self.assertEqual((self.bom["bomFormat"], self.bom["specVersion"]), ("CycloneDX", "1.6"))

    def test_components_and_purls(self):
        purls = {c["purl"] for c in self.bom["components"]}
        self.assertIn("pkg:pypi/requests@2.19.1", purls)
        self.assertIn("pkg:pypi/pyyaml@5.3", purls)          # PEP 503 normalization
        self.assertIn("pkg:npm/lodash@4.17.15", purls)
        self.assertIn("pkg:pypi/gunicorn", purls)             # unpinned, no version

    def test_unpinned_flagged(self):
        warn = {c["name"] for c in self.bom["components"] if any(p["name"] == "warning" for p in c["properties"])}
        self.assertEqual(warn, {"flask", "gunicorn"})


class VulnTests(unittest.TestCase):
    def run_check(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d) / "bom.json"
            b.write_text(json.dumps(sbom.build(APP, "a", "1")))
            out = Path(d) / "r.json"
            rc = vuln_check.main([str(b), "--osv", str(ROOT / "sample_data/vuln_db_snapshot.json"), "--out", str(out), *extra])
            return rc, json.loads(out.read_text())

    def test_policy_fails_and_plan(self):
        rc, r = self.run_check()
        self.assertEqual(rc, 1)
        plan = {p["component"]: p["upgrade_to"] for p in r["upgrade_plan"]}
        self.assertEqual(plan["pyyaml"], ">= 5.4")
        self.assertTrue(plan["lodash"].startswith("latest"))
        self.assertNotIn("express", plan)                     # clean dependency

    def test_vkey(self):
        self.assertGreater(vuln_check.vkey("2.10.1"), vuln_check.vkey("2.9.9"))


if __name__ == "__main__":
    unittest.main()
