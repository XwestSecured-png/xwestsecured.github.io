import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detections"))
import engine, export_sigma  # noqa: E402
from rules import RULES  # noqa: E402
from sigma_lite import match_detection  # noqa: E402


class RuleFixtures(unittest.TestCase):
    """Every rule must fire on its positive fixture and stay silent on its negative one."""

    def test_fixtures(self):
        for r in RULES:
            with self.subTest(rule=r["id"]):
                if "pos" in r:
                    self.assertTrue(match_detection(r["pos"], r["detection"]))
                    self.assertFalse(match_detection(r["neg"], r["detection"]))
                else:
                    self.assertTrue(engine.run_rule(r, r["pos_series"]), "positive series did not fire")
                    self.assertFalse(engine.run_rule(r, r["neg_series"]), "negative series fired")

    def test_metadata_complete(self):
        for r in RULES:
            for k in ("id", "title", "level", "attack", "description", "falsepositives", "logsource"):
                self.assertTrue(r.get(k), f"{r['id']} missing {k}")
            self.assertIn(r["level"], ("low", "medium", "high", "critical"))


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts = engine.run(engine.load(ROOT / "data/cloudtrail.jsonl"), engine.load(ROOT / "data/entra_signins.jsonl"))

    def test_every_rule_fires_on_planted_attack(self):
        self.assertEqual({a["rule"] for a in self.alerts}, {r["id"] for r in RULES})

    def test_no_alerts_on_benign_traffic(self):
        for a in self.alerts:
            benign_actor = any(x in a["summary"] for x in ("maria.ortiz", "sam.patel", "lambda-etl", "ci-deploy-role", "dana.kim"))
            self.assertFalse(benign_actor, a)

    def test_cloudtrail_records_wrapper_supported(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"Records": [RULES[0]["pos"]]}, f)
        self.assertEqual(len(engine.load(Path(f.name))), 1)


class SigmaExport(unittest.TestCase):
    def test_export_shapes(self):
        y = export_sigma.to_sigma(next(r for r in RULES if r["id"] == "CLD-011"))
        self.assertIn("correlation:", y); self.assertIn("attack.t1621", y); self.assertIn("timespan: 10m", y)

    def test_pysigma_parses_if_installed(self):
        try:
            from sigma.collection import SigmaCollection
        except ImportError:
            self.skipTest("pySigma not installed")
        for r in RULES:
            if "python_only" not in r:
                SigmaCollection.from_yaml(export_sigma.to_sigma(r))


if __name__ == "__main__":
    unittest.main()
