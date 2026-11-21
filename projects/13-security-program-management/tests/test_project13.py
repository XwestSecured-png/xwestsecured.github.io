import json, sys, tempfile, unittest, csv
from datetime import date
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for p in ("tabletop", "vendor_risk", "kpi"):
    sys.path.insert(0, str(ROOT / p))
import score_exercise, vendor_risk, build_dashboard  # noqa: E402


class Tabletop(unittest.TestCase):
    def setUp(self):
        self.ex = json.loads((ROOT / "tabletop/ransomware_exercise.json").read_text())

    def test_perfect_responses_score_100(self):
        resp = {"exercise_date": "x", "team": "x", "responses": {str(i["id"]): i["expected"] for i in self.ex["injects"]}}
        self.assertEqual(score_exercise.score(self.ex, resp)["overall"], 100)

    def test_sample_produces_improvement_items(self):
        resp = json.loads((ROOT / "tabletop/sample_responses.json").read_text())
        r = score_exercise.score(self.ex, resp)
        md = score_exercise.aar(self.ex, resp, r)
        self.assertIn("Sanctions check before any payment", md)
        self.assertLess(r["overall"], 100)

    def test_every_inject_has_csf_mapping(self):
        for i in self.ex["injects"]:
            self.assertTrue(i["nist"] and i["expected"])


class VendorRisk(unittest.TestCase):
    def setUp(self):
        self.v = {x["name"]: x for x in json.loads((ROOT / "vendor_risk/vendors.json").read_text())["vendors"]}
        self.d = date(2026, 11, 21)

    def test_privileged_msp_without_mfa_is_critical_and_overdue(self):
        r = vendor_risk.assess(self.v["NetWatch MSP"], self.d)
        self.assertEqual(r["tier"], "Critical"); self.assertGreater(r["review_overdue_days"], 0)
        self.assertTrue(any("MFA" in f for f in r["flags"]))

    def test_low_risk_vendor_gets_no_follow_ups(self):
        r = vendor_risk.assess(self.v["QuickPrint Supplies"], self.d)
        self.assertEqual(r["tier"], "Low"); self.assertEqual(r["follow_ups"], [])

    def test_controls_reduce_residual(self):
        v = json.loads(json.dumps(self.v["PayrollCloud Inc."]))
        good = vendor_risk.assess(v, self.d)["residual"]
        v["answers"] = {k: False for k in v["answers"]}
        self.assertGreater(vendor_risk.assess(v, self.d)["residual"], good)

    def test_ai_training_flag(self):
        self.assertTrue(any("AI" in f for f in vendor_risk.assess(self.v["AIScribe Notes"], self.d)["flags"]))


class Dashboard(unittest.TestCase):
    def test_status_logic_both_directions(self):
        up = {"target": 95, "amber": 85, "better": "higher"}; down = {"target": 0, "amber": 3, "better": "lower"}
        self.assertEqual([build_dashboard.status(v, up) for v in (96, 90, 80)], ["good", "warning", "critical"])
        self.assertEqual([build_dashboard.status(v, down) for v in (0, 2, 5)], ["good", "warning", "critical"])

    def test_page_is_self_contained(self):
        rows = list(csv.DictReader((ROOT / "kpi/metrics.csv").open()))
        page, summary = build_dashboard.build(rows, json.loads((ROOT / "kpi/targets.json").read_text()))
        self.assertNotIn("http://", page.replace("http://www.w3", "")); self.assertNotIn("https://", page)
        self.assertEqual(len(summary), 9); self.assertIn("Table view", page)


if __name__ == "__main__":
    unittest.main()
