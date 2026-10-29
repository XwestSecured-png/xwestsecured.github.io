"""python3 -m unittest discover -s tests -v"""
import json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import grc_report as g  # noqa: E402


class GRCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = json.loads((ROOT / "config.json").read_text())
        cls.cats, cls.fn, cls.road, cls.risks = g.analyze(
            g.load_csv(ROOT / "assessment/csf2_profile.csv"), g.load_csv(ROOT / "risk/risk_register.csv"), cls.cfg)

    def test_all_22_csf2_categories(self):
        self.assertEqual(len(self.cats), 22)
        self.assertEqual(list(self.fn), g.FUNCTIONS)
        self.assertEqual(len({c["category_id"] for c in self.cats}), 22)

    def test_category_ids_match_function(self):
        prefix = {"Govern": "GV", "Identify": "ID", "Protect": "PR", "Detect": "DE", "Respond": "RS", "Recover": "RC"}
        for c in self.cats:
            self.assertTrue(c["category_id"].startswith(prefix[c["function"]] + "."))

    def test_roadmap_sorted_and_phased(self):
        scores = [c["priority_score"] for c in self.road]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(self.road[0]["category_id"], "PR.AA")
        self.assertEqual(sum(c["phase"] == "0-90 days" for c in self.road), 5)

    def test_risk_scoring(self):
        r1 = next(r for r in self.risks if r["risk_id"] == "R-01")
        self.assertEqual((r1["inherent"], r1["inherent_band"], r1["residual"]), (20, "critical", 6))
        self.assertTrue(r1["within_appetite"])
        self.assertFalse(next(r for r in self.risks if r["risk_id"] == "R-03")["within_appetite"])

    def test_band_edges(self):
        b = self.cfg["risk_bands"]
        self.assertEqual([g.band(x, b) for x in (4, 5, 9, 10, 16, 17)],
                         ["low", "medium", "medium", "high", "high", "critical"])

    def test_report_files(self):
        with tempfile.TemporaryDirectory() as d:
            g.main(["--profile", str(ROOT / "assessment/csf2_profile.csv"), "--risks", str(ROOT / "risk/risk_register.csv"),
                    "--config", str(ROOT / "config.json"), "--out", d])
            for f in ("grc_report.md", "grc_report.html", "roadmap.csv", "heatmap_inherent.svg", "csf_functions.svg"):
                self.assertTrue((Path(d) / f).stat().st_size > 200, f)
            self.assertIn("<svg", (Path(d) / "grc_report.html").read_text())


if __name__ == "__main__":
    unittest.main()
