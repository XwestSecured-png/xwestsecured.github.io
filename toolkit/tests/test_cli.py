import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from westguard import __version__
from westguard.cli import COMMANDS, data_path, main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def test_version_and_list(self):
        self.assertEqual(run("version")[1].strip(), __version__)
        code, out, _ = run("list")
        self.assertEqual(code, 0)
        for name in COMMANDS:
            self.assertIn(name, out)

    def test_every_command_has_help(self):
        for name in COMMANDS:
            code, out, _ = run(name, "--help")
            self.assertEqual(code, 0, name)
            self.assertIn(f"westguard {name}", out, name)

    def test_usage_errors_return_64(self):
        self.assertEqual(run("no-such-command")[0], 64)
        self.assertEqual(run("vuln")[0], 64)                       # missing required --findings
        self.assertEqual(run("file-triage", "/definitely/missing")[0], 64)

    def test_bad_input_returns_64_not_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "rules.json"
            bad.write_text("{not json")
            code, _, err = run("firewall", str(bad), "--out", d)
            self.assertEqual(code, 64)
            self.assertNotIn("Traceback", err)

    def test_doctor(self):
        self.assertEqual(run("doctor")[0], 0)

    def test_bundled_data_present(self):
        for p in [("yara", "rules.yar"), ("templates", "targets.json"), ("collectors", "win_triage.ps1"),
                  ("samples", "cloudlogs", "cloudtrail.jsonl")]:
            self.assertTrue(data_path(*p).exists(), p)

    def test_collectors_export(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("collectors", "--out", d)[0], 0)
            self.assertTrue((Path(d) / "linux_triage.sh").exists())


class Demo(unittest.TestCase):
    """End-to-end smoke test: every engine runs on bundled data and produces its reports."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.code, cls.stdout, cls.stderr = run("demo", "--out", str(cls.out))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_demo_succeeds(self):
        self.assertEqual(self.code, 0, self.stderr[-2000:])

    def test_reports_written(self):
        for f in ["logs/triage_report.json", "endpoint/triage_findings.json", "network/network_findings.json",
                  "cloud-detect/alerts.json", "sigma/cld-011.yml", "vuln/remediation_plan.csv", "sbom.cdx.json", "deps.json",
                  "secrets.sarif", "firewall/firewall_audit.json", "cloud-audit/identity_findings.json",
                  "vendor-risk/vendor_risk.json", "kpi/security_kpi_dashboard.html", "tabletop/tabletop_aar.md",
                  "intel/scattered_spider_stix21.json"]:
            self.assertTrue((self.out / f).exists(), f)

    def test_findings_are_meaningful(self):
        logs = json.loads((self.out / "logs/triage_report.json").read_text())
        self.assertTrue(logs["findings"])
        alerts = json.loads((self.out / "cloud-detect/alerts.json").read_text())
        self.assertEqual(len({a["rule"] for a in alerts}), 13)
        sarif = json.loads((self.out / "secrets.sarif").read_text())
        self.assertEqual(sarif["version"], "2.1.0")
        sbom = json.loads((self.out / "sbom.cdx.json").read_text())
        self.assertEqual(sbom["bomFormat"], "CycloneDX")


if __name__ == "__main__":
    unittest.main()
