"""
Integration tests: need a disposable PostgreSQL 13+ server and psql.
    PGHOST=/tmp/pgsock PGPORT=5433 PGUSER=postgres python3 -m unittest discover -s tests -v
Skipped automatically when PGHOST is not set.
"""
import os, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@unittest.skipUnless(os.environ.get("PGHOST") and shutil.which("psql"), "needs a disposable PostgreSQL (set PGHOST)")
class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import run_lab
        cls.rl = run_lab
        cls.tmp = tempfile.mkdtemp()
        cls.rc = run_lab.main(["--out", cls.tmp])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, sql, user=None):
        return self.rl.psql(sql, user=user or self.rl.ADMIN).stdout.strip()

    def test_all_controls_pass(self):
        self.assertEqual(self.rc, 0)

    def test_breach_scope_exact(self):
        f7 = [r for t, _, r in self.rl.run_named(ROOT / "sql/07_forensic_queries.sql") if t.startswith("F7")][0]
        total = [r for r in f7 if r[0] == "TOTAL"][0]
        self.assertEqual(total[1], "120")

    def test_rls_isolation_counts(self):
        self.assertEqual(self.q("SELECT count(*) FROM app.export_site_clients()", "alice_cw"), "150")
        self.assertEqual(self.q("SELECT count(*) FROM app.export_site_clients()", "bob_cw"), "120")

    def test_denied_reads_are_logged(self):
        before = int(self.q("SELECT count(*) FROM audit.event WHERE action='DENIED'"))
        self.q("SELECT * FROM app.get_client(1151)", "alice_cw")
        self.assertEqual(int(self.q("SELECT count(*) FROM audit.event WHERE action='DENIED'")), before + 1)

    def test_zz_superuser_tampering_is_detected(self):
        f8 = lambda: [r for t, _, r in self.rl.run_named(ROOT / "sql/07_forensic_queries.sql") if t.startswith("F8")][0][1][-1]
        self.assertEqual(f8(), "INTACT")
        self.q("ALTER TABLE audit.event DISABLE TRIGGER audit_append_only; "
               "UPDATE audit.event SET row_count = 1 WHERE action = 'EXPORT'; "
               "ALTER TABLE audit.event ENABLE TRIGGER audit_append_only;")
        self.assertEqual(f8(), "TAMPERED")


if __name__ == "__main__":
    unittest.main()
