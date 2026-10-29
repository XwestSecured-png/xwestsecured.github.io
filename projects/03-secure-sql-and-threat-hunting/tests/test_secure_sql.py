"""python3 -m unittest discover -s tests -v"""
import os, sqlite3, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("secure_coding", "detection", "lab", "hunting"):
    sys.path.insert(0, str(ROOT / sub))
import auth_demo, detect_sqli_logs, build_lab_db, run_hunts  # noqa: E402


class SecureAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        auth_demo.build_db(cls.path)
        cls.safe, cls.vuln = auth_demo.SecureAuth(cls.path), auth_demo.VulnerableAuth(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.safe.con.close(); cls.vuln.con.close(); os.remove(cls.path)

    def test_valid_login(self):
        self.assertEqual(self.safe.login("jdoe", "spring-meadow-lantern-77"), ("jdoe", "user"))

    def test_wrong_password(self):
        self.assertIsNone(self.safe.login("jdoe", "wrong"))

    def test_injection_payloads_blocked(self):
        for u, p in [("admin' --", "x"), ("x' OR '1'='1", "x' OR '1'='1"), ("admin'", "x")]:
            self.assertIsNone(self.safe.login(u, p))
            self.assertIsNotNone(self.vuln.login(u, p))      # proves the payload is real

    def test_union_returns_nothing(self):
        self.assertEqual(self.safe.search("x' UNION SELECT username, password_pt FROM users --", "username"), [])

    def test_order_by_allowlist(self):
        a = self.safe.search("IT", auth_demo._blind("C"))
        b = self.safe.search("IT", auth_demo._blind("X"))
        self.assertEqual(a, b)                               # no oracle

    def test_read_only_connection(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.safe.con.execute("DELETE FROM users")

    def test_hash_format_and_salt(self):
        h1, h2 = auth_demo.hash_password("x" * 20), auth_demo.hash_password("x" * 20)
        self.assertNotEqual(h1, h2)
        self.assertTrue(auth_demo.verify_password("x" * 20, h1))

    def test_length_limits(self):
        self.assertIsNone(self.safe.login("a" * 1000, "b"))


class DetectorTests(unittest.TestCase):
    def test_benign_not_flagged(self):
        for uri in ["/search?q=O%27Brien+jacket", "/blog/what-is-sql-injection", "/products?id=12"]:
            self.assertLess(detect_sqli_logs.score(uri)[0], 5, uri)

    def test_attacks_flagged(self):
        for uri in ["/p?id=1+UNION+SELECT+1,2--", "/p?id=1%2520AND%2520SLEEP(5)",
                    "/p?id=1/**/UNION/**/SELECT/**/table_name/**/FROM/**/information_schema.tables"]:
            self.assertGreaterEqual(detect_sqli_logs.score(uri)[0], 5, uri)

    def test_sample_log_sources(self):
        rc = detect_sqli_logs.main([str(ROOT / "detection/sample_access.log")])
        self.assertEqual(rc, 1)


class HuntTests(unittest.TestCase):
    def test_hunts_find_planted_activity(self):
        fd, db = tempfile.mkstemp(suffix=".db"); os.close(fd)
        try:
            build_lab_db.build(db)
            con = sqlite3.connect(db)
            hunts = {t.split()[0]: q for t, _, q in run_hunts.parse_hunts(
                (ROOT / "hunting/threat_hunting_queries.sql").read_text())}
            self.assertEqual(len(hunts), 10)
            self.assertEqual(len(con.execute(hunts["H04"]).fetchall()), 1)
            self.assertEqual(len(con.execute(hunts["H06"]).fetchall()), 1)
            self.assertEqual(con.execute(hunts["H09"]).fetchall()[0][0], "203.0.113.99")
            con.close()
        finally:
            os.remove(db)


if __name__ == "__main__":
    unittest.main()
