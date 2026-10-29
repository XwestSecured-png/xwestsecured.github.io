"""python3 -m unittest discover -s tests -v"""
import sys, unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cloud_identity_audit as c  # noqa: E402

TODAY = date(2026, 10, 29)
SD = ROOT / "sample_data"


def ids(findings, check):
    return {f.resource for f in findings if f.check == check}


class AWSTests(unittest.TestCase):
    f = c.audit_aws(SD / "aws", TODAY, c.DEFAULTS)

    def test_root(self):
        self.assertTrue(ids(self.f, "AWS-IAM-01") and ids(self.f, "AWS-IAM-02"))

    def test_mfa_only_console_users(self):
        self.assertEqual(ids(self.f, "AWS-IAM-04"), {"jdoe"})      # backup-svc has no console password

    def test_admin_detection_managed_and_inline(self):
        self.assertEqual(ids(self.f, "AWS-IAM-09"), {"ci-deploy", "former-contractor"})

    def test_sg_ipv4_ipv6_and_all_protocols(self):
        self.assertEqual(len(ids(self.f, "AWS-NET-01")), 2)
        self.assertFalse(any("web-public" in r for r in ids(self.f, "AWS-NET-01")))

    def test_admin_doc(self):
        self.assertTrue(c._is_admin_doc({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}))
        self.assertFalse(c._is_admin_doc({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))


class EntraTests(unittest.TestCase):
    f = c.audit_entra(SD / "entra", TODAY, c.DEFAULTS)

    def test_phishing_resistant(self):
        self.assertEqual(ids(self.f, "ENT-MFA-02"), {"globaladmin2@corp.example"})   # admin.west has a passkey

    def test_report_only_legacy_block_does_not_count(self):
        self.assertTrue(ids(self.f, "ENT-CA-01"))

    def test_guest_admin(self):
        self.assertEqual(len(ids(self.f, "ENT-PRIV-02")), 1)


class ADTests(unittest.TestCase):
    f = c.audit_ad(SD / "ad", TODAY, c.DEFAULTS)

    def test_kerberos(self):
        self.assertEqual(ids(self.f, "AD-KRB-02"), {"svc_sql", "svc_backup"})
        self.assertEqual(ids(self.f, "AD-KRB-03"), {"scanner"})
        self.assertEqual(ids(self.f, "AD-KRB-01"), {"krbtgt"})

    def test_disabled_accounts_ignored(self):
        self.assertNotIn("termed.user", {f.resource for f in self.f})

    def test_stale(self):
        self.assertEqual(ids(self.f, "AD-ACC-01"), {"old.helpdesk", "intern2024"})


if __name__ == "__main__":
    unittest.main()
