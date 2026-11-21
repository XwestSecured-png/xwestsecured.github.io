import io
import re
import tempfile
import unittest
from pathlib import Path

from westguard.cli import data_path
from westguard.web.app import App, main as web_main

TOKEN = "t" * 32


class Web(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = App(Path(self.tmp.name), TOKEN, secure_cookies=False, max_upload_mb=1)

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, method, path, body=b"", ctype="", cookie="", ip="127.0.0.1"):
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(body)), "CONTENT_TYPE": ctype,
               "wsgi.input": io.BytesIO(body), "REMOTE_ADDR": ip, "HTTP_COOKIE": cookie}
        out = {}
        data = b"".join(self.app(env, lambda s, h: out.update(s=int(s[:3]), h=dict(h))))
        return out["s"], out["h"], data

    def login(self):
        s, h, _ = self.call("POST", "/login", b"token=" + TOKEN.encode())
        self.assertEqual(s, 303)
        ck = h["Set-Cookie"]
        self.assertIn("HttpOnly", ck); self.assertIn("SameSite=Strict", ck)
        ck = ck.split(";")[0]
        _, _, body = self.call("GET", "/", cookie=ck)
        return ck, re.search(rb"name='csrf' value='([^']+)'", body).group(1)

    def upload(self, ck, csrf, tool, field, fname, data):
        b = (b"--B\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n" + csrf + b"\r\n--B\r\nContent-Disposition: form-data; name=\""
             + field.encode() + b"\"; filename=\"" + fname.encode() + b"\"\r\n\r\n" + data + b"\r\n--B--\r\n")
        return self.call("POST", f"/run/{tool}", b, "multipart/form-data; boundary=B", ck)

    def test_requires_login(self):
        self.assertEqual(self.call("GET", "/")[0], 303)
        self.assertEqual(self.call("GET", "/healthz")[0], 200)

    def test_security_headers(self):
        _, h, _ = self.call("GET", "/login")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_wrong_token_and_rate_limit(self):
        codes = [self.call("POST", "/login", b"token=nope", ip="192.0.2.5")[0] for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5); self.assertEqual(codes[-1], 429)

    def test_job_flow_and_traversal(self):
        ck, csrf = self.login()
        rules = data_path("samples", "firewall", "sample_ruleset.json").read_bytes()
        s, h, _ = self.upload(ck, csrf, "firewall", "ruleset", "../../evil.json", rules)
        self.assertEqual(s, 303)
        job = h["Location"]
        s, _, body = self.call("GET", job, cookie=ck)
        self.assertEqual(s, 200); self.assertIn(b"critical findings", body)
        uploaded = list((Path(self.tmp.name) / "jobs").glob("*/in/ruleset/*"))
        self.assertEqual(uploaded[0].name, "evil.json")             # path components stripped
        self.assertEqual(self.call("GET", job + "/../job.json", cookie=ck)[0], 404)
        self.assertEqual(self.call("GET", job + "/firewall_audit.md", cookie=ck)[1]["Content-Type"], "text/plain; charset=utf-8")

    def test_csrf_and_size_limit(self):
        ck, _ = self.login()
        self.assertEqual(self.upload(ck, b"forged", "firewall", "ruleset", "r.json", b"{}")[0], 403)
        _, csrf = self.login()
        self.assertEqual(self.upload(ck, csrf, "firewall", "ruleset", "r.json", b"x" * (2 * 1024 * 1024))[0], 413)

    def test_audit_log_written(self):
        self.login()
        self.assertIn("login_ok", (Path(self.tmp.name) / "audit.log").read_text())

    def test_refuses_insecure_remote_bind(self):
        with self.assertRaises(SystemExit):
            web_main(["--host", "0.0.0.0", "--data-dir", self.tmp.name])
        with self.assertRaises(SystemExit):
            web_main(["--host", "0.0.0.0", "--allow-remote", "--data-dir", self.tmp.name])


if __name__ == "__main__":
    unittest.main()
