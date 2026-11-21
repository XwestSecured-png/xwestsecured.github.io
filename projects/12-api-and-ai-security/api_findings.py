#!/usr/bin/env python3
"""
OWASP API Security Top 10 (2023) verification harness for api_lab.

Runs a proof of concept for each finding against BOTH builds, in-process (WSGI calls,
no sockets), and checks: reproduces on the vulnerable build -> blocked on the secure
build -> the legitimate feature still works. Exit code 0 only if every check passes.

    python3 api_findings.py --out reports/
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "api_lab")); sys.path.insert(0, str(ROOT))
from app import Api  # noqa: E402
import cvss  # noqa: E402

FINDINGS = [
    ("API2-a", "JWT 'alg:none' accepted: forge an admin token with no password", "API2:2023 Broken Authentication", "CWE-347",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("API3-a", "Mass assignment: customer sets own role to admin", "API3:2023 Broken Object Property Level Authorization", "CWE-915",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("API5", "Customer can call admin-only DELETE /api/admin/users", "API5:2023 Broken Function Level Authorization", "CWE-285",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"),
    ("API1", "BOLA: read another customer's account by changing the ID", "API1:2023 Broken Object Level Authorization", "CWE-639",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    ("API2-b", "No login throttling: unlimited password guessing", "API2:2023 Broken Authentication", "CWE-307",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    ("API3-b", "Excessive data exposure: response includes SSN digits", "API3:2023 Broken Object Property Level Authorization", "CWE-213",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    ("API4", "Unbounded page size: ?limit=100000 returns everything", "API4:2023 Unrestricted Resource Consumption", "CWE-770",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"),
    ("API8", "Wildcard CORS with credentials flag", "API8:2023 Security Misconfiguration", "CWE-942",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
]


class Client:
    def __init__(self, app):
        self.app, self.token = app, None

    def req(self, method, path, body=None, token=None):
        raw = json.dumps(body).encode() if body is not None else b""
        p, _, q = path.partition("?")
        tok = token if token is not None else self.token
        env = {"REQUEST_METHOD": method, "PATH_INFO": p, "QUERY_STRING": q, "CONTENT_LENGTH": str(len(raw)),
               "wsgi.input": io.BytesIO(raw), "HTTP_AUTHORIZATION": f"Bearer {tok}" if tok else ""}
        out = {}
        data = b"".join(self.app(env, lambda s, h: out.update(status=int(s[:3]), headers=dict(h))))
        return out["status"], out["headers"], json.loads(data or b"{}")

    def login(self, u, p):
        s, _, b = self.req("POST", "/api/login", {"username": u, "password": p})
        self.token = b.get("token")
        return s


def b64u(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def run(mode):
    r = {}
    # API2-a: unsigned token claiming to be user 3 (admin)
    c = Client(Api(mode)); forged = f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{b64u({'sub': 3})}."
    s, _, b = c.req("DELETE", "/api/admin/users/2", token=forged)
    ok = Client(Api(mode)); ok.login("admin", "Admin-Harbor-Quiet-26")
    r["API2-a"] = {"reproduced": s == 200, "functional": ok.req("GET", "/api/transactions")[0] == 200,
                   "evidence": f"DELETE /api/admin/users/2 with alg:none token -> {s} {b}"}
    # API3-a: mass assignment
    c = Client(Api(mode)); c.login("alice", "Alice-Lamp-Garden-26")
    s, _, b = c.req("PATCH", "/api/users/me", {"email": "alice@new.example", "role": "admin"})
    s2, _, b2 = c.req("PATCH", "/api/users/me", {"email": "alice@new.example"})
    r["API3-a"] = {"reproduced": b.get("role") == "admin", "functional": s2 == 200 and b2.get("email") == "alice@new.example",
                   "evidence": f"PATCH /api/users/me {{role:admin}} -> {s} role={b.get('role')}"}
    # API5: BFLA
    c = Client(Api(mode)); c.login("alice", "Alice-Lamp-Garden-26")
    s, _, b = c.req("DELETE", "/api/admin/users/2")
    adm = Client(Api(mode)); adm.login("admin", "Admin-Harbor-Quiet-26")
    r["API5"] = {"reproduced": s == 200, "functional": adm.req("DELETE", "/api/admin/users/2")[0] == 200,
                 "evidence": f"DELETE /api/admin/users/2 as customer -> {s} {b}"}
    # API1: BOLA
    c = Client(Api(mode)); c.login("alice", "Alice-Lamp-Garden-26")
    s, _, b = c.req("GET", "/api/accounts/502")
    own = c.req("GET", "/api/accounts/501")
    r["API1"] = {"reproduced": s == 200 and b.get("balance") == 98000.0,
                 "functional": own[0] == 200, "evidence": f"GET /api/accounts/502 as alice -> {s} {b}"}
    # API3-b: excessive data exposure on own account
    r["API3-b"] = {"reproduced": "ssn_last4" in own[2], "functional": own[0] == 200 and "balance" in own[2],
                   "evidence": f"GET /api/accounts/501 fields -> {sorted(own[2])}"}
    # API2-b: brute force
    app = Api(mode); c = Client(app)
    codes = [c.login("bob", f"wrong-{i}") for i in range(12)]
    r["API2-b"] = {"reproduced": 429 not in codes, "functional": Client(Api(mode)).login("bob", "Bob-River-Stone-26") == 200,
                   "evidence": f"12 wrong passwords -> statuses {sorted(set(codes))}"}
    # API4: unbounded limit
    c = Client(Api(mode)); c.login("alice", "Alice-Lamp-Garden-26")
    s, _, b = c.req("GET", "/api/transactions?limit=100000")
    r["API4"] = {"reproduced": b.get("count", 0) > 100, "functional": c.req("GET", "/api/transactions?limit=10")[2]["count"] == 10,
                 "evidence": f"GET /api/transactions?limit=100000 -> {b.get('count')} rows"}
    # API8: CORS
    s, h, _ = c.req("GET", "/api/transactions")
    r["API8"] = {"reproduced": h.get("Access-Control-Allow-Origin") == "*", "functional": s == 200,
                 "evidence": f"Access-Control-Allow-Origin: {h.get('Access-Control-Allow-Origin')}"}
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, default=Path("reports")); a = ap.parse_args(argv)
    v, s = run("vulnerable"), run("secure")
    rows, ok_all = [], True
    print(f"{'ID':<7}{'CVSS':>5} {'Sev':<9}{'Vulnerable':<13}{'Secure':<9}{'Works':<6} Finding")
    for fid, title, owasp, cwe, vec in FINDINGS:
        sc = cvss.base_score(vec); ok = v[fid]["reproduced"] and not s[fid]["reproduced"] and s[fid]["functional"]
        ok_all &= ok
        rows.append({"id": fid, "title": title, "owasp": owasp, "cwe": cwe, "vector": vec, "cvss": sc,
                     "severity": cvss.severity(sc), "vulnerable": v[fid], "secure": s[fid], "pass": ok})
        print(f"{fid:<7}{sc:>5} {cvss.severity(sc):<9}{'EXPLOITABLE' if v[fid]['reproduced'] else 'no':<13}"
              f"{'FIXED' if not s[fid]['reproduced'] else 'VULN':<9}{'yes' if s[fid]['functional'] else 'NO':<6} {title}")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "api_findings.json").write_text(json.dumps(rows, indent=2))
    md = ["# API Security Findings (OWASP API Top 10:2023)", "",
          "| ID | CVSS | Severity | OWASP API | CWE | Finding | Vulnerable build evidence | Secure build |", "|---|---|---|---|---|---|---|---|"]
    md += [f"| {x['id']} | {x['cvss']} | {x['severity']} | {x['owasp']} | {x['cwe']} | {x['title']} | `{x['vulnerable']['evidence'][:110]}` | "
           f"{'✅ blocked, feature works' if x['pass'] else '❌'} |" for x in rows]
    (a.out / "api_findings.md").write_text("\n".join(md) + "\n")
    print(f"[{'✓' if ok_all else '✗'}] {sum(x['pass'] for x in rows)}/{len(rows)} reproduced on vulnerable build and fixed on secure build")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
