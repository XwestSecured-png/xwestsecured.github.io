#!/usr/bin/env python3
"""
API Lab: a small JSON REST API with a VULNERABLE and a SECURE build of the same endpoints,
covering the OWASP API Security Top 10 (2023) issues that bug bounty programs see most.

    python3 api_lab/app.py --mode vulnerable   # http://127.0.0.1:8086  (lab only)
    python3 api_lab/app.py --mode secure

!! Training target. Binds to 127.0.0.1 only and refuses any other interface. !!

Endpoints
  POST   /api/login                 {"username","password"} -> {"token"}       API2 broken authentication
  GET    /api/accounts/<id>         account details                            API1 BOLA, API3 excessive data exposure
  PATCH  /api/users/me              update own profile                         API3 mass assignment
  GET    /api/transactions?limit=N  list own transactions                      API4 unrestricted resource consumption
  DELETE /api/admin/users/<id>      admin-only user deletion                   API5 broken function-level authorization
  (all responses)                   CORS headers                               API8 security misconfiguration

Tokens are HS256 JWTs implemented with the standard library (hmac + base64).
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections import defaultdict, deque

SECRET = secrets.token_bytes(32)          # per-process signing key (never hard-code in production)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(claims: dict) -> str:
    h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(json.dumps(claims).encode())
    sig = b64u(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def hash_pw(pw: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def check_pw(pw: str, stored: str) -> bool:
    s, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(s)).split("$")[1], h)


class Api:
    LOGIN_LIMIT = 5            # failed attempts per user per window
    WINDOW = 300               # seconds
    MAX_PAGE = 100

    def __init__(self, mode: str):
        assert mode in ("vulnerable", "secure")
        self.vuln = mode == "vulnerable"
        self.users = {
            1: {"id": 1, "username": "alice", "email": "alice@bank.example", "role": "customer", "pw": hash_pw("Alice-Lamp-Garden-26")},
            2: {"id": 2, "username": "bob", "email": "bob@bank.example", "role": "customer", "pw": hash_pw("Bob-River-Stone-26")},
            3: {"id": 3, "username": "admin", "email": "ops@bank.example", "role": "admin", "pw": hash_pw("Admin-Harbor-Quiet-26")},
        }
        self.accounts = {
            501: {"id": 501, "owner": 1, "iban": "XX00 0000 0000 0501", "balance": 2450.10, "ssn_last4": "1234"},
            502: {"id": 502, "owner": 2, "iban": "XX00 0000 0000 0502", "balance": 98000.00, "ssn_last4": "5678"},
        }
        self.tx = {1: [{"id": i, "amount": round(10 + i * 1.5, 2)} for i in range(5000)],
                   2: [{"id": i, "amount": 5.0} for i in range(20)]}
        self.failed = defaultdict(deque)

    # ---- auth -------------------------------------------------------------
    def verify(self, auth_header: str):
        if not auth_header.startswith("Bearer "):
            return None
        try:
            h, p, s = auth_header[7:].split(".")
            header, claims = json.loads(b64u_dec(h)), json.loads(b64u_dec(p))
        except Exception:
            return None
        if self.vuln:
            # API2: trusts the token's own 'alg' header; "none" skips the signature entirely
            if header.get("alg", "").lower() == "none":
                return self.users.get(claims.get("sub"))
        else:
            if header.get("alg") != "HS256":
                return None
            if claims.get("exp", 0) < time.time():
                return None
        good = b64u(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(good, s):
            return None
        return self.users.get(claims.get("sub"))

    # ---- WSGI -------------------------------------------------------------
    def __call__(self, env, start):
        method, path = env["REQUEST_METHOD"], env.get("PATH_INFO", "/")
        try:
            n = int(env.get("CONTENT_LENGTH") or 0)
            if not self.vuln and n > 16_384:
                return self.send(start, 413, {"error": "payload too large"})
            body = json.loads(env["wsgi.input"].read(n) or b"{}") if n else {}
        except ValueError:
            return self.send(start, 400, {"error": "invalid JSON"})
        user = self.verify(env.get("HTTP_AUTHORIZATION", ""))
        qs = dict(p.split("=", 1) for p in env.get("QUERY_STRING", "").split("&") if "=" in p)
        parts = path.strip("/").split("/")

        if path == "/api/login" and method == "POST":
            return self.login(start, body)
        if not user:
            return self.send(start, 401, {"error": "authentication required"})
        if parts[:2] == ["api", "accounts"] and len(parts) == 3 and method == "GET":
            return self.account(start, user, parts[2])
        if path == "/api/users/me" and method == "PATCH":
            return self.update_me(start, user, body)
        if path == "/api/transactions" and method == "GET":
            return self.transactions(start, user, qs)
        if parts[:3] == ["api", "admin", "users"] and len(parts) == 4 and method == "DELETE":
            return self.delete_user(start, user, parts[3])
        return self.send(start, 404, {"error": "not found"})

    def send(self, start, code, obj):
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                  413: "Payload Too Large", 429: "Too Many Requests"}[code]
        headers = [("Content-Type", "application/json")]
        if self.vuln:   # API8: any origin may read authenticated responses
            headers += [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
        else:
            headers += [("Access-Control-Allow-Origin", "https://app.bank.example"), ("Vary", "Origin"),
                        ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-store")]
        start(f"{code} {reason}", headers)
        return [json.dumps(obj).encode()]

    # ---- endpoints ----------------------------------------------------------
    def login(self, start, body):
        u = next((x for x in self.users.values() if x["username"] == body.get("username")), None)
        if not self.vuln:  # API2/API4: throttle credential stuffing per account
            q = self.failed[body.get("username", "")]
            while q and q[0] < time.time() - self.WINDOW:
                q.popleft()
            if len(q) >= self.LOGIN_LIMIT:
                return self.send(start, 429, {"error": "too many attempts, try later"})
        if not u or not check_pw(str(body.get("password", "")), u["pw"]):
            if not self.vuln:
                self.failed[body.get("username", "")].append(time.time())
            return self.send(start, 401, {"error": "invalid credentials"})
        claims = {"sub": u["id"], "iat": int(time.time())}
        if not self.vuln:
            claims["exp"] = int(time.time()) + 900
        return self.send(start, 200, {"token": jwt_encode(claims)})

    def account(self, start, user, acct_id):
        if not acct_id.isdigit():
            return self.send(start, 400, {"error": "invalid id"})
        a = self.accounts.get(int(acct_id))
        if self.vuln:
            # API1 BOLA: no ownership check; API3: returns every field, including sensitive ones
            return self.send(start, 200, a) if a else self.send(start, 404, {"error": "not found"})
        if not a or (a["owner"] != user["id"] and user["role"] != "admin"):
            return self.send(start, 404, {"error": "not found"})
        return self.send(start, 200, {k: a[k] for k in ("id", "iban", "balance")})   # explicit allow-list

    def update_me(self, start, user, body):
        if self.vuln:
            user.update(body)            # API3 mass assignment: {"role":"admin"} is accepted
        else:
            allowed = {"email"}
            extra = set(body) - allowed
            if extra:
                return self.send(start, 400, {"error": f"fields not allowed: {sorted(extra)}"})
            if "email" in body:
                user["email"] = str(body["email"])[:254]
        return self.send(start, 200, {k: user[k] for k in ("id", "username", "email", "role")})

    def transactions(self, start, user, qs):
        try:
            limit = int(qs.get("limit", 20))
        except ValueError:
            return self.send(start, 400, {"error": "invalid limit"})
        if not self.vuln:
            limit = max(1, min(limit, self.MAX_PAGE))   # API4: bounded page size
        rows = self.tx.get(user["id"], [])[:limit]
        return self.send(start, 200, {"count": len(rows), "items": rows})

    def delete_user(self, start, user, uid):
        if not self.vuln and user["role"] != "admin":    # API5: function-level authorization
            return self.send(start, 403, {"error": "forbidden"})
        if not uid.isdigit() or int(uid) not in self.users:
            return self.send(start, 404, {"error": "not found"})
        self.users.pop(int(uid))
        return self.send(start, 200, {"deleted": int(uid)})


def main():
    ap = argparse.ArgumentParser(description="API security lab (localhost only)")
    ap.add_argument("--mode", choices=["vulnerable", "secure"], default="secure")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8086)
    a = ap.parse_args()
    if not ipaddress.ip_address(a.host).is_loopback:
        raise SystemExit("Refusing to bind the API lab to a non-loopback address.")
    from wsgiref.simple_server import make_server
    print(f"[!] API lab ({a.mode}) on http://{a.host}:{a.port}  (training only)")
    make_server(a.host, a.port, Api(a.mode)).serve_forever()


if __name__ == "__main__":
    main()
