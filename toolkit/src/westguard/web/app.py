"""
WestGuard web dashboard: upload evidence, run a tool, read the report.

Security model
  * Binds to 127.0.0.1 by default. Remote binding needs --allow-remote AND either --tls-cert/--tls-key
    or --behind-proxy (a TLS-terminating reverse proxy you operate).
  * Access token: WESTGUARD_TOKEN env var (>= 24 chars) or a random one printed once at start-up.
    Compared in constant time; 5 failed logins per IP per 5 minutes, then 429.
  * Server-side sessions (random 256-bit IDs, 8 h idle expiry). Cookie: HttpOnly, SameSite=Strict, Secure under TLS.
  * CSRF token on every state-changing form. Strict CSP, no inline script, frame-ancestors 'none'.
  * Uploads capped (default 50 MB), stored per job under the data directory with random job IDs.
    Report files are served only from inside their job folder (path traversal checked) as text/plain,
    except the KPI dashboard HTML, which is served in a CSP sandbox.
  * Every login and job is written to an append-only JSON-lines audit log.

    westguard web [--host 127.0.0.1] [--port 8765] [--data-dir ~/.westguard]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import ssl
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import redirect_stdout
from email.parser import BytesParser
from email.policy import HTTP
from http import cookies
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .. import __version__
from ..cli import COMMANDS, run_tool

log = logging.getLogger("westguard.web")

SESSION_IDLE = 8 * 3600
LOGIN_LIMIT, LOGIN_WINDOW = 5, 300
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

# Tools exposed in the browser: form fields (name, label, kind) and how to build the CLI argv.
WEB_TOOLS = {
    "file-triage": {"fields": [("files", "Suspicious file(s)", "files")],
                    "argv": lambda f, o: [*f["files"], "--out", o] + (["--yara", "default"] if _has("yara") else [])},
    "logs": {"fields": [("linux", "Linux auth.log / secure (optional)", "file"), ("windows", "Windows Security CSV export (optional)", "file")],
             "argv": lambda f, o: sum([["--linux", p] for p in f.get("linux", [])], []) + sum([["--windows", p] for p in f.get("windows", [])], []) + ["--out", o]},
    "cloud-detect": {"fields": [("cloudtrail", "CloudTrail logs (.json/.jsonl/.gz, optional)", "files"), ("signin", "Entra ID sign-in export (optional)", "file")],
                     "argv": lambda f, o: (["--cloudtrail", str(Path(f["cloudtrail"][0]).parent)] if f.get("cloudtrail") else [])
                     + (["--signin", f["signin"][0]] if f.get("signin") else []) + ["--out", o]},
    "vuln": {"fields": [("findings", "Scanner findings CSV", "file"), ("assets", "Asset inventory CSV (optional)", "file"),
                        ("kev", "CISA KEV JSON (optional)", "file"), ("epss", "EPSS CSV (optional)", "file")],
             "argv": lambda f, o: ["--findings", f["findings"][0]] + sum([[f"--{k}", f[k][0]] for k in ("assets", "kev", "epss") if f.get(k)], []) + ["--out", o]},
    "firewall": {"fields": [("ruleset", "Firewall rule set (JSON)", "file")], "argv": lambda f, o: [f["ruleset"][0], "--out", o]},
    "vendor-risk": {"fields": [("vendors", "Vendor questionnaire JSON", "file")], "argv": lambda f, o: [f["vendors"][0], "--out", o]},
    "kpi": {"fields": [("metrics", "Monthly metrics CSV", "file"), ("targets", "Targets JSON", "file")],
            "argv": lambda f, o: [f["metrics"][0], f["targets"][0], "--out", str(Path(o) / "security_kpi_dashboard.html")]},
}
REQUIRED = {"file-triage": ["files"], "vuln": ["findings"], "firewall": ["ruleset"], "vendor-risk": ["vendors"], "kpi": ["metrics", "targets"]}


def _has(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


class ThreadingServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):  # route access log through logging, without query strings
        log.info("%s %s", self.address_string(), fmt % args)


class App:
    def __init__(self, data_dir: Path, token: str, secure_cookies: bool, max_upload_mb: int = 50, trust_proxy: bool = False):
        self.data = data_dir
        (self.data / "jobs").mkdir(parents=True, exist_ok=True)
        os.chmod(self.data, 0o700)
        self.token_hash = hashlib.sha256(token.encode()).digest()
        self.secure = secure_cookies
        self.max_upload = max_upload_mb * 1024 * 1024
        self.trust_proxy = trust_proxy
        self.sessions: dict[str, dict] = {}
        self.failures: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
        self.run_lock = threading.Lock()   # tools redirect stdout; run one at a time

    # ------------------------------------------------------------------ helpers
    def audit(self, event: str, ip: str, **kw):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, "ip": ip, **kw}
        with self.lock, open(self.data / "audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def client_ip(self, env) -> str:
        if self.trust_proxy and env.get("HTTP_X_FORWARDED_FOR"):
            return env["HTTP_X_FORWARDED_FOR"].split(",")[0].strip()
        return env.get("REMOTE_ADDR", "?")

    def session(self, env) -> dict | None:
        c = cookies.SimpleCookie(env.get("HTTP_COOKIE", ""))
        sid = c["wg_session"].value if "wg_session" in c else None
        with self.lock:
            s = self.sessions.get(sid or "")
            if s and time.time() - s["seen"] < SESSION_IDLE:
                s["seen"] = time.time()
                return s
            if sid:
                self.sessions.pop(sid, None)
        return None

    def headers(self, ctype="text/html; charset=utf-8", extra=None, csp=None):
        h = [("Content-Type", ctype), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
             ("Cache-Control", "no-store"), ("X-Frame-Options", "DENY"), ("Cross-Origin-Opener-Policy", "same-origin"),
             ("Content-Security-Policy", csp or "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]
        if self.secure:
            h.append(("Strict-Transport-Security", "max-age=31536000"))
        return h + (extra or [])

    def page(self, start, title, body, status="200 OK", extra=None):
        doc = (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
               f"<title>{html.escape(title)} · WestGuard</title><link rel='stylesheet' href='/static/app.css'></head><body>"
               f"<header><a href='/' class='brand'>WestGuard</a><span class='ver'>v{__version__}</span></header><main>{body}</main></body></html>")
        start(status, self.headers(extra=extra))
        return [doc.encode()]

    def redirect(self, start, to, extra=None):
        start("303 See Other", self.headers(extra=[("Location", to)] + (extra or [])))
        return [b""]

    def read_body(self, env) -> bytes:
        n = int(env.get("CONTENT_LENGTH") or 0)
        if n > self.max_upload:
            raise OverflowError
        return env["wsgi.input"].read(n) if n else b""

    # ------------------------------------------------------------------ routing
    def __call__(self, env, start):
        path, method, ip = env.get("PATH_INFO", "/"), env["REQUEST_METHOD"], self.client_ip(env)
        try:
            if path == "/healthz":
                start("200 OK", self.headers("application/json"))
                return [b'{"status":"ok"}']
            if path == "/static/app.css":
                start("200 OK", self.headers("text/css; charset=utf-8"))
                return [CSS.encode()]
            if path == "/login":
                return self.login(env, start, ip)
            s = self.session(env)
            if not s:
                return self.redirect(start, "/login")
            if path == "/logout" and method == "POST":
                return self.logout(env, start, s, ip)
            if path == "/" and method == "GET":
                return self.home(start, s)
            m = re.fullmatch(r"/run/([a-z-]+)", path)
            if m and m.group(1) in WEB_TOOLS:
                return self.run(env, start, s, ip, m.group(1)) if method == "POST" else self.form(start, s, m.group(1))
            m = re.fullmatch(r"/jobs/([0-9a-f]{32})(?:/(.+))?", path)
            if m and method == "GET":
                return self.job(start, m.group(1), m.group(2))
            return self.page(start, "Not found", "<h1>Not found</h1>", "404 Not Found")
        except OverflowError:
            return self.page(start, "Too large", f"<h1>Upload too large</h1><p>Limit is {self.max_upload // 1048576} MB.</p>", "413 Payload Too Large")
        except Exception:  # noqa: BLE001
            log.exception("unhandled error on %s", path)
            return self.page(start, "Error", "<h1>Something went wrong</h1><p>The error was logged.</p>", "500 Internal Server Error")

    # ------------------------------------------------------------------ auth
    def login(self, env, start, ip):
        if env["REQUEST_METHOD"] == "GET":
            return self.page(start, "Sign in", LOGIN_FORM.format(msg=""))
        now = time.time()
        with self.lock:
            q = self.failures[ip]
            while q and q[0] < now - LOGIN_WINDOW:
                q.popleft()
            limited = len(q) >= LOGIN_LIMIT
        if limited:
            self.audit("login_rate_limited", ip)
            return self.page(start, "Sign in", LOGIN_FORM.format(msg="<p class='err'>Too many attempts. Try again in a few minutes.</p>"), "429 Too Many Requests")
        form = parse_qs(self.read_body(env).decode("utf-8", "replace"))
        given = form.get("token", [""])[0]
        if not hmac.compare_digest(hashlib.sha256(given.encode()).digest(), self.token_hash):
            with self.lock:
                self.failures[ip].append(now)
            self.audit("login_failed", ip)
            return self.page(start, "Sign in", LOGIN_FORM.format(msg="<p class='err'>Invalid token.</p>"), "401 Unauthorized")
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[sid] = {"seen": now, "csrf": secrets.token_urlsafe(32), "jobs": []}
        self.audit("login_ok", ip)
        cookie = f"wg_session={sid}; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if self.secure else "")
        return self.redirect(start, "/", [("Set-Cookie", cookie)])

    def logout(self, env, start, s, ip):
        form = parse_qs(self.read_body(env).decode())
        if not hmac.compare_digest(form.get("csrf", [""])[0], s["csrf"]):
            return self.page(start, "Forbidden", "<h1>Invalid form token</h1>", "403 Forbidden")
        with self.lock:
            for k, v in list(self.sessions.items()):
                if v is s:
                    self.sessions.pop(k)
        self.audit("logout", ip)
        return self.redirect(start, "/login", [("Set-Cookie", "wg_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")])

    # ------------------------------------------------------------------ pages
    def home(self, start, s):
        cards = "".join(f"<a class='card' href='/run/{t}'><h3>{html.escape(t)}</h3><p>{html.escape(COMMANDS[t][2])}</p></a>" for t in WEB_TOOLS)
        jobs = "".join(f"<li><a href='/jobs/{j['id']}'>{html.escape(j['tool'])}</a> · {j['when']} · exit {j['code']}</li>" for j in reversed(s["jobs"][-20:]))
        body = (f"<h1>Run a tool</h1><div class='grid'>{cards}</div><h2>Your recent jobs</h2><ul>{jobs or '<li>None yet</li>'}</ul>"
                f"<form method='post' action='/logout'><input type='hidden' name='csrf' value='{s['csrf']}'><button class='link'>Sign out</button></form>"
                "<p class='muted'>Other commands (network, endpoint, cloud-audit, secrets, sbom, deps, intel) run from the CLI: <code>westguard list</code></p>")
        return self.page(start, "Home", body)

    def form(self, start, s, tool):
        fields = "".join(f"<label>{html.escape(label)}<input type='file' name='{n}'{' multiple' if kind == 'files' else ''}"
                         f"{' required' if n in REQUIRED.get(tool, []) else ''}></label>" for n, label, kind in WEB_TOOLS[tool]["fields"])
        body = (f"<h1>{html.escape(tool)}</h1><p>{html.escape(COMMANDS[tool][2])}</p>"
                f"<form method='post' enctype='multipart/form-data'><input type='hidden' name='csrf' value='{s['csrf']}'>{fields}"
                f"<button>Run</button></form><p class='muted'>Files are analysed read-only and never executed. Max upload {self.max_upload // 1048576} MB.</p>")
        return self.page(start, tool, body)

    def run(self, env, start, s, ip, tool):
        ctype = env.get("CONTENT_TYPE", "")
        if not ctype.startswith("multipart/form-data"):
            return self.page(start, "Bad request", "<h1>Expected a file upload</h1>", "400 Bad Request")
        raw = self.read_body(env)
        msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + raw)
        fields: dict[str, list] = defaultdict(list)
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            fields[name].append((part.get_filename(), part.get_payload(decode=True) or b""))
        csrf = fields.get("csrf", [(None, b"")])[0][1].decode()
        if not hmac.compare_digest(csrf, s["csrf"]):
            self.audit("csrf_rejected", ip, tool=tool)
            return self.page(start, "Forbidden", "<h1>Invalid form token</h1>", "403 Forbidden")
        job_id = uuid.uuid4().hex
        jdir = self.data / "jobs" / job_id
        (jdir / "in").mkdir(parents=True); (jdir / "out").mkdir()
        saved, hashes = defaultdict(list), {}
        for name, _, _ in WEB_TOOLS[tool]["fields"]:
            sub = jdir / "in" / name
            for i, (fname, data) in enumerate(fields.get(name, [])):
                if not fname or not data:
                    continue
                sub.mkdir(exist_ok=True)
                safe = SAFE_NAME.sub("_", Path(fname).name)[:100] or f"upload{i}"
                p = sub / safe
                if p.exists():
                    p = sub / f"{i}_{safe}"
                p.write_bytes(data); os.chmod(p, 0o600)
                saved[name].append(str(p)); hashes[safe] = hashlib.sha256(data).hexdigest()
        missing = [n for n in REQUIRED.get(tool, []) if not saved.get(n)]
        if missing or not saved:
            shutil.rmtree(jdir)
            return self.page(start, "Missing input", f"<h1>Missing input</h1><p>Please upload: {html.escape(', '.join(missing) or 'at least one file')}</p>", "400 Bad Request")
        argv = WEB_TOOLS[tool]["argv"](saved, str(jdir / "out"))
        buf = io.StringIO()
        with self.run_lock, redirect_stdout(buf):
            code = run_tool(tool, argv)
        (jdir / "out" / "console.txt").write_text(buf.getvalue(), encoding="utf-8")
        meta = {"id": job_id, "tool": tool, "code": code, "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "inputs": hashes}
        (jdir / "job.json").write_text(json.dumps(meta, indent=2))
        s["jobs"].append(meta)
        self.audit("job_run", ip, tool=tool, job=job_id, exit=code, inputs=hashes)
        return self.redirect(start, f"/jobs/{job_id}")

    def job(self, start, job_id, fname):
        jdir = (self.data / "jobs" / job_id).resolve()
        if not JOB_ID.match(job_id) or not (jdir / "job.json").exists():
            return self.page(start, "Not found", "<h1>Not found</h1>", "404 Not Found")
        out = jdir / "out"
        if fname:
            target = (out / fname).resolve()
            if out not in target.parents or not target.is_file():
                return self.page(start, "Not found", "<h1>Not found</h1>", "404 Not Found")
            data = target.read_bytes()
            if target.suffix == ".html":   # KPI dashboard: render, but sandboxed (no same-origin, no forms)
                start("200 OK", self.headers("text/html; charset=utf-8", csp="sandbox allow-scripts; default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"))
            else:
                start("200 OK", self.headers("text/plain; charset=utf-8", extra=[("Content-Disposition", f"inline; filename=\"{target.name}\"")]))
            return [data]
        meta = json.loads((jdir / "job.json").read_text())
        files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
        report = next((out / f for f in files if f.endswith(".md")), None)
        console = (out / "console.txt").read_text(encoding="utf-8") if (out / "console.txt").exists() else ""
        status = {0: "Completed: nothing above threshold", 1: "Completed: findings", 2: "Completed: critical findings"}.get(meta["code"], "Failed: see console output")
        body = (f"<h1>{html.escape(meta['tool'])}</h1><p class='status s{meta['code']}'>{status} (exit {meta['code']})</p>"
                f"<p class='muted'>Job {job_id} · {meta['when']}</p><h2>Files</h2><ul>"
                + "".join(f"<li><a href='/jobs/{job_id}/{html.escape(f)}'>{html.escape(f)}</a></li>" for f in files) + "</ul>"
                + (f"<h2>Report</h2><pre>{html.escape(report.read_text(encoding='utf-8')[:200_000])}</pre>" if report else "")
                + f"<h2>Console</h2><pre>{html.escape(console[-50_000:])}</pre>")
        return self.page(start, meta["tool"], body)


LOGIN_FORM = ("<h1>Sign in</h1>{msg}<form method='post' action='/login'><label>Access token"
              "<input type='password' name='token' autocomplete='current-password' required autofocus></label><button>Sign in</button></form>")

CSS = """
:root{--bg:#f6f6f4;--surface:#fff;--ink:#141413;--ink2:#55544f;--rule:#e2e1dc;--accent:#1f5fbf;--bad:#b42323;--warn:#9a6700;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--surface:#1b1b1a;--ink:#efeee9;--ink2:#b5b4ad;--rule:#2f2f2c;--accent:#6ea8ff;--bad:#ff8080;--warn:#e3b341;--ok:#56d364}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{display:flex;gap:10px;align-items:baseline;padding:14px 20px;border-bottom:1px solid var(--rule);background:var(--surface)}
.brand{font-weight:700;color:var(--ink);text-decoration:none;font-size:18px}.ver,.muted{color:var(--ink2);font-size:13px}
main{max-width:1000px;margin:0 auto;padding:24px 16px 60px}a{color:var(--accent)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.card{display:block;background:var(--surface);border:1px solid var(--rule);border-radius:10px;padding:14px;text-decoration:none;color:var(--ink)}
.card h3{margin:0 0 6px;font-size:15px;color:var(--accent)}.card p{margin:0;font-size:13px;color:var(--ink2)}
form{display:flex;flex-direction:column;gap:12px;max-width:520px}label{display:flex;flex-direction:column;gap:4px;font-weight:600;font-size:14px}
input{font:inherit;padding:8px;border:1px solid var(--rule);border-radius:8px;background:var(--surface);color:var(--ink)}
button{font:inherit;font-weight:600;padding:9px 16px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;align-self:flex-start}
button.link{background:none;color:var(--accent);padding:0}
pre{background:var(--surface);border:1px solid var(--rule);border-radius:8px;padding:12px;overflow-x:auto;font-size:12.5px;white-space:pre-wrap}
.err{color:var(--bad)}.status{font-weight:600}.s0{color:var(--ok)}.s1{color:var(--warn)}.s2,.s64,.s70{color:var(--bad)}
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="westguard web", description="WestGuard dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data-dir", type=Path, default=Path(os.environ.get("WESTGUARD_DATA_DIR", Path.home() / ".westguard")))
    ap.add_argument("--max-upload-mb", type=int, default=50)
    ap.add_argument("--allow-remote", action="store_true", help="permit binding to a non-loopback address")
    ap.add_argument("--tls-cert", type=Path); ap.add_argument("--tls-key", type=Path)
    ap.add_argument("--behind-proxy", action="store_true", help="a TLS reverse proxy fronts this server (trusts X-Forwarded-For, sets Secure cookies)")
    a = ap.parse_args(argv)

    loopback = ipaddress.ip_address(a.host if a.host != "localhost" else "127.0.0.1").is_loopback
    tls = bool(a.tls_cert and a.tls_key)
    if not loopback and not a.allow_remote:
        raise SystemExit("Refusing to bind to a non-loopback address without --allow-remote.")
    if not loopback and not (tls or a.behind_proxy):
        raise SystemExit("Remote access requires TLS: pass --tls-cert/--tls-key, or --behind-proxy with a TLS reverse proxy.")
    token = os.environ.get("WESTGUARD_TOKEN", "")
    if token and len(token) < 24:
        raise SystemExit("WESTGUARD_TOKEN must be at least 24 characters.")
    generated = not token
    token = token or secrets.token_urlsafe(24)

    app = App(a.data_dir.expanduser(), token, secure_cookies=tls or a.behind_proxy, max_upload_mb=a.max_upload_mb, trust_proxy=a.behind_proxy)
    srv = make_server(a.host, a.port, app, server_class=ThreadingServer, handler_class=QuietHandler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    scheme = "https" if tls else "http"
    print(f"WestGuard dashboard on {scheme}://{a.host}:{a.port}  (data: {app.data})", file=sys.stderr)
    if generated:
        print(f"Access token (shown once; set WESTGUARD_TOKEN to choose your own): {token}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
