#!/usr/bin/env python3
"""
Builds the secure case-management database on a PostgreSQL 13+ server, replays an insider
data-theft scenario through real role logins, verifies every security control, then runs
the forensic investigation and the configuration audit.

    # throwaway local instance (recommended), connection via standard libpq env vars:
    PGHOST=/tmp/pgsock PGPORT=5433 PGUSER=postgres python3 run_lab.py --out reports/

Requires: psql on PATH, a superuser for setup, and local authentication that lets the lab
roles log in (e.g. 'trust' on a disposable instance, or set PGPASSWORD per role).
!! Drops and recreates database "caselab" and the lab roles. Never point it at production. !!

Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SQL = ROOT / "sql"
DB = "caselab"
ROLES = ["alice_cw", "bob_cw", "mallory_cw", "reporting_svc", "audit_reader", "caseworker", "reporting", "auditor",
         "app_owner", "audit_owner"]
ADMIN = os.environ.get("PGUSER", "postgres")


def psql(sql: str, user: str = ADMIN, db: str = DB, check: bool = True, csv_out: bool = False):
    cmd = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db]
    cmd += ["--csv"] if csv_out else ["-tA"]
    p = subprocess.run(cmd + ["-c", sql], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"[{user}] {sql[:80]}…\n{p.stderr}")
    return p


def run_file(path: Path):
    p = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", ADMIN, "-d", DB, "-f", str(path)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{path.name}: {p.stderr}")


def reset():
    psql(f"DROP DATABASE IF EXISTS {DB}", db="postgres")
    for r in ROLES:
        psql(f"DROP ROLE IF EXISTS {r}", db="postgres")
    psql(f"CREATE DATABASE {DB}", db="postgres")


def set_clock(ts: datetime):
    psql(f"TRUNCATE audit.lab_clock; INSERT INTO audit.lab_clock VALUES ('{ts.isoformat()}+00')")


# --------------------------------------------------------------------------- #
# Scenario (all times UTC; Eastern Daylight Time = UTC-4 in late October 2026)
# --------------------------------------------------------------------------- #

def scenario() -> list[tuple[datetime, str, str, str]]:
    site1 = [1001 + i for i in range(150)]
    site2 = [1151 + i for i in range(120)]
    steps = []
    d1 = datetime(2026, 10, 26, 13, 0)               # Mon 09:00 EDT
    steps.append((datetime(2026, 10, 26, 11, 0), "reporting_svc", "SELECT * FROM app.client_demographics()", "monthly demographics report"))
    for i in range(25):
        steps.append((d1 + timedelta(minutes=15 * i), "alice_cw", f"SELECT * FROM app.get_client({site1[i * 5]})", "casework"))
    for i in range(20):
        steps.append((d1 + timedelta(minutes=17 * i + 5), "bob_cw", f"SELECT * FROM app.get_client({site2[i * 4]})", "casework"))
    for i in range(18):
        steps.append((d1 + timedelta(minutes=20 * i + 9), "mallory_cw", f"SELECT * FROM app.get_client({site2[i * 6 + 1]})", "casework"))
    steps.append((d1 + timedelta(hours=3), "bob_cw", "SELECT * FROM app.search_clients('Ng')", "lookup by surname"))
    # ---- incident: Mon 22:05-22:40 EDT (Tue 02:05-02:40 UTC) ------------------
    t = datetime(2026, 10, 27, 2, 5)
    steps += [
        (t, "mallory_cw", "SELECT * FROM app.search_clients('')", "wildcard search attempt"),
        (t + timedelta(minutes=1), "mallory_cw", "SELECT * FROM app.search_clients('A')", "short search attempt"),
        (t + timedelta(minutes=3), "mallory_cw", "SELECT * FROM app.export_site_clients()", "bulk export of site"),
        (t + timedelta(minutes=6), "mallory_cw", "SELECT first_name, last_name, phone FROM app.clients", "direct table read"),
    ]
    for i in range(10):
        steps.append((t + timedelta(minutes=8, seconds=20 * i), "mallory_cw", f"SELECT * FROM app.get_client({site1[i]})",
                      "probe other site"))
    steps += [
        (t + timedelta(minutes=15), "mallory_cw", f"SELECT app.update_client_phone({site2[10]}, '555-0199')", "tamper phone"),
        (t + timedelta(minutes=16), "mallory_cw", f"SELECT app.update_client_phone({site2[11]}, '555-0199')", "tamper phone"),
        (t + timedelta(minutes=17), "mallory_cw", f"SELECT app.update_client_phone({site1[0]}, '555-0199')", "tamper other site"),
        (t + timedelta(minutes=20), "mallory_cw", "GRANT reporting TO mallory_cw", "privilege escalation"),
        (t + timedelta(minutes=25), "mallory_cw", "DELETE FROM audit.event", "cover tracks"),
        (t + timedelta(minutes=35), "mallory_cw", "SELECT * FROM app.get_client(1160)", "final read"),
    ]
    d2 = datetime(2026, 10, 27, 13, 30)
    for i in range(6):
        steps.append((d2 + timedelta(minutes=30 * i), "alice_cw", f"SELECT * FROM app.get_client({site1[i * 7 + 2]})", "casework"))
    return sorted(steps, key=lambda s: s[0])


def simulate(out: Path) -> list[dict]:
    log = []
    for ts, user, sql, label in scenario():
        set_clock(ts)
        p = psql(sql, user=user, check=False)
        err = p.stderr.strip().splitlines()[0] if p.returncode else ""
        log.append({"utc": ts.isoformat(), "user": user, "intent": label, "sql": sql,
                    "result": "ERROR: " + err.replace("ERROR:  ", "") if err else f"ok ({len(p.stdout.splitlines())} rows)"})
    psql("TRUNCATE audit.lab_clock")
    with (out / "simulation_log.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(log[0])); w.writeheader(); w.writerows(log)
    return log


# --------------------------------------------------------------------------- #
# Control verification
# --------------------------------------------------------------------------- #

def verify_controls() -> list[tuple[str, bool, str]]:
    r = []

    def chk(name, user, sql, expect_error=None, expect_out=None):
        p = psql(sql, user=user, check=False)
        if expect_error:
            ok = p.returncode != 0 and re.search(expect_error, p.stderr, re.I) is not None
            detail = (p.stderr.strip().splitlines() or ["(no error)"])[0]
        else:
            ok = p.returncode == 0 and (expect_out is None or expect_out(p.stdout.strip()))
            detail = p.stdout.strip().replace("\n", " | ")[:90] or p.stderr.strip()[:90]
        r.append((name, ok, detail))

    chk("Caseworker cannot SELECT client table directly", "alice_cw", "SELECT * FROM app.clients LIMIT 1", "permission denied")
    chk("RLS: caseworker cannot read a client at another site", "alice_cw", "SELECT count(*) FROM app.get_client(1151)",
        expect_out=lambda o: o == "0")
    chk("RLS: caseworker can read own-site client", "alice_cw", "SELECT count(*) FROM app.get_client(1001)",
        expect_out=lambda o: o == "1")
    chk("Reporting cannot read names/DOB/phone", "reporting_svc", "SELECT last_name FROM app.clients LIMIT 1", "permission denied")
    chk("Reporting can read de-identified columns", "reporting_svc", "SELECT count(*) FROM app.clients",
        expect_out=lambda o: o == "300")
    chk("Reporting demographics apply small-cell suppression", "reporting_svc",
        "SELECT min(clients) >= 5 FROM app.client_demographics()", expect_out=lambda o: o == "t")
    chk("Wildcard / 1-char search returns nothing (and is logged)", "bob_cw", "SELECT count(*) FROM app.search_clients('')",
        expect_out=lambda o: o == "0")
    chk("Audit trail is append-only (DELETE blocked even for auditor)", "audit_reader", "DELETE FROM audit.event", "permission denied")
    chk("Audit trail rejects UPDATE even by its owner role", ADMIN,
        "SET ROLE audit_owner; UPDATE audit.event SET db_user='x' WHERE event_id=1", "append-only")
    chk("Caseworker cannot grant herself extra roles", "mallory_cw", "GRANT reporting TO mallory_cw",
        "permission denied|must have admin option|ADMIN option")
    chk("Caseworker cannot execute audit writer directly", "mallory_cw",
        "SELECT audit.write('READ','x',1,1,NULL)", "permission denied")
    chk("Case notes are ciphertext at rest", ADMIN,
        "SELECT bool_and(encode(notes_enc,'escape') NOT LIKE '%assistance%' AND encode(notes_enc,'escape') NOT LIKE '%intake%') FROM app.clients",
        expect_out=lambda o: o == "t")
    chk("Notes decrypt only with the application key", ADMIN,
        "SELECT pgp_sym_decrypt(notes_enc, 'lab-only-notes-key') IS NOT NULL FROM app.clients LIMIT 1", expect_out=lambda o: o == "t")
    chk("Wrong key cannot decrypt notes", ADMIN,
        "SELECT pgp_sym_decrypt(notes_enc, 'guess') FROM app.clients LIMIT 1", "Wrong key|corrupt")
    chk("PUBLIC has no privileges on app/audit tables", ADMIN,
        "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='PUBLIC' AND table_schema IN ('app','audit')",
        expect_out=lambda o: o == "0")
    chk("Lab passwords stored as SCRAM-SHA-256", ADMIN,
        "SELECT bool_and(rolpassword LIKE 'SCRAM-SHA-256$%') FROM pg_authid WHERE rolname LIKE '%\\_cw'",
        expect_out=lambda o: o == "t")
    return r


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

def run_named(path: Path) -> list[tuple[str, str, list[list[str]]]]:
    out = []
    for block in re.split(r"^-- name:\s*", path.read_text(), flags=re.M)[1:]:
        title, _, body = block.partition("\n")
        why = re.search(r"^-- why:\s*(.+)$", body, re.M)
        q = "\n".join(l for l in body.splitlines() if not l.strip().startswith("--")).strip()
        p = psql(q, csv_out=True)
        rows = list(csv.reader(io.StringIO(p.stdout)))
        out.append((title.strip(), why.group(1) if why else "", rows))
    return out


def md_table(rows, limit=40):
    if not rows:
        return "_no rows_"
    head, body = rows[0], rows[1:]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in body[:limit]:
        lines.append("| " + " | ".join(c.replace("|", "\\|")[:120] for c in r) + " |")
    if len(body) > limit:
        lines.append(f"\n…{len(body) - limit} more rows")
    return "\n".join(lines) if body else "_no rows_"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=True)

    print("[*] Building database (01-06)…")
    reset()
    for f in sorted(SQL.glob("0[1-6]_*.sql")):
        run_file(f); print(f"    ✓ {f.name}")
    print("[*] Replaying scenario through real role logins…")
    log = simulate(a.out)
    print(f"    {len(log)} actions, {sum(l['result'].startswith('ERROR') for l in log)} rejected by the database")
    print("[*] Running forensic investigation (07) and configuration audit (08)…")
    forensic, audit = run_named(SQL / "07_forensic_queries.sql"), run_named(SQL / "08_security_audit_queries.sql")
    print("[*] Verifying security controls (after forensics, so test probes don't enter the evidence)…")
    controls = verify_controls()
    for name, ok, detail in controls:
        print(f"    [{'PASS' if ok else 'FAIL'}] {name}")

    md = ["# Database Security Controls & Breach Forensics: Lab Results", "",
          f"*Generated:* {datetime.now().strftime('%Y-%m-%d %H:%M')} · PostgreSQL {psql('SHOW server_version').stdout.strip()}", "",
          "## Security control verification", "", "| Control | Result | Evidence |", "|---|---|---|"]
    md += [f"| {n} | {'✅ PASS' if ok else '❌ FAIL'} | `{d}` |" for n, ok, d in controls]
    md += ["", "## Attacker actions rejected by the database", "", "| UTC | User | Intent | Result |", "|---|---|---|---|"]
    md += [f"| {l['utc']} | {l['user']} | {l['intent']} | {l['result'][:110]} |" for l in log if l["result"].startswith("ERROR")]
    md += ["", "# Forensic investigation", ""]
    for t, why, rows in forensic:
        md += [f"## {t}", "", f"_{why}_", "", md_table(rows), ""]
    (a.out / "forensics_report.md").write_text("\n".join(md), encoding="utf-8")
    md = ["# PostgreSQL Security Configuration Audit", ""]
    for t, why, rows in audit:
        md += [f"## {t}", "", f"_{why}_", "", md_table(rows), ""]
    (a.out / "security_audit_report.md").write_text("\n".join(md), encoding="utf-8")

    f7 = next(r for t, _, r in forensic if t.startswith("F7"))
    f8 = next(r for t, _, r in forensic if t.startswith("F8"))
    total = [r for r in f7[1:] if r[0] == "TOTAL"]
    print(f"    Breach scope (F7): {total[0][1] if total else '?'} client records exposed by mallory_cw")
    print(f"    Audit chain (F8): {f8[1][-1]} ({f8[1][0]} events)")
    print(f"[+] Reports: {a.out}/forensics_report.md, security_audit_report.md, simulation_log.csv")
    return 0 if all(ok for _, ok, _ in controls) else 1


if __name__ == "__main__":
    sys.exit(main())
