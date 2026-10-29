#!/usr/bin/env python3
"""
Phishing Incident Scoping & Forensic Timeline
=============================================

Answers the questions an incident commander asks after a phish lands:
  1. Who received it?               (message trace)
  2. Who clicked?                   (web proxy / DNS / firewall logs)
  3. Who submitted credentials?     (HTTP POST to phishing infrastructure)
  4. Who opened the attachment?     (EDR file/process events)
  5. Whose account is compromised?  (sign-ins from attacker IPs / new locations, mailbox rules)

It correlates IOCs from phish_analyzer.py (reports/phish_results.json) with those
log sources and produces a single UTC super-timeline plus a per-user impact table
with the required response actions.

    python3 timeline.py --phish reports/phish_results.json --trace logs/message_trace.csv \
        --proxy logs/proxy.csv --signins logs/signins.csv --edr logs/edr_events.csv --out reports/

Maps to: NIST SP 800-61r3 (RS.AN incident analysis, RS.MA), MITRE ATT&CK T1566, T1078.004, T1564.008
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

LEVELS = ["received", "clicked", "opened_attachment", "submitted_credentials", "compromised"]


def rows(p: Path | None) -> list[dict]:
    if not p or not p.exists():
        return []
    with p.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Phishing incident scoping + timeline")
    ap.add_argument("--phish", type=Path, required=True)
    ap.add_argument("--trace", type=Path)
    ap.add_argument("--proxy", type=Path)
    ap.add_argument("--signins", type=Path)
    ap.add_argument("--edr", type=Path)
    ap.add_argument("--known-ips", nargs="*", default=["192.0.2.10"], help="normal egress IPs for the org")
    ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)

    phish = [r for r in json.loads(a.phish.read_text()) if r["verdict"] != "LIKELY BENIGN"]
    mids = {r["message_id"]: r for r in phish}
    hosts = {i["value"].lower() for r in phish for i in r["iocs"] if i["type"] == "domain-name"}
    ips = {i["value"] for r in phish for i in r["iocs"] if i["type"] == "ipv4-addr"}
    hosts |= ips
    att_names = {at["name"].lower() for r in phish for at in r["attachments"]}

    events, impact = [], defaultdict(lambda: {"status": set(), "evidence": []})

    def add(t, source, user, what, level=None, attack=""):
        events.append({"ts": t, "source": source, "user": user, "event": what, "attack": attack})
        if user and level:
            impact[user]["status"].add(level)
            impact[user]["evidence"].append(f"{t} {what}")

    for r in phish:
        if r["date_utc"]:
            add(r["date_utc"], "email", "", f"Phish sent: '{r['subject']}' from {r['from']} (origin {r['origin_ip']})")

    for m in rows(a.trace):
        if m["message_id"] in mids:
            user = m["recipient"].split("@")[0]
            if m["status"].lower() == "delivered":
                add(m["received_utc"], "message trace", user, f"Delivered to {m['recipient']}", "received", "T1566")
            else:
                add(m["received_utc"], "message trace", user, f"{m['status']} for {m['recipient']} (no user exposure)")

    attacker_post_time = {}
    for p in rows(a.proxy):
        host = (urlparse(p["url"]).hostname or "").lower()
        if host in hosts:
            if p["method"].upper() == "POST":
                add(p["ts_utc"], "proxy", p["user"], f"POST (credential submission) to {host} from {p['src_ip']}",
                    "submitted_credentials", "T1566.002 → T1056.003")
                attacker_post_time[p["user"]] = ts(p["ts_utc"])
            else:
                add(p["ts_utc"], "proxy", p["user"], f"Clicked phishing link {host}", "clicked", "T1204.001")

    for e in rows(a.edr):
        d = e["detail"].lower()
        if any(n in d for n in att_names):
            add(e["ts_utc"], f"EDR {e['host']}", e["user"], f"{e['event']}: {e['process']} ← {e['parent'] or '-'} ({Path(e['detail'].split()[-1].strip('\"')).name})",
                "opened_attachment", "T1204.002")
        if e["event"] == "MailboxRule":
            add(e["ts_utc"], "M365 audit", e["user"], f"Suspicious inbox rule created: {e['detail']}", "compromised", "T1564.008")

    pivot_ips = set()
    for s in rows(a.signins):
        u = s["user"]
        new_ip = s["ip"] not in a.known_ips
        after_submit = u in attacker_post_time and ts(s["ts_utc"]) >= attacker_post_time[u]
        if new_ip and (after_submit or s["ip"] in ips or impact[u]["status"] & {"submitted_credentials"}):
            pivot_ips.add(s["ip"])
            if s["result"].lower().startswith("success"):
                add(s["ts_utc"], "Entra sign-in", u, f"SUCCESSFUL sign-in from {s['ip']} ({s['country']}) to {s['app']}",
                    "compromised", "T1078.004")
            else:
                add(s["ts_utc"], "Entra sign-in", u, f"Attacker sign-in attempt from {s['ip']} ({s['country']}): {s['result']}",
                    None, "T1078.004")
                impact[u]["evidence"].append(f"{s['ts_utc']} attacker attempt blocked: {s['result']}")

    events.sort(key=lambda e: e["ts"])
    actions = {
        "compromised": "Disable sign-in, revoke sessions/refresh tokens, reset password, re-register MFA, remove inbox rules, review mailbox audit for data access and onward phishing",
        "submitted_credentials": "Reset password, revoke sessions, confirm MFA blocked attacker, monitor sign-ins 30 days",
        "opened_attachment": "Isolate endpoint, collect triage package, scan, verify no persistence; reset password if form submitted",
        "clicked": "Confirm no submission in proxy/EDR; targeted awareness follow-up",
        "received": "Message purged; no action beyond awareness",
    }
    table = []
    for u, d in impact.items():
        top = max((s for s in d["status"]), key=LEVELS.index, default=None)
        if top:
            table.append({"user": u, "highest_stage": top, "stages": sorted(d["status"], key=LEVELS.index),
                          "action": actions[top], "evidence": d["evidence"]})
    table.sort(key=lambda x: -LEVELS.index(x["highest_stage"]))

    a.out.mkdir(parents=True, exist_ok=True)
    new_iocs = sorted(pivot_ips - ips)
    (a.out / "incident_scope.json").write_text(json.dumps({"timeline": events, "impact": table,
                                                           "new_iocs": new_iocs}, indent=2), encoding="utf-8")
    funnel = {lvl: sum(1 for t in table if lvl in t["stages"]) for lvl in LEVELS}
    md = ["# Phishing Incident: Scope & Timeline", "",
          "## Exposure funnel", "", "| Received | Clicked | Opened attachment | Submitted credentials | Compromised |",
          "|---|---|---|---|---|", "| " + " | ".join(str(funnel[l]) for l in LEVELS) + " |", "",
          "## Impacted users & required actions", "", "| User | Highest stage | Stages | Action |", "|---|---|---|---|"]
    md += [f"| {t['user']} | **{t['highest_stage'].replace('_', ' ')}** | {', '.join(s.replace('_', ' ') for s in t['stages'])} | {t['action']} |" for t in table]
    if new_iocs:
        md += ["", "## New IOCs discovered during scoping", "",
               "Attacker infrastructure not present in the original email (found by pivoting on sign-ins). "
               "Block it, then hunt for it across all users:", ""] + [f"- `{i}` (ipv4-addr)" for i in new_iocs]
    md += ["", "## Super-timeline (UTC)", "", "| Time | Source | User | Event | ATT&CK |", "|---|---|---|---|---|"]
    md += [f"| {e['ts']} | {e['source']} | {e['user'] or '-'} | {e['event']} | {e['attack'] or '-'} |" for e in events]
    (a.out / "incident_timeline.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("[+] Exposure funnel: " + " → ".join(f"{l.replace('_', ' ')} {funnel[l]}" for l in LEVELS))
    for t in table:
        if t["highest_stage"] in ("compromised", "submitted_credentials", "opened_attachment"):
            print(f"    {t['user']:<10} {t['highest_stage']:<22} {t['action'][:90]}")
    if new_iocs:
        print(f"[!] New attacker IOCs from sign-in pivot: {', '.join(new_iocs)}")
    print(f"[+] {len(events)} timeline events -> {a.out}/incident_timeline.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
