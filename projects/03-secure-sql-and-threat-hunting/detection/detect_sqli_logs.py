#!/usr/bin/env python3
"""
SQL-injection detector for web server access logs (Apache/Nginx "combined" format,
IIS W3C, or one-URI-per-line). URL-decodes repeatedly to defeat simple encoding
evasion, normalizes SQL comments, scores each request against weighted signatures,
and aggregates by source IP.

    python3 detection/detect_sqli_logs.py detection/sample_access.log
    python3 detection/detect_sqli_logs.py /var/log/nginx/access.log --min-score 5 --json out.json

Mapped to: OWASP Top 10:2025 A05 Injection · CWE-89 · MITRE ATT&CK T1190
Read-only. Author: Xiome West | License: MIT
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from urllib.parse import unquote_plus

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "[^"]*" "(?P<ua>[^"]*)")?')
IIS = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\S+) \S+ (?P<method>[A-Z]+) (?P<stem>\S+) (?P<query>\S+) '
                 r'\S+ \S+ (?P<ip>\S+) (?P<ua>\S+) .*? (?P<status>\d{3}) ')

# (name, weight, regex). Weights tuned so a single quote alone is not an alert.
SIGNATURES = [
    ("union_select",     5, r"union(\s+all)?\s+select"),
    ("tautology",        4, r"['\"]?\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+"),
    ("comment_terminator", 2, r"(--|#|/\*)\s*$|'\s*(--|#)"),
    ("time_based",       5, r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()"),
    ("stacked_query",    4, r";\s*(drop|insert|update|delete|exec|declare|shutdown)\b"),
    ("info_schema",      5, r"information_schema|sys\.(tables|objects)|sqlite_master|pg_catalog"),
    ("version_probe",    4, r"@@version|version\s*\(\)|sqlite_version\s*\("),
    ("error_based",      4, r"(convert|cast)\s*\(.*select|extractvalue\s*\(|updatexml\s*\("),
    ("quote_break",      1, r"'"),
    ("hex_or_char_obf",  2, r"0x[0-9a-f]{6,}|char\s*\(\s*\d+"),
]
SIG_RE = [(n, w, re.compile(p, re.I)) for n, w, p in SIGNATURES]
TOOLS = re.compile(r"sqlmap|havij|nikto|nuclei|ghauri", re.I)


def normalize(uri: str) -> str:
    prev, cur = None, uri
    for _ in range(3):                      # handle double/triple encoding
        if cur == prev:
            break
        prev, cur = cur, unquote_plus(cur)
    cur = re.sub(r"/\*.*?\*/", " ", cur)    # strip inline comments used as whitespace
    return re.sub(r"\s+", " ", cur)


def score(uri: str):
    u = normalize(uri)
    hits = [(n, w) for n, w, r in SIG_RE if r.search(u)]
    return sum(w for _, w in hits), [n for n, _ in hits], u


def parse(line: str):
    if m := COMBINED.match(line):
        return m["ip"], m["ts"], m["uri"], int(m["status"]), m["ua"] or ""
    if m := IIS.match(line):
        uri = m["stem"] + ("" if m["query"] == "-" else "?" + m["query"])
        return m["ip"], f'{m["date"]} {m["time"]}', uri, int(m["status"]), m["ua"].replace("+", " ")
    s = line.strip()
    return ("-", "-", s, 0, "") if s.startswith("/") else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--min-score", type=int, default=5)
    ap.add_argument("--json")
    a = ap.parse_args(argv)

    alerts, by_ip = [], defaultdict(lambda: {"hits": 0, "max": 0, "sigs": set(), "first": None,
                                             "last": None, "errors": 0, "tools": set()})
    total = 0
    for path in a.logs:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not (p := parse(line)):
                    continue
                total += 1
                ip, ts, uri, status, ua = p
                sc, sigs, norm = score(uri)
                tool = TOOLS.search(ua)
                if tool:
                    sc += 3; sigs.append(f"tool:{tool.group(0).lower()}")
                if sc >= a.min_score:
                    alerts.append({"src_ip": ip, "ts": ts, "status": status, "score": sc,
                                   "signatures": sigs, "uri": norm[:200]})
                    d = by_ip[ip]
                    d["hits"] += 1; d["max"] = max(d["max"], sc); d["sigs"].update(sigs)
                    d["first"] = d["first"] or ts; d["last"] = ts
                    d["errors"] += status >= 500
                    if tool: d["tools"].add(tool.group(0).lower())

    print(f"[+] {total} requests analyzed, {len(alerts)} SQLi alerts from {len(by_ip)} source(s)\n")
    for ip, d in sorted(by_ip.items(), key=lambda kv: -kv[1]["hits"]):
        sev = "HIGH" if d["max"] >= 9 or d["errors"] else "MEDIUM"
        print(f"  [{sev}] {ip}: {d['hits']} requests, max score {d['max']}, 5xx={d['errors']}, "
              f"tools={','.join(sorted(d['tools'])) or '-'}\n         {d['first']} -> {d['last']}"
              f"\n         signatures: {', '.join(sorted(d['sigs']))}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"total_requests": total, "alerts": alerts,
                       "sources": {k: {**v, "sigs": sorted(v["sigs"]), "tools": sorted(v["tools"])}
                                   for k, v in by_ip.items()}}, fh, indent=2)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
