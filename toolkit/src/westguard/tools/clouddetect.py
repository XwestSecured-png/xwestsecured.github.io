#!/usr/bin/env python3
"""
Run the cloud detection rules over CloudTrail and Entra ID sign-in logs (JSON Lines or
CloudTrail's {"Records": [...]} files) and write an alert report.

    python3 detections/engine.py --cloudtrail data/cloudtrail.jsonl --signin data/entra_signins.jsonl --out reports/
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from datetime import datetime
from pathlib import Path

from .cloud_rules import KNOWN_EGRESS, MAX_KMH, RULES, haversine_km
from .sigma_lite import correlate, get, match_detection, ts

TIME = {"cloudtrail": "eventTime", "signinlogs": "createdDateTime"}


def _read(path: Path) -> list[dict]:
    raw = gzip.open(path, "rt", encoding="utf-8").read() if path.suffix == ".gz" else path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("{") and '"Records"' in stripped[:200]:
        return json.loads(raw)["Records"]                      # native CloudTrail S3 object
    if stripped.startswith("["):
        return json.loads(raw)                                 # JSON array (e.g. Graph / portal export)
    if stripped.startswith("{") and '"value"' in stripped[:200]:
        return json.loads(raw)["value"]                        # Microsoft Graph page
    return [json.loads(l) for l in raw.splitlines() if l.strip()]   # JSON Lines


def load(path: Path | None) -> list[dict]:
    """Load a file or a directory tree of CloudTrail/Entra logs (.json, .jsonl, .json.gz)."""
    if not path:
        return []
    if path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.is_file() and p.name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")))
        return [e for f in files for e in _read(f)]
    return _read(path)


def impossible_travel(events: list[dict]) -> list[dict]:
    hits, last, alerted = [], {}, {}
    ok = sorted((e for e in events if get(e, "status.errorCode") == 0 and get(e, "location.geoCoordinates")
                 and e.get("ipAddress") not in KNOWN_EGRESS), key=lambda e: ts(e, "createdDateTime"))
    for e in ok:
        u = e["userPrincipalName"]
        if u in last:
            p = last[u]
            km = haversine_km(p["location"]["geoCoordinates"], e["location"]["geoCoordinates"])
            hrs = max((ts(e, "createdDateTime") - ts(p, "createdDateTime")).total_seconds() / 3600, 1 / 60)
            recent = u in alerted and (ts(e, "createdDateTime") - alerted[u]).total_seconds() < 86400
            if km > 500 and km / hrs > MAX_KMH and not recent:
                alerted[u] = ts(e, "createdDateTime")
                hits.append({"group": {"userPrincipalName": u}, "count": 2, "first": p["createdDateTime"], "last": e["createdDateTime"],
                             "detail": f"{p['location'].get('city')} → {e['location'].get('city')}: {km:,.0f} km in {hrs:.1f} h "
                                       f"({km / hrs:,.0f} km/h)", "sample": e})
        last[u] = e
    return hits


def run_rule(rule: dict, events: list[dict]) -> list[dict]:
    tf = TIME[rule["logsource"]["service"]]
    if rule["id"] == "CLD-013":
        return impossible_travel(events)
    if "correlation" in rule:
        return correlate(events, rule["detection"], rule["correlation"], tf)
    return [{"group": {}, "count": 1, "first": get(e, tf), "last": get(e, tf), "sample": e}
            for e in events if match_detection(e, rule["detection"])]


def describe(hit: dict, rule: dict) -> str:
    if "detail" in hit:
        return hit["detail"]
    e = hit["sample"]
    if rule["logsource"]["service"] == "cloudtrail":
        who = get(e, "userIdentity.arn") or get(e, "userIdentity.type")
        base = f"{get(e, 'eventName')} by {who} from {get(e, 'sourceIPAddress')} in {get(e, 'awsRegion')}"
    else:
        base = f"{get(e, 'userPrincipalName')} from {get(e, 'ipAddress')} via {get(e, 'clientAppUsed')}"
    if hit["count"] > 1:
        c = rule["correlation"]
        what = f"{hit['count']} events" if c["type"] == "event_count" else f"{hit['count']} distinct {c['field']}"
        base = f"{what} for {', '.join(f'{k}={v}' for k, v in hit['group'].items())} ({hit['first'][11:16]}–{hit['last'][11:16]}); last: {base}"
    return base


def run(cloudtrail: list[dict], signin: list[dict]) -> list[dict]:
    alerts = []
    for r in RULES:
        evs = cloudtrail if r["logsource"]["service"] == "cloudtrail" else signin
        for h in run_rule(r, evs):
            alerts.append({"rule": r["id"], "title": r["title"], "level": r["level"], "attack": r["attack"], "tactic": r["tactic"],
                           "first": h["first"], "last": h["last"], "summary": describe(h, r)})
    return sorted(alerts, key=lambda a: a["first"])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cloudtrail", type=Path, help="CloudTrail file or folder (.json/.jsonl/.json.gz)")
    ap.add_argument("--signin", type=Path, help="Entra ID sign-in export: JSON array, Graph page or JSON Lines")
    ap.add_argument("--out", type=Path, default=Path("reports")); a = ap.parse_args(argv)
    ct, si = load(a.cloudtrail), load(a.signin)
    alerts = run(ct, si)
    print(f"events: cloudtrail={len(ct)} signin={len(si)}  alerts={len(alerts)}")
    for x in alerts:
        print(f"  {x['first'][:19]}  {x['level']:<8} {x['rule']}  {x['title']}\n{'':24}{x['summary']}")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "alerts.json").write_text(json.dumps(alerts, indent=2))
    sev = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}
    md = ["# Cloud Detection Alerts (attack timeline)", "", f"Events analysed: {len(ct):,} CloudTrail, {len(si):,} Entra ID sign-ins. Alerts: {len(alerts)}.", "",
          "| First seen (UTC) | Level | Rule | ATT&CK | What happened |", "|---|---|---|---|---|"]
    md += [f"| {x['first'][:19].replace('T', ' ')} | {sev[x['level']]} {x['level']} | {x['rule']} {x['title']} | {', '.join(x['attack'])} | {x['summary']} |" for x in alerts]
    (a.out / "alerts.md").write_text("\n".join(md) + "\n")
    levels = {x["level"] for x in alerts}
    return 2 if levels & {"critical", "high"} else 1 if alerts else 0


if __name__ == "__main__":
    main()
