#!/usr/bin/env python3
"""
Third-party (vendor) risk scorecard: inherent risk x control strength -> residual risk,
tier, review cadence and specific follow-ups. Aligned to NIST CSF 2.0 GV.SC and SP 800-161r1.

    python3 vendor_risk/vendor_risk.py vendor_risk/vendors.json --as-of 2026-11-21 --out reports/
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

DATA = {"public": 1, "internal": 2, "confidential": 4, "restricted": 5}
ACCESS = {"none": 1, "data_hosted": 3, "network": 4, "privileged_network": 5}
CRIT = {"low": 1, "medium": 2, "high": 3}
# control -> (weight, follow-up if missing)
CONTROLS = {
    "soc2_type2": (3, "Request SOC 2 Type II report (or ISO 27001 certificate) and review exceptions"),
    "iso27001": (1, None),
    "mfa_enforced": (3, "Require MFA on every account with access to our data or systems"),
    "sso_supported": (1, "Ask for SSO/SAML support so access is removed when staff leave"),
    "encryption_at_rest": (2, "Confirm encryption at rest (AES-256 or equivalent) and key management"),
    "encryption_in_transit": (2, "Require TLS 1.2+ for all data in transit"),
    "pentest_annual": (2, "Request latest third-party penetration test summary"),
    "breach_notify_72h": (2, "Add 72-hour breach notification clause to the contract"),
    "sub_processors_disclosed": (1, "Obtain list of sub-processors (fourth parties)"),
    "data_deletion_on_exit": (1, "Add certified data return/deletion at contract end"),
    "bcp_tested": (1, "Request evidence of tested business continuity / DR plan"),
    "vuln_mgmt_sla": (1, "Confirm critical vulnerabilities are patched within a defined SLA"),
}
REVIEW_DAYS = {"Critical": 180, "High": 365, "Moderate": 730, "Low": 1095}


def assess(v: dict, as_of: date) -> dict:
    inherent = DATA[v["data"]] * ACCESS[v["access"]] * CRIT[v["criticality"]]          # 1..75
    inherent_n = round(100 * inherent / 75)
    total = sum(w for w, _ in CONTROLS.values())
    have = sum(w for k, (w, _) in CONTROLS.items() if v["answers"].get(k))
    if v["answers"].get("soc2_type2") is False and v["answers"].get("iso27001"):
        have += CONTROLS["soc2_type2"][0]          # ISO 27001 accepted in place of SOC 2
    control = round(100 * min(have, total) / total)
    residual = round(inherent_n * (1 - 0.7 * control / 100))   # controls reduce at most 70% of risk
    flags = []
    if v["answers"].get("ai_trains_on_customer_data"):
        residual += 15; flags.append("Vendor trains AI models on customer data: require opt-out in contract")
    if v["access"] == "privileged_network" and not v["answers"].get("mfa_enforced"):
        residual += 15; flags.append("Privileged remote access without MFA: top supply-chain attack path")
    tier = "Critical" if residual >= 50 else "High" if residual >= 30 else "Moderate" if residual >= 12 else "Low"
    if inherent_n < 10:                                # trivial-risk vendors never need full review
        tier = "Low"
    follow = [msg for k, (_, msg) in CONTROLS.items() if msg and not v["answers"].get(k)
              and not (k == "soc2_type2" and v["answers"].get("iso27001"))] if tier != "Low" else []
    overdue_days = (as_of - date.fromisoformat(v["last_review"])).days - REVIEW_DAYS[tier]
    return {"name": v["name"], "service": v["service"], "inherent": inherent_n, "control": control, "residual": min(residual, 100),
            "tier": tier, "review_every_days": REVIEW_DAYS[tier], "review_overdue_days": max(0, overdue_days),
            "flags": flags, "follow_ups": follow}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("vendors", type=Path)
    ap.add_argument("--as-of", default=date.today().isoformat()); ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    rows = sorted((assess(v, date.fromisoformat(a.as_of)) for v in json.loads(a.vendors.read_text())["vendors"]),
                  key=lambda r: -r["residual"])
    print(f"{'Vendor':<22}{'Inh':>4}{'Ctl':>5}{'Res':>5}  {'Tier':<9}{'Overdue':>8}")
    for r in rows:
        print(f"{r['name']:<22}{r['inherent']:>4}{r['control']:>4}%{r['residual']:>5}  {r['tier']:<9}{r['review_overdue_days']:>7}d")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "vendor_risk.json").write_text(json.dumps(rows, indent=2))
    L = [f"# Third-Party Risk Register (as of {a.as_of})", "",
         "Residual risk = inherent risk (data sensitivity × access × business criticality) reduced by verified controls, plus penalties for high-impact red flags.", "",
         "| Vendor | Service | Inherent | Controls | Residual | Tier | Review cycle | Overdue |", "|---|---|---|---|---|---|---|---|"]
    L += [f"| {r['name']} | {r['service']} | {r['inherent']} | {r['control']}% | **{r['residual']}** | {r['tier']} | {r['review_every_days']} d | "
          f"{str(r['review_overdue_days']) + ' d' if r['review_overdue_days'] else '—'} |" for r in rows]
    for r in rows:
        if r["flags"] or r["follow_ups"]:
            L += ["", f"## {r['name']} ({r['tier']})", ""] + [f"- 🚩 **{f}**" for f in r["flags"]] + [f"- [ ] {f}" for f in r["follow_ups"]]
    (a.out / "vendor_risk.md").write_text("\n".join(L) + "\n")
    return rows


if __name__ == "__main__":
    main()
