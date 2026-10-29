#!/usr/bin/env python3
"""
Vendor-Neutral Firewall Rule Auditor
====================================

Audits a firewall policy expressed in a simple, vendor-neutral JSON schema
(see sample_ruleset.json) for the misconfigurations auditors and attackers
look for first. Rules for most platforms can be exported/converted to this
schema (pfSense/OPNsense XML, FortiGate, Palo Alto, Cisco ASA, AWS Security
Groups, Azure NSGs, iptables/nftables) — see README for mapping notes.

Checks
  FW-001  Any/any/any allow rule
  FW-002  Internet-exposed administrative / database ports
  FW-003  Overly permissive rule (any source + any port, or huge port ranges)
  FW-004  Shadowed / redundant rules (never match) and conflicting shadows
  FW-005  No explicit default-deny
  FW-006  Allow rule without logging
  FW-007  Missing owner / business justification
  FW-008  Expired temporary rule still present
  FW-009  Cleartext / legacy protocols allowed
  FW-010  Unrestricted egress (no outbound filtering)

    python3 firewall/firewall_audit.py firewall/sample_ruleset.json --as-of 2026-10-29

Aligned with: CIS Controls v8.1 (4.4, 4.5, 12.2, 13.4), NIST SP 800-41 Rev. 1,
PCI DSS v4.0.1 Req. 1, NIST SP 800-207 (Zero Trust).
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import date
from pathlib import Path

ADMIN_PORTS = {22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP",
               5985: "WinRM", 5986: "WinRM", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL",
               5432: "PostgreSQL", 1521: "Oracle", 6379: "Redis", 9200: "Elasticsearch",
               27017: "MongoDB", 161: "SNMP", 389: "LDAP", 636: "LDAPS", 2375: "Docker API",
               6443: "Kubernetes API", 10250: "Kubelet"}
CLEARTEXT = {21: "FTP", 23: "Telnet", 69: "TFTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
             161: "SNMPv1/v2c", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "rsh/syslog"}
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
INTERNET = ("any", "0.0.0.0/0", "::/0", "internet")


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def nets(values) -> list | None:
    """None means 'any'."""
    vals = [values] if isinstance(values, str) else list(values or ["any"])
    if any(str(v).lower() in INTERNET for v in vals):
        return None
    return [ipaddress.ip_network(v, strict=False) for v in vals]


def ports(values) -> list | None:
    vals = [values] if isinstance(values, (str, int)) else list(values or ["any"])
    if any(str(v).lower() == "any" for v in vals):
        return None
    out = []
    for v in vals:
        s = str(v)
        if "-" in s:
            a, b = s.split("-")
            out.append((int(a), int(b)))
        else:
            out.append((int(s), int(s)))
    return out


def covers_nets(outer, inner) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return all(any(i.version == o.version and i.subnet_of(o) for o in outer) for i in inner)


def covers_ports(outer, inner) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return all(any(o[0] <= i[0] and i[1] <= o[1] for o in outer) for i in inner)


def port_hits(pr, table) -> list[str]:
    if pr is None:
        return ["ALL PORTS"]
    return [f"{p}/{name}" for p, name in table.items() if any(a <= p <= b for a, b in pr)]


def span(pr) -> int:
    return 65535 if pr is None else sum(b - a + 1 for a, b in pr)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def audit(policy: dict, today: date) -> list[dict]:
    findings = []

    def add(rule, check, sev, title, detail, fix):
        findings.append({"rule_id": rule.get("id") if rule else "-", "rule_name": rule.get("name", "") if rule else "",
                         "check": check, "severity": sev, "title": title, "detail": detail, "fix": fix})

    rules = policy.get("rules", [])
    norm = []
    for r in rules:
        n = dict(r)
        n["_src"], n["_dst"] = nets(r.get("src")), nets(r.get("dst"))
        n["_ports"] = ports(r.get("ports"))
        n["_proto"] = str(r.get("protocol", "any")).lower()
        n["_dir"] = r.get("direction", "inbound").lower()
        n["_allow"] = r.get("action", "deny").lower() in ("allow", "permit", "accept", "pass")
        n["_enabled"] = r.get("enabled", True)
        norm.append(n)

    active = [r for r in norm if r["_enabled"]]
    for r in active:
        if not r["_allow"]:
            continue
        inbound_from_internet = r["_dir"] == "inbound" and r["_src"] is None

        # FW-001
        if r["_src"] is None and r["_dst"] is None and r["_ports"] is None and r["_proto"] == "any":
            add(r, "FW-001", "critical", "Any/any/any allow rule",
                f"{r['_dir']} allow with no restriction on source, destination, port or protocol",
                "Delete or replace with specific source/destination/port rules (least privilege).")
        # FW-002
        if inbound_from_internet:
            hits = port_hits(r["_ports"], ADMIN_PORTS)
            if hits:
                add(r, "FW-002", "critical", "Admin/database service exposed to the internet",
                    f"inbound from ANY to {r.get('dst')} on {', '.join(hits[:8])}",
                    "Restrict to VPN/ZTNA/bastion source ranges with MFA; never expose RDP/SMB/DB ports publicly.")
        # FW-003
        if (r["_src"] is None and r["_ports"] is None) or span(r["_ports"]) > 1000:
            if not (r["_src"] is None and r["_dst"] is None and r["_ports"] is None and r["_proto"] == "any"):
                add(r, "FW-003", "high", "Overly permissive rule",
                    f"src={r.get('src')} ports={r.get('ports')} ({span(r['_ports'])} ports)",
                    "Narrow to the specific ports/sources the application requires.")
        # FW-006
        if not r.get("log", False):
            add(r, "FW-006", "medium" if inbound_from_internet else "low", "Allow rule without logging",
                "log=false", "Enable logging on allow rules (at least session start) and forward to SIEM.")
        # FW-009
        if r["_ports"] is not None and span(r["_ports"]) <= 1000:   # broad ranges already FW-003
            clear = port_hits(r["_ports"], CLEARTEXT)
            if clear and not (r["_dir"] == "inbound" and clear == ["80/HTTP"] and r.get("redirect_to_https")):
                add(r, "FW-009", "medium", "Cleartext / legacy protocol allowed",
                    ", ".join(clear), "Migrate to encrypted equivalents (SSH/SFTP, HTTPS, LDAPS, SNMPv3, IMAPS).")
        # FW-010
        if r["_dir"] == "outbound" and r["_dst"] is None and r["_ports"] is None:
            add(r, "FW-010", "high", "Unrestricted egress",
                f"outbound from {r.get('src')} to ANY on ANY port",
                "Implement egress filtering: allow only required ports (e.g. 443, 53 to internal resolvers) "
                "and route web traffic through a proxy/SWG. Limits C2 and exfiltration.")

    for r in norm:
        # FW-007
        if not r.get("owner") or not r.get("description"):
            add(r, "FW-007", "low", "Missing owner or business justification",
                f"owner={r.get('owner')!r} description={r.get('description')!r}",
                "Every rule needs an owner, ticket/justification and review date (PCI DSS 1.2, CIS 4.4).")
        # FW-008
        if r.get("expires"):
            try:
                exp = date.fromisoformat(r["expires"])
                if exp < today:
                    add(r, "FW-008", "high" if r["_allow"] and r["_enabled"] else "low",
                        "Expired temporary rule still present",
                        f"expired {r['expires']} ({(today - exp).days} days ago)",
                        "Remove the rule or re-approve with a new expiry.")
            except ValueError:
                pass

    # FW-004: shadowing — a later rule fully covered by an earlier enabled rule
    for j, later in enumerate(active):
        for earlier in active[:j]:
            if earlier["_dir"] != later["_dir"]:
                continue
            if earlier["_proto"] not in ("any", later["_proto"]):
                continue
            if (covers_nets(earlier["_src"], later["_src"]) and covers_nets(earlier["_dst"], later["_dst"])
                    and covers_ports(earlier["_ports"], later["_ports"])):
                conflict = earlier["_allow"] != later["_allow"]
                add(later, "FW-004", "high" if conflict else "low",
                    "Conflicting shadowed rule" if conflict else "Redundant shadowed rule",
                    f"never matches; fully covered by earlier rule {earlier.get('id')} "
                    f"({earlier.get('name')}, action={earlier.get('action')})",
                    "Reorder (specific before general) or remove. Conflicts mean the intended "
                    + ("deny is NOT enforced." if not later["_allow"] else "allow never applies."))
                break

    # FW-005
    default = str(policy.get("default_action", "")).lower()
    last = active[-1] if active else None
    explicit_last_deny = (last is not None and not last["_allow"] and last["_src"] is None
                          and last["_dst"] is None and last["_ports"] is None)
    if default not in ("deny", "drop", "reject") and not explicit_last_deny:
        add(None, "FW-005", "critical", "No default-deny",
            f"default_action={policy.get('default_action')!r} and no final deny-all rule",
            "Set implicit/explicit deny-all at the end of every rule set (inbound and outbound).")

    findings.sort(key=lambda f: (SEV[f["severity"]], str(f["rule_id"])))
    return findings


def to_markdown(policy, findings, today) -> str:
    from collections import Counter
    c = Counter(f["severity"] for f in findings)
    md = [f"# Firewall Audit: {policy.get('name', 'policy')}", "",
          f"*As of:* {today} · *Rules:* {len(policy.get('rules', []))} · *Findings:* {len(findings)} "
          f"(critical {c['critical']}, high {c['high']}, medium {c['medium']}, low {c['low']})", "",
          "| Sev | Check | Rule | Title | Detail | Fix |", "|---|---|---|---|---|---|"]
    for f in findings:
        md.append(f"| **{f['severity'].upper()}** | {f['check']} | {f['rule_id']} {f['rule_name']} | "
                  f"{f['title']} | {f['detail']} | {f['fix']} |")
    return "\n".join(md) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Vendor-neutral firewall rule audit")
    ap.add_argument("ruleset")
    ap.add_argument("--as-of", help="YYYY-MM-DD (default: today)")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.as_of) if a.as_of else date.today()
    policy = json.loads(Path(a.ruleset).read_text(encoding="utf-8"))
    findings = audit(policy, today)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "firewall_audit.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    (out / "firewall_audit.md").write_text(to_markdown(policy, findings, today), encoding="utf-8")
    print(f"[+] {len(policy.get('rules', []))} rules audited, {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity'].upper():8}] {f['check']} rule {f['rule_id']}: {f['title']} -> {f['detail']}")
    return 2 if any(f["severity"] == "critical" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
