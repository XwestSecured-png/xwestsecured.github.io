#!/usr/bin/env python3
"""
Incident Response Log Triage Toolkit
====================================

Parses authentication logs from Linux (OpenSSH / sudo via syslog or journald
text export) and Windows (Security event log exported to CSV), runs a set of
detections mapped to MITRE ATT&CK, and produces an analyst-ready JSON + Markdown
report aligned to NIST SP 800-61 Rev. 3 / NIST CSF 2.0 (Detect -> Respond).

Design goals
  * Standard library only -> runs on any analyst workstation or jump box.
  * Read-only: never modifies the evidence it is pointed at.
  * Environment-neutral: thresholds, internal networks, business hours and
    service accounts live in a JSON config, not in code.

Usage
  python3 triage.py --linux sample_logs/auth.log \
                    --windows sample_logs/windows_security.csv \
                    --config config.json --out reports/

Author: Xiome West
License: MIT
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class AuthEvent:
    timestamp: datetime
    source: str            # "linux" | "windows"
    host: str
    event: str             # normalized: login_failure, login_success, priv_use,
                           # account_created, group_add, log_cleared
    user: str = ""
    src_ip: str = ""
    detail: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str          # low | medium | high | critical
    attack: list[str]      # MITRE ATT&CK technique IDs
    first_seen: str
    last_seen: str
    entities: dict
    evidence_count: int
    recommendation: str
    evidence: list[str] = field(default_factory=list)


DEFAULT_CONFIG = {
    "year": None,                        # syslog lines have no year; None = current UTC year
    "brute_force_threshold": 10,         # failures from one IP ...
    "brute_force_window_minutes": 10,    # ... inside this window
    "spray_user_threshold": 5,           # distinct users targeted by one IP
    "spray_window_minutes": 30,
    "success_after_failure_minutes": 30,
    "business_hours": {"start": 7, "end": 19, "weekdays_only": True,
                       "utc_offset_hours": 0},
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "service_accounts": [],              # excluded from off-hours alerting
    "privileged_groups": ["Administrators", "Domain Admins", "Enterprise Admins",
                          "sudo", "wheel"],
    "max_evidence_lines": 5,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

# Classic syslog:  "Oct 27 02:14:01 web01 sshd[1234]: ..."
SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)
# RFC 3339 (rsyslog high-precision / journalctl -o short-iso)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s"
    r"(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)
SSH_FAIL = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d\.a-fA-F:]+)"
)
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.a-fA-F:]+)")
SSH_OK = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>[\d\.a-fA-F:]+)"
)
SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUPADD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")


def _parse_ts_syslog(m: re.Match, year: int) -> datetime:
    ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    return ts.replace(tzinfo=timezone.utc)


def parse_linux(path: Path, cfg: dict) -> list[AuthEvent]:
    year = cfg.get("year") or datetime.now(timezone.utc).year
    events: list[AuthEvent] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = ISO_RE.match(line)
            if m:
                ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            else:
                m = SYSLOG_RE.match(line)
                if not m:
                    continue
                ts = _parse_ts_syslog(m, year)
            host, proc, msg = m["host"], m["proc"], m["msg"]

            if proc.startswith("sshd"):
                if (s := SSH_FAIL.search(msg)) or (s := SSH_INVALID.search(msg)):
                    # "Invalid user" and "Failed password ... invalid user" are the
                    # same attempt; only count the "Failed" line to avoid doubles.
                    if msg.startswith("Invalid user"):
                        continue
                    events.append(AuthEvent(ts, "linux", host, "login_failure",
                                            s["user"], s["ip"], line))
                elif s := SSH_OK.search(msg):
                    events.append(AuthEvent(ts, "linux", host, "login_success",
                                            s["user"], s["ip"], line))
            elif proc == "sudo" and (s := SUDO.search(msg)):
                events.append(AuthEvent(ts, "linux", host, "priv_use",
                                        s["user"], "", line))
            elif proc == "useradd" and (s := USERADD.search(msg)):
                events.append(AuthEvent(ts, "linux", host, "account_created",
                                        s["user"], "", line))
            elif proc in ("usermod", "gpasswd") and (s := GROUPADD.search(msg)):
                events.append(AuthEvent(ts, "linux", host, "group_add",
                                        s["user"], "", f"group={s['group']} | {line}"))
    return events


# Windows Security Event IDs -> normalized event
WIN_EVENT_MAP = {
    "4625": "login_failure",
    "4624": "login_success",
    "4672": "priv_use",        # special privileges assigned to new logon
    "4720": "account_created",
    "4728": "group_add",       # member added to security-enabled global group
    "4732": "group_add",       # ... local group
    "4756": "group_add",       # ... universal group
    "1102": "log_cleared",     # audit log cleared
}


def parse_windows(path: Path, cfg: dict) -> list[AuthEvent]:
    """
    Expects a CSV with at least: TimeCreated, Computer, EventID and the
    usual fields from Get-WinEvent / Event Viewer export:
    TargetUserName, IpAddress, LogonType, GroupName (optional).
    See export_windows_events.ps1 for a matching exporter.
    """
    events: list[AuthEvent] = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            eid = str(row.get("EventID", "")).strip()
            kind = WIN_EVENT_MAP.get(eid)
            if not kind:
                continue
            ts = datetime.fromisoformat(row["TimeCreated"].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            ip = (row.get("IpAddress") or "").strip()
            if ip in ("-", "::1", "127.0.0.1"):
                ip = ""
            user = (row.get("TargetUserName") or "").strip()
            detail = f"EventID={eid} LogonType={row.get('LogonType','')} "
            if row.get("GroupName"):
                detail += f"group={row['GroupName']} "
            events.append(AuthEvent(ts, "windows", row.get("Computer", ""), kind,
                                    user, ip, detail.strip()))
    return events


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_internal(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _sliding_max(times: list[datetime], window: timedelta) -> tuple[int, int, int]:
    """Return (max_count, start_idx, end_idx) of events inside any window."""
    best, bi, bj, i = 0, 0, 0, 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        if j - i + 1 > best:
            best, bi, bj = j - i + 1, i, j
    return best, bi, bj


def detect_brute_force(events, cfg) -> list[Finding]:
    window = timedelta(minutes=cfg["brute_force_window_minutes"])
    by_ip = defaultdict(list)
    for e in events:
        if e.event == "login_failure" and e.src_ip:
            by_ip[e.src_ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        count, i, j = _sliding_max([e.timestamp for e in evs], window)
        if count >= cfg["brute_force_threshold"]:
            users = sorted({e.user for e in evs[i:j + 1]})
            out.append(Finding(
                "IR-001", "Brute-force authentication attempts",
                "high" if count >= cfg["brute_force_threshold"] * 3 else "medium",
                ["T1110.001"],
                _iso(evs[i].timestamp), _iso(evs[j].timestamp),
                {"src_ip": ip, "users": users, "hosts": sorted({e.host for e in evs})},
                count,
                "Block source at perimeter/host firewall, confirm no successful logon "
                "from this IP, enforce MFA and account lockout/throttling.",
                [e.detail for e in evs[i:j + 1]][: cfg["max_evidence_lines"]],
            ))
    return out


def detect_password_spray(events, cfg) -> list[Finding]:
    window = timedelta(minutes=cfg["spray_window_minutes"])
    by_ip = defaultdict(list)
    for e in events:
        if e.event == "login_failure" and e.src_ip:
            by_ip[e.src_ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        i = 0
        for j in range(len(evs)):
            while evs[j].timestamp - evs[i].timestamp > window:
                i += 1
            users = {e.user for e in evs[i:j + 1]}
            if len(users) >= cfg["spray_user_threshold"]:
                out.append(Finding(
                    "IR-002", "Password spraying (one source, many accounts)", "high",
                    ["T1110.003"],
                    _iso(evs[i].timestamp), _iso(evs[j].timestamp),
                    {"src_ip": ip, "distinct_users": len(users), "users": sorted(users)},
                    j - i + 1,
                    "Block source, review all targeted accounts for successful logons, "
                    "screen passwords against a breached-password blocklist "
                    "(NIST SP 800-63B-4), require phishing-resistant MFA.",
                    [e.detail for e in evs[i:j + 1]][: cfg["max_evidence_lines"]],
                ))
                break
    return out


def detect_success_after_failures(events, cfg) -> list[Finding]:
    window = timedelta(minutes=cfg["success_after_failure_minutes"])
    fails = defaultdict(list)
    out = []
    for e in sorted(events, key=lambda e: e.timestamp):
        if not e.src_ip:
            continue
        if e.event == "login_failure":
            fails[e.src_ip].append(e)
        elif e.event == "login_success":
            recent = [f for f in fails[e.src_ip] if e.timestamp - f.timestamp <= window]
            if len(recent) >= 3:
                out.append(Finding(
                    "IR-003", "Successful logon after repeated failures (possible compromise)",
                    "critical", ["T1110", "T1078"],
                    _iso(recent[0].timestamp), _iso(e.timestamp),
                    {"src_ip": e.src_ip, "user": e.user, "host": e.host,
                     "prior_failures": len(recent)},
                    len(recent) + 1,
                    "Treat as a likely compromised account: disable/reset credentials, "
                    "revoke sessions and keys, isolate host if post-logon activity is "
                    "found, and preserve evidence before remediation.",
                    [f.detail for f in recent[-(cfg['max_evidence_lines'] - 1):]] + [e.detail],
                ))
                fails[e.src_ip].clear()
    return out


def detect_off_hours(events, cfg, nets) -> list[Finding]:
    bh = cfg["business_hours"]
    svc = {s.lower() for s in cfg["service_accounts"]}
    out = []
    for e in events:
        if e.event != "login_success" or e.user.lower() in svc:
            continue
        local = e.timestamp + timedelta(hours=bh.get("utc_offset_hours", 0))
        off = not (bh["start"] <= local.hour < bh["end"])
        if bh.get("weekdays_only") and local.weekday() >= 5:
            off = True
        if off:
            external = e.src_ip and not _is_internal(e.src_ip, nets)
            out.append(Finding(
                "IR-004", "Successful logon outside business hours",
                "medium" if external else "low", ["T1078"],
                _iso(e.timestamp), _iso(e.timestamp),
                {"user": e.user, "src_ip": e.src_ip or "local", "host": e.host,
                 "external_source": bool(external)},
                1,
                "Validate with the account owner; if unexpected, follow the "
                "compromised-account playbook.",
                [e.detail],
            ))
    return out


def detect_persistence_and_tampering(events, cfg) -> list[Finding]:
    priv_groups = {g.lower() for g in cfg["privileged_groups"]}
    out = []
    for e in events:
        if e.event == "account_created":
            out.append(Finding(
                "IR-005", "New local/domain account created", "medium", ["T1136"],
                _iso(e.timestamp), _iso(e.timestamp),
                {"user": e.user, "host": e.host}, 1,
                "Confirm a change ticket exists for this account; disable if unapproved.",
                [e.detail]))
        elif e.event == "group_add":
            m = re.search(r"group=([^|]+?)(?:\s|\||$)", e.detail)
            group = m.group(1).strip() if m else ""
            if group.lower() in priv_groups:
                out.append(Finding(
                    "IR-006", "Account added to privileged group", "high", ["T1098"],
                    _iso(e.timestamp), _iso(e.timestamp),
                    {"user": e.user, "group": group, "host": e.host}, 1,
                    "Verify against approved change; remove membership and investigate "
                    "the actor if unapproved.", [e.detail]))
        elif e.event == "log_cleared":
            out.append(Finding(
                "IR-007", "Security audit log cleared", "critical", ["T1070.001"],
                _iso(e.timestamp), _iso(e.timestamp),
                {"host": e.host, "actor": e.user}, 1,
                "Indicator of anti-forensics. Pull logs from SIEM/forwarder copy, "
                "isolate host, escalate to incident commander.", [e.detail]))
    return out


def run_detections(events, cfg) -> list[Finding]:
    nets = [ipaddress.ip_network(n) for n in cfg["internal_networks"]]
    findings = (
        detect_brute_force(events, cfg)
        + detect_password_spray(events, cfg)
        + detect_success_after_failures(events, cfg)
        + detect_off_hours(events, cfg, nets)
        + detect_persistence_and_tampering(events, cfg)
    )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_reports(findings, events, inputs, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = _iso(datetime.now(timezone.utc))
    custody = [{"file": str(p), "sha256": sha256(p), "bytes": p.stat().st_size}
               for p in inputs]
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    payload = {
        "generated_utc": generated,
        "evidence_integrity": custody,
        "events_parsed": len(events),
        "summary": dict(sev_counts),
        "findings": [asdict(f) for f in findings],
    }
    jpath = out_dir / "triage_report.json"
    jpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Incident Triage Report",
        "",
        f"*Generated:* {generated}  ",
        f"*Events parsed:* {len(events)}  ",
        f"*Findings:* {len(findings)} "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))})",
        "",
        "## Evidence integrity (chain of custody)",
        "",
        "| File | SHA-256 | Bytes |",
        "|---|---|---|",
        *[f"| `{c['file']}` | `{c['sha256']}` | {c['bytes']} |" for c in custody],
        "",
        "## Findings",
        "",
        "| # | Severity | Rule | Title | ATT&CK | First seen | Key entities |",
        "|---|---|---|---|---|---|---|",
    ]
    for n, f in enumerate(findings, 1):
        ent = ", ".join(f"{k}={v}" for k, v in f.entities.items()
                        if not isinstance(v, list))
        lines.append(f"| {n} | **{f.severity.upper()}** | {f.rule_id} | {f.title} | "
                     f"{', '.join(f.attack)} | {f.first_seen} | {ent} |")
    lines += ["", "## Details", ""]
    for n, f in enumerate(findings, 1):
        lines += [
            f"### {n}. {f.title} ({f.rule_id})",
            "",
            f"- **Severity:** {f.severity}",
            f"- **MITRE ATT&CK:** {', '.join(f.attack)}",
            f"- **Window:** {f.first_seen} → {f.last_seen} ({f.evidence_count} events)",
            f"- **Entities:** `{json.dumps(f.entities)}`",
            f"- **Recommended action:** {f.recommendation}",
            "",
            "<details><summary>Evidence sample</summary>",
            "",
            "```",
            *f.evidence,
            "```",
            "</details>",
            "",
        ]
    mpath = out_dir / "triage_report.md"
    mpath.write_text("\n".join(lines), encoding="utf-8")
    return jpath, mpath


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def load_config(path: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        user = json.loads(Path(path).read_text(encoding="utf-8"))
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Authentication log triage (read-only).")
    ap.add_argument("--linux", action="append", default=[], help="Linux auth/secure log (repeatable)")
    ap.add_argument("--windows", action="append", default=[], help="Windows Security CSV export (repeatable)")
    ap.add_argument("--config", help="JSON config overriding defaults")
    ap.add_argument("--out", default="reports", help="Output directory")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                    help="Exit 2 if any finding at/above this severity (for automation)")
    args = ap.parse_args(argv)

    if not (args.linux or args.windows):
        ap.error("provide at least one --linux or --windows input")

    cfg = load_config(args.config)
    inputs = [Path(p) for p in args.linux + args.windows]
    events: list[AuthEvent] = []
    for p in map(Path, args.linux):
        events += parse_linux(p, cfg)
    for p in map(Path, args.windows):
        events += parse_windows(p, cfg)

    findings = run_detections(events, cfg)
    jpath, mpath = write_reports(findings, events, inputs, Path(args.out))
    print(f"[+] Parsed {len(events)} events, {len(findings)} findings")
    for f in findings:
        print(f"    [{f.severity.upper():8}] {f.rule_id} {f.title} :: "
              f"{', '.join(f'{k}={v}' for k, v in f.entities.items() if not isinstance(v, list))}")
    print(f"[+] Reports: {jpath}  {mpath}")

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
