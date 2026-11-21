#!/usr/bin/env python3
"""
DFIR Triage Analyzer
====================

Analyzes live-response triage packages (one folder per host, produced by
collectors/win_triage.ps1 or collectors/linux_triage.sh) and reconstructs the
attack:

  1. Verifies evidence integrity (SHA256SUMS) before touching anything.
  2. Runs ~25 behavior rules over Sysmon / Security / System events and the
     live snapshot (processes, connections, scheduled tasks, services, autoruns).
  3. Decodes PowerShell -EncodedCommand payloads and extracts IOCs.
  4. Detects ransomware impact (mass file renames to one new extension, ransom notes)
     and C2 beaconing (regular outbound intervals).
  5. Builds a multi-host super-timeline and an ATT&CK-ordered kill chain.

    python3 analyze_triage.py evidence/WS-0102 evidence/FS01 --out reports/

Standard library only; read-only. Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Lateral Movement", "Command and Control", "Impact"]
USER_WRITABLE = re.compile(r"(?i)\\(appdata|temp|programdata|users\\public|downloads|perflogs)\\|^[a-z]:\\windows\\temp\\")
OFFICE = re.compile(r"(?i)\\(winword|excel|powerpnt|outlook|onenote|msaccess)\.exe$")
SHELLS = re.compile(r"(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")

# Rule: id, tactic, technique, severity, title, predicate(event)->bool
RULES = [
    ("DF-01", "Initial Access", "T1553.005", "high", "Disk image (ISO/IMG/VHD) written by browser or mail client",
     lambda e: e.get("Id") == 11 and re.search(r"(?i)\.(iso|img|vhd|vhdx)$", e.get("TargetFilename", ""))),
    ("DF-02", "Execution", "T1218.005", "high", "mshta.exe executing HTA / script",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)\\mshta\.exe$", e.get("Image", ""))),
    ("DF-03", "Execution", "T1059.001", "high", "Encoded / hidden PowerShell",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)powershell|pwsh", e.get("Image", ""))
     and re.search(r"(?i)\s-(e|en|enc|enco|encodedcommand)\s|-w(indowstyle)?\s+hidden|-nop\b", e.get("CommandLine", ""))),
    ("DF-04", "Execution", "T1204.002", "high", "Office / mail application spawned a shell or LOLBin",
     lambda e: e.get("Id") == 1 and OFFICE.search(e.get("ParentImage", "")) and SHELLS.search(e.get("Image", ""))),
    ("DF-05", "Defense Evasion", "T1218.011", "high", "rundll32 loading a DLL from a user-writable path",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)\\rundll32\.exe$", e.get("Image", ""))
     and USER_WRITABLE.search(e.get("CommandLine", "")) and "comsvcs" not in e.get("CommandLine", "").lower()),
    ("DF-06", "Execution", "T1105", "medium", "Executable/DLL dropped in user-writable path",
     lambda e: e.get("Id") == 11 and re.search(r"(?i)\.(exe|dll|ps1|bat|vbs|js|hta)$", e.get("TargetFilename", ""))
     and USER_WRITABLE.search(e.get("TargetFilename", ""))),
    ("DF-07", "Persistence", "T1053.005", "high", "Scheduled task created (command line)",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)schtasks(\.exe)?\s+/create", e.get("CommandLine", ""))),
    ("DF-08", "Persistence", "T1053.005", "high", "Scheduled task registered (Event 4698)",
     lambda e: e.get("Id") == 4698),
    ("DF-09", "Persistence", "T1543.003", "medium", "New service installed (Event 7045)",
     lambda e: e.get("Id") == 7045),
    ("DF-10", "Discovery", "T1087.002", "medium", "Domain / privileged-group discovery commands",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)net(1)?\s+group\s+\"?domain admins|nltest\s+/dclist|whoami\s+/all|adfind",
                                             e.get("CommandLine", ""))),
    ("DF-11", "Credential Access", "T1003.001", "critical", "LSASS memory dump (comsvcs MiniDump / procdump)",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)comsvcs(\.dll)?,?\s*#?(minidump|24)|procdump.*lsass", e.get("CommandLine", ""))),
    ("DF-12", "Credential Access", "T1003.001", "critical", "Process opened LSASS with full access (Sysmon 10)",
     lambda e: e.get("Id") == 10 and e.get("TargetImage", "").lower().endswith("lsass.exe")
     and e.get("GrantedAccess", "").lower() in ("0x1fffff", "0x1410", "0x1010", "0x143a")),
    ("DF-13", "Defense Evasion", "T1562.001", "critical", "Microsoft Defender protection disabled",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)Set-MpPreference.*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)",
                                             e.get("CommandLine", ""))),
    ("DF-14", "Lateral Movement", "T1569.002", "high", "PsExec remote execution",
     lambda e: (e.get("Id") == 1 and re.search(r"(?i)psexec(64)?(\.exe)?\s+\\\\", e.get("CommandLine", "")))
     or (e.get("Id") == 7045 and "psexesvc" in e.get("ServiceName", "").lower())),
    ("DF-15", "Lateral Movement", "T1021.002", "medium", "Network logon (type 3) from a workstation to a server",
     lambda e: e.get("Id") == 4624 and str(e.get("LogonType")) == "3" and e.get("IpAddress", "").startswith("10.10.20.")),
    ("DF-16", "Impact", "T1490", "critical", "Shadow copies / backup catalog deleted, recovery disabled",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)vssadmin.*delete\s+shadows|wbadmin.*delete\s+catalog|"
                                             r"bcdedit.*recoveryenabled\s+no|shadowcopy\s+delete", e.get("CommandLine", ""))),
    ("DF-17", "Defense Evasion", "T1070.001", "critical", "Event log cleared",
     lambda e: e.get("Id") == 1102 or (e.get("Id") == 1 and re.search(r"(?i)wevtutil(\.exe)?\s+cl\b|Clear-EventLog",
                                                                      e.get("CommandLine", "")))),
    ("DF-18", "Execution", "T1569.002", "high", "Process executed from Windows\\Temp by a service (SYSTEM)",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)^[a-z]:\\windows\\temp\\", e.get("Image", ""))),
    ("DF-19", "Execution", "T1059", "medium", "LOLBin download / decode (certutil, bitsadmin, curl to temp)",
     lambda e: e.get("Id") == 1 and re.search(r"(?i)certutil.*(-urlcache|-decode)|bitsadmin.*/transfer|"
                                             r"curl(\.exe)?\s.*-o\s.*(temp|programdata)", e.get("CommandLine", ""))),
]


# --------------------------------------------------------------------------- #

def verify(host_dir: Path) -> list[str]:
    sums = host_dir / "SHA256SUMS"
    if not sums.exists():
        return ["SHA256SUMS missing: integrity cannot be verified"]
    problems = []
    for line in sums.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        p = host_dir / name.strip()
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            problems.append(f"{name.strip()}: hash mismatch or missing")
    return problems


def load(host_dir: Path) -> dict:
    d = {}
    for name in ("host", "events", "processes", "network", "autoruns", "scheduled_tasks", "services"):
        p = host_dir / f"{name}.json"
        d[name] = json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else ([] if name != "host" else {})
    return d


def decode_ps(cmd: str) -> str | None:
    m = re.search(r"(?i)\s-(?:e|en|enc|enco|encod|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", cmd)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16le")
    except Exception:
        return None


INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10")]


def is_external(ip: str) -> bool:
    """Explicit RFC 1918/loopback/link-local check. (ipaddress.is_private would also treat the
    RFC 5737 documentation ranges used in training data as private.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a.version == n.version and a in n for n in INTERNAL_NETS)


def beacons(events, min_n=10, max_cv=0.1):
    g = defaultdict(list)
    for e in events:
        if e.get("Id") == 3 and is_external(e.get("DestinationIp", "")):
            g[(e["Computer"], e["Image"], e["DestinationIp"], e.get("DestinationPort"))].append(e["TimeCreated"])
    out = []
    for k, ts in g.items():
        if len(ts) < min_n:
            continue
        s = sorted(datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp() for x in ts)
        gaps = [b - a for a, b in zip(s, s[1:])]
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv <= max_cv:
            out.append({"host": k[0], "image": k[1], "dst": k[2], "port": k[3], "count": len(ts),
                        "interval_s": round(mean, 1), "jitter_cv": round(cv, 3), "first": min(ts), "last": max(ts)})
    return out


def mass_rename(events, threshold=100):
    g = defaultdict(list)
    notes = []
    for e in events:
        if e.get("Id") != 11:
            continue
        f = e.get("TargetFilename", "")
        m = re.search(r"\.[A-Za-z0-9]{2,6}(\.[A-Za-z0-9]{3,10})$", f)
        if m:
            g[(e["Computer"], e["Image"], m.group(1).lower())].append(e["TimeCreated"])
        if re.search(r"(?i)(readme|restore|decrypt|how_to).*\.(txt|html|hta)$", f):
            notes.append(e)
    out = [{"host": h, "image": i, "extension": ext, "files": len(ts), "first": min(ts), "last": max(ts)}
           for (h, i, ext), ts in g.items() if len(ts) >= threshold]
    return out, notes


IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s'\"\)]+"),
    "path": re.compile(r"(?i)[a-z]:\\(?:programdata|windows\\temp|users\\[^\\]+\\(?:appdata|downloads))\\[^\s\"',]+"),
}


def analyze(hosts: list[Path]) -> dict:
    events, integrity, snapshots = [], {}, {}
    for hd in hosts:
        integrity[hd.name] = verify(hd)
        d = load(hd)
        snapshots[hd.name] = d
        events += d["events"]
    events.sort(key=lambda e: e["TimeCreated"])

    findings = []
    for e in events:
        for rid, tactic, tech, sev, title, pred in RULES:
            try:
                hit = pred(e)
            except Exception:
                hit = False
            if hit:
                f = {"rule": rid, "tactic": tactic, "technique": tech, "severity": sev, "title": title,
                     "time": e["TimeCreated"], "host": e.get("Computer"), "user": e.get("User") or e.get("TargetUserName", ""),
                     "evidence": e.get("CommandLine") or e.get("TargetFilename") or e.get("TaskContent")
                     or e.get("ImagePath") or e.get("TargetImage") or f"EventID {e.get('Id')}"}
                dec = decode_ps(e.get("CommandLine", ""))
                if dec:
                    f["decoded"] = dec
                findings.append(f)

    for b in beacons(events):
        findings.append({"rule": "DF-20", "tactic": "Command and Control", "technique": "T1071.001", "severity": "critical",
                         "title": f"C2 beaconing every ~{b['interval_s']}s ({b['count']} connections, jitter {b['jitter_cv']})",
                         "time": b["first"], "host": b["host"], "user": "", "evidence": f"{b['image']} -> {b['dst']}:{b['port']}"})
    mr, notes = mass_rename(events)
    for m in mr:
        findings.append({"rule": "DF-21", "tactic": "Impact", "technique": "T1486", "severity": "critical",
                         "title": f"Mass encryption: {m['files']} files renamed to *{m['extension']}",
                         "time": m["first"], "host": m["host"], "user": "", "evidence": f"{m['image']} ({m['first']} → {m['last']})"})
    for n in notes:
        findings.append({"rule": "DF-22", "tactic": "Impact", "technique": "T1486", "severity": "critical",
                         "title": "Ransom note dropped", "time": n["TimeCreated"], "host": n["Computer"], "user": "",
                         "evidence": n["TargetFilename"]})
    # snapshot rules
    for hn, d in snapshots.items():
        for t in d["scheduled_tasks"]:
            if USER_WRITABLE.search(t.get("Action", "")) and "microsoft corporation" not in t.get("Author", "").lower():
                findings.append({"rule": "DF-23", "tactic": "Persistence", "technique": "T1053.005", "severity": "high",
                                 "title": f"Live scheduled task runs from user-writable path ({t['TaskName']})",
                                 "time": d["host"].get("collected_utc", ""), "host": d["host"].get("hostname", hn),
                                 "user": t.get("Author", ""), "evidence": t["Action"]})
        pids = {p["ProcessId"]: p for p in d["processes"]}
        for c in d["network"]:
            p = pids.get(c.get("OwningProcess"))
            if p and is_external(c["RemoteAddress"]) and (USER_WRITABLE.search(p.get("CommandLine", "")) or SHELLS.search(p.get("Path", ""))):
                findings.append({"rule": "DF-24", "tactic": "Command and Control", "technique": "T1071", "severity": "critical",
                                 "title": "Active connection to internet from suspicious process at collection time",
                                 "time": d["host"].get("collected_utc", ""), "host": d["host"].get("hostname", hn),
                                 "user": p.get("User", ""), "evidence": f"{p['CommandLine']} -> {c['RemoteAddress']}:{c['RemotePort']}"})

    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: f["time"])
    # IOCs
    iocs = defaultdict(set)
    for f in findings:
        blob = " ".join(str(f.get(k, "")) for k in ("evidence", "decoded"))
        for typ, rx in IOC_PATTERNS.items():
            for v in rx.findall(blob):
                if typ == "ipv4" and not is_external(v):
                    continue
                iocs[typ].add(v.rstrip(".,;"))
    for e in events:
        if e.get("Id") == 1 and any(f["time"] == e["TimeCreated"] and f["host"] == e["Computer"] for f in findings):
            if e.get("Hashes") and USER_WRITABLE.search(e.get("Image", "")):
                iocs["sha256"].add(f"{e['Hashes'].split('=')[-1]}  ({Path(e['Image'].replace(chr(92), '/')).name})")
        if e.get("Id") == 4698:
            iocs["scheduled_task"].add(e["TaskName"])
        if e.get("Id") == 7045:
            iocs["service"].add(e["ServiceName"])
    chain = {t: [f for f in findings if f["tactic"] == t] for t in TACTICS}
    patient_zero = next((f for f in findings if f["tactic"] in ("Initial Access", "Execution")), None)
    return {"integrity": integrity, "event_count": len(events), "findings": findings,
            "kill_chain": {t: len(v) for t, v in chain.items()},
            "first_malicious": patient_zero, "iocs": {k: sorted(v) for k, v in iocs.items()},
            "severity_counts": dict(Counter(f["severity"] for f in findings)),
            "hosts": {k: v["host"] for k, v in snapshots.items()}}


def write(result: dict, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "triage_findings.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    with (out / "super_timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["time_utc", "host", "user", "tactic", "technique", "rule", "severity", "title", "evidence"])
        for f in result["findings"]:
            w.writerow([f["time"], f["host"], f["user"], f["tactic"], f["technique"], f["rule"], f["severity"], f["title"], f["evidence"]])
    md = ["# DFIR Triage Findings", "", "## Evidence integrity", "", "| Host | Status |", "|---|---|"]
    for h, probs in result["integrity"].items():
        md.append(f"| {h} | {'✅ all SHA-256 hashes verified' if not probs else '❌ ' + '; '.join(probs)} |")
    md += ["", "## Kill chain coverage (ATT&CK tactics)", "", "| Tactic | Findings |", "|---|---|"]
    md += [f"| {t} | {'█' * n} {n} |" for t, n in result["kill_chain"].items()]
    md += ["", "## Timeline of malicious activity (UTC)", "", "| Time | Host | Tactic | Technique | Sev | Finding | Evidence |", "|---|---|---|---|---|---|---|"]
    for f in result["findings"]:
        ev = f["evidence"].replace("|", "\\|")
        ev = ev if len(ev) < 140 else ev[:137] + "…"
        dec = f" <br>**Decoded:** `{f['decoded']}`" if f.get("decoded") else ""
        md.append(f"| {f['time'][11:19]} {f['time'][:10]} | {f['host'].split('.')[0]} | {f['tactic']} | {f['technique']} | "
                  f"{f['severity']} | {f['title']} | `{ev}`{dec} |")
    md += ["", "## Indicators of compromise", ""]
    for k, vs in result["iocs"].items():
        md.append(f"**{k}**")
        md += [f"- `{v}`" for v in vs]
        md.append("")
    (out / "triage_findings.md").write_text("\n".join(md), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DFIR triage package analyzer")
    ap.add_argument("hosts", nargs="+", type=Path, help="triage folders (one per host)")
    ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    r = analyze(a.hosts)
    write(r, a.out)
    for h, p in r["integrity"].items():
        print(f"[{'✓' if not p else '✗'}] integrity {h}: {'verified' if not p else p}")
    print(f"[+] {r['event_count']} events, {len(r['findings'])} findings {r['severity_counts']}")
    for f in r["findings"]:
        print(f"    {f['time'][11:19]} {f['host'].split('.')[0]:<8} {f['tactic']:<20} {f['technique']:<10} {f['title'][:70]}")
        if f.get("decoded"):
            print(f"             ↳ decoded: {f['decoded']}")
    print("[+] Kill chain: " + " → ".join(t for t, n in r["kill_chain"].items() if n))
    print(f"[+] IOCs: " + ", ".join(f"{k}={len(v)}" for k, v in r["iocs"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
