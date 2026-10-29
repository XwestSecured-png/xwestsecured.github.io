#!/usr/bin/env python3
"""
Network Threat Detection from Flow Logs
=======================================

Analyzes Zeek conn.log / dns.log (TSV or JSON) or a generic flow CSV (exported
from NetFlow/IPFIX, VPC Flow Logs, firewall logs) and detects:

  NET-001  Port scanning (vertical and horizontal)               T1046
  NET-002  C2 beaconing (regular intervals, low jitter)          T1071 / T1573
  NET-003  Large outbound transfer / possible exfiltration       T1048 / T1041
  NET-004  Policy violations (risky ports crossing trust zones)  T1021 / T1133
  NET-005  DNS tunneling indicators (long, high-entropy names)   T1071.004

Standard library only, read-only. Thresholds and trust zones live in config.json.

    python3 netdetect.py --conn sample_data/conn.log --dns sample_data/dns.log \
                         --config config.json --out reports/

Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONFIG = {
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "scan_vertical_ports": 25,          # distinct ports on one host
    "scan_horizontal_hosts": 20,        # distinct hosts on one port
    "beacon_min_connections": 12,
    "beacon_max_cv": 0.15,              # coefficient of variation of intervals (jitter)
    "beacon_min_interval_s": 10,
    "exfil_bytes_threshold": 100_000_000,   # 100 MB to a single external dest
    "dns_label_min_len": 40,
    "dns_entropy_threshold": 3.8,
    "dns_min_queries_per_domain": 10,
    "allowlist_destinations": [],       # e.g. update servers, backup provider
    "risky_outbound_ports": {"23": "Telnet", "445": "SMB", "3389": "RDP", "135": "MS-RPC",
                             "139": "NetBIOS", "1433": "MSSQL", "3306": "MySQL", "5900": "VNC",
                             "6667": "IRC"},
    "risky_inbound_ports": {"22": "SSH", "23": "Telnet", "445": "SMB", "3389": "RDP",
                            "5985": "WinRM", "5986": "WinRM-TLS", "1433": "MSSQL", "3306": "MySQL",
                            "5432": "PostgreSQL", "6379": "Redis", "9200": "Elasticsearch",
                            "27017": "MongoDB"},
}


@dataclass
class Flow:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    duration: float
    bytes_out: int
    bytes_in: int
    state: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    attack: list
    entities: dict
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""


FAILED_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "SH", "OTH"}
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

def _num(v, cast=float, default=0):
    try:
        return cast(v) if v not in ("-", "", None) else default
    except ValueError:
        return default


def read_zeek(path: Path) -> list[dict]:
    """Zeek TSV (with #fields header) or Zeek JSON-lines."""
    rows, fields = [], None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                rows.append(json.loads(line))
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                rows.append(dict(zip(fields, line.split("\t"))))
    return rows


def load_flows(path: Path) -> list[Flow]:
    flows = []
    if path.suffix.lower() == ".csv":
        # Generic: ts,src_ip,src_port,dst_ip,dst_port,proto,duration,bytes_out,bytes_in
        with path.open(encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh):
                ts = r["ts"]
                t = _num(ts) if ts.replace(".", "", 1).isdigit() else \
                    datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                flows.append(Flow(t, r["src_ip"], _num(r.get("src_port"), int), r["dst_ip"],
                                  _num(r.get("dst_port"), int), r.get("proto", "tcp").lower(),
                                  _num(r.get("duration")), _num(r.get("bytes_out"), int),
                                  _num(r.get("bytes_in"), int)))
        return flows
    for r in read_zeek(path):
        flows.append(Flow(_num(r.get("ts")), r.get("id.orig_h", ""), _num(r.get("id.orig_p"), int),
                          r.get("id.resp_h", ""), _num(r.get("id.resp_p"), int), r.get("proto", ""),
                          _num(r.get("duration")), _num(r.get("orig_bytes"), int),
                          _num(r.get("resp_bytes"), int), r.get("conn_state", "")))
    return flows


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

class Zones:
    def __init__(self, nets):
        self.nets = [ipaddress.ip_network(n) for n in nets]

    def internal(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def base_domain(q: str) -> str:
    parts = q.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #

def detect_scans(flows, cfg, z) -> list[Finding]:
    out = []
    vert = defaultdict(set)           # (src,dst) -> ports
    horiz = defaultdict(set)          # (src,port) -> dsts
    failed = Counter()
    times = defaultdict(list)
    for f in flows:
        vert[(f.src, f.dst)].add(f.dport)
        times[f.src].append(f.ts)
        probe = f.state in FAILED_STATES or f.bytes_in == 0
        if probe:
            failed[f.src] += 1
            # Horizontal sweeps count only probe-like connections (no answer / no data
            # back) so a busy user browsing many HTTPS sites is not flagged.
            horiz[(f.src, f.dport)].add(f.dst)
    for (src, dst), ports in vert.items():
        if len(ports) >= cfg["scan_vertical_ports"]:
            ext = not z.internal(src)
            out.append(Finding("NET-001", "Vertical port scan", "high" if ext else "medium", ["T1046"],
                               {"src": src, "dst": dst, "external_source": ext},
                               {"distinct_ports": len(ports), "sample_ports": sorted(ports)[:15],
                                "failed_conns_from_src": failed[src],
                                "first_seen": iso(min(times[src])), "last_seen": iso(max(times[src]))},
                               "Block source if external; if internal, identify the host owner — "
                               "unauthorized internal scanning often follows initial compromise."))
    for (src, port), dsts in horiz.items():
        if len(dsts) >= cfg["scan_horizontal_hosts"]:
            out.append(Finding("NET-001", f"Horizontal sweep on port {port}", "high", ["T1046"],
                               {"src": src, "dst_port": port, "external_source": not z.internal(src)},
                               {"distinct_hosts": len(dsts), "first_seen": iso(min(times[src]))},
                               "Sweeps of a single service (e.g. 445/3389) across many hosts are typical "
                               "of worm propagation or lateral-movement discovery. Isolate and investigate."))
    return out


def detect_beacons(flows, cfg, z) -> list[Finding]:
    allow = set(cfg["allowlist_destinations"])
    groups = defaultdict(list)
    for f in flows:
        if z.internal(f.src) and not z.internal(f.dst) and f.dst not in allow:
            groups[(f.src, f.dst, f.dport)].append(f)
    out = []
    for (src, dst, port), fl in groups.items():
        if len(fl) < cfg["beacon_min_connections"]:
            continue
        ts = sorted(x.ts for x in fl)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(gaps) < cfg["beacon_min_connections"] - 1:
            continue
        mean = statistics.mean(gaps)
        if mean < cfg["beacon_min_interval_s"]:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 1
        sizes = [x.bytes_out for x in fl]
        size_cv = (statistics.pstdev(sizes) / statistics.mean(sizes)) if statistics.mean(sizes) else 0
        if cv <= cfg["beacon_max_cv"]:
            out.append(Finding("NET-002", "Periodic beaconing to external host", "high",
                               ["T1071", "T1573"],
                               {"src": src, "dst": dst, "dst_port": port},
                               {"connections": len(fl), "mean_interval_s": round(mean, 1),
                                "interval_jitter_cv": round(cv, 3), "payload_size_cv": round(size_cv, 3),
                                "first_seen": iso(ts[0]), "last_seen": iso(ts[-1])},
                               "Look up destination reputation, pull process/parent from EDR on the source "
                               "host, and check for persistence. Consistent intervals + uniform payload "
                               "sizes are typical of C2 implants (Cobalt Strike, Sliver, etc.)."))
    return out


def detect_exfil(flows, cfg, z) -> list[Finding]:
    allow = set(cfg["allowlist_destinations"])
    totals = defaultdict(lambda: [0, 0, None, None])
    for f in flows:
        if z.internal(f.src) and not z.internal(f.dst) and f.dst not in allow:
            t = totals[(f.src, f.dst, f.dport)]
            t[0] += f.bytes_out; t[1] += f.bytes_in
            t[2] = f.ts if t[2] is None else min(t[2], f.ts)
            t[3] = f.ts if t[3] is None else max(t[3], f.ts)
    out = []
    for (src, dst, port), (bo, bi, first, last) in totals.items():
        if bo >= cfg["exfil_bytes_threshold"]:
            ratio = round(bo / max(bi, 1), 1)
            out.append(Finding("NET-003", "Large outbound data transfer", "critical" if ratio > 20 else "high",
                               ["T1048", "T1041"], {"src": src, "dst": dst, "dst_port": port},
                               {"bytes_out": bo, "mb_out": round(bo / 1e6, 1), "upload_download_ratio": ratio,
                                "first_seen": iso(first), "last_seen": iso(last)},
                               "Confirm whether this is a sanctioned backup/sync. If not: isolate the host, "
                               "identify the data, and engage the incident response and legal/privacy teams."))
    return out


def detect_policy(flows, cfg, z) -> list[Finding]:
    out_ports = {int(k): v for k, v in cfg["risky_outbound_ports"].items()}
    in_ports = {int(k): v for k, v in cfg["risky_inbound_ports"].items()}
    seen = defaultdict(lambda: [0, None])
    for f in flows:
        si, di = z.internal(f.src), z.internal(f.dst)
        if si and not di and f.dport in out_ports:
            key = ("out", f.src, f.dst, f.dport)
        elif not si and di and f.dport in in_ports and f.state not in ("S0", "REJ"):
            key = ("in", f.src, f.dst, f.dport)
        else:
            continue
        seen[key][0] += 1
        seen[key][1] = seen[key][1] or f.ts
    out = []
    for (d, src, dst, port), (n, first) in seen.items():
        if d == "out":
            out.append(Finding("NET-004", f"Outbound {out_ports[port]} to internet", "medium",
                               ["T1048", "T1021"], {"src": src, "dst": dst, "dst_port": port},
                               {"connections": n, "first_seen": iso(first)},
                               f"Egress filtering should block {out_ports[port]} ({port}) to the internet."))
        else:
            out.append(Finding("NET-004", f"Inbound {in_ports[port]} reachable from internet", "high",
                               ["T1133", "T1021"], {"src": src, "dst": dst, "dst_port": port},
                               {"established_connections": n, "first_seen": iso(first)},
                               f"Remove internet exposure of {in_ports[port]}; place behind VPN/ZTNA with MFA."))
    return out


def detect_dns_tunnel(dns_rows, cfg) -> list[Finding]:
    by_dom = defaultdict(lambda: {"n": 0, "long": 0, "ent": [], "srcs": set(), "qtypes": Counter(), "ex": ""})
    for r in dns_rows:
        q = (r.get("query") or "").lower()
        if not q or q == "-":
            continue
        dom = base_domain(q)
        sub = q[: -len(dom)].rstrip(".")
        label = max(sub.split("."), key=len) if sub else ""
        d = by_dom[dom]
        d["n"] += 1
        d["srcs"].add(r.get("id.orig_h", ""))
        d["qtypes"][r.get("qtype_name", "")] += 1
        if len(label) >= cfg["dns_label_min_len"]:
            d["long"] += 1
            d["ex"] = d["ex"] or q
        d["ent"].append(shannon(label))
    out = []
    for dom, d in by_dom.items():
        if d["n"] < cfg["dns_min_queries_per_domain"]:
            continue
        avg_ent = statistics.mean(d["ent"]) if d["ent"] else 0
        if d["long"] / d["n"] >= 0.5 and avg_ent >= cfg["dns_entropy_threshold"]:
            out.append(Finding("NET-005", "DNS tunneling indicators", "high", ["T1071.004", "T1048.003"],
                               {"domain": dom, "sources": sorted(d["srcs"])},
                               {"queries": d["n"], "long_label_ratio": round(d["long"] / d["n"], 2),
                                "avg_label_entropy": round(avg_ent, 2), "qtypes": dict(d["qtypes"]),
                                "example": d["ex"][:120]},
                               "Sinkhole/block the domain at the resolver, force all DNS through internal "
                               "resolvers (block outbound 53/853 except resolvers), inspect source hosts."))
    return out


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def report(findings, n_flows, n_dns, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "network_findings.json").write_text(json.dumps(
        {"flows": n_flows, "dns_queries": n_dns, "findings": [asdict(f) for f in findings]}, indent=2),
        encoding="utf-8")
    c = Counter(f.severity for f in findings)
    md = ["# Network Threat Detection Report", "",
          f"*Flows analyzed:* {n_flows} · *DNS queries:* {n_dns} · *Findings:* {len(findings)} "
          f"(critical {c['critical']}, high {c['high']}, medium {c['medium']}, low {c['low']})", "",
          "| # | Sev | Rule | Title | ATT&CK | Entities | Key evidence |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        ent = ", ".join(f"{k}={v}" for k, v in f.entities.items())
        ev = ", ".join(f"{k}={v}" for k, v in f.evidence.items()
                       if k not in ("sample_ports", "first_seen", "last_seen", "example", "qtypes"))
        md.append(f"| {i} | **{f.severity.upper()}** | {f.rule_id} | {f.title} | {', '.join(f.attack)} | {ent} | {ev} |")
    md += ["", "## Recommended actions", ""]
    for i, f in enumerate(findings, 1):
        md.append(f"{i}. **{f.title}** ({', '.join(f'{k}={v}' for k, v in f.entities.items())}): {f.recommendation}")
    (out / "network_findings.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        cfg.update({k: v for k, v in json.loads(Path(path).read_text()).items() if not k.startswith("_")})
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Flow-based network threat detection (read-only)")
    ap.add_argument("--conn", action="append", default=[], help="Zeek conn.log (TSV/JSON) or flow CSV")
    ap.add_argument("--dns", action="append", default=[], help="Zeek dns.log (TSV/JSON)")
    ap.add_argument("--config")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args(argv)
    if not a.conn and not a.dns:
        ap.error("provide --conn and/or --dns")

    cfg = load_config(a.config)
    z = Zones(cfg["internal_networks"])
    flows = [f for p in a.conn for f in load_flows(Path(p))]
    dns = [r for p in a.dns for r in read_zeek(Path(p))]

    findings = (detect_scans(flows, cfg, z) + detect_beacons(flows, cfg, z) + detect_exfil(flows, cfg, z)
                + detect_policy(flows, cfg, z) + detect_dns_tunnel(dns, cfg))
    findings.sort(key=lambda f: SEV[f.severity])
    report(findings, len(flows), len(dns), Path(a.out))

    print(f"[+] {len(flows)} flows, {len(dns)} DNS queries -> {len(findings)} findings")
    for f in findings:
        print(f"    [{f.severity.upper():8}] {f.rule_id} {f.title} :: "
              f"{', '.join(f'{k}={v}' for k, v in f.entities.items())}")
    print(f"[+] Reports in {a.out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
