# Project 04: Network Threat Detection & Firewall Policy Audit

**Skills shown:** network security monitoring (Zeek, Suricata) · traffic analysis · detection engineering · firewall policy review · network segmentation / Zero Trust · Python

A network defense toolkit in three parts:

1. **`netdetect.py`**: hunts Zeek or flow logs for **port scans, C2 beaconing, data exfiltration, policy violations and DNS tunneling**. It uses statistical methods (interval jitter, Shannon entropy, upload/download ratio) rather than signatures alone.
2. **`firewall/firewall_audit.py`**: a vendor-neutral rule-set auditor. It finds any/any rules, internet-exposed RDP/SMB/DB ports, shadowed and conflicting rules, missing default-deny, expired temporary rules, and unrestricted egress.
3. **`suricata/local.rules`**: 11 custom IDS rules, validated on **Suricata 7.0.3** (`11 rules successfully loaded, 0 rules failed`), plus a **segmentation and monitoring design** you can reuse.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Zeek](https://img.shields.io/badge/Zeek-conn%2Fdns%20logs-informational) ![Suricata](https://img.shields.io/badge/Suricata-7.x-orange) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Results on the sample dataset

The synthetic Zeek dataset (4,286 flows and 3,035 DNS queries) has six attack scenarios planted inside eight hours of normal traffic. It also includes a legitimate periodic update check that should **not** alert.

```
[+] 4286 flows, 3035 DNS queries -> 7 findings
    [CRITICAL] NET-003 Large outbound data transfer :: src=10.10.30.12, dst=203.0.113.200, dst_port=443
    [HIGH    ] NET-001 Vertical port scan :: src=203.0.113.50, dst=10.10.1.10, external_source=True
    [HIGH    ] NET-001 Horizontal sweep on port 445 :: src=10.10.20.66, dst_port=445
    [HIGH    ] NET-002 Periodic beaconing to external host :: src=10.10.20.31, dst=198.51.100.66, dst_port=443
    [HIGH    ] NET-004 Inbound RDP reachable from internet :: src=198.51.100.201, dst=10.10.1.20, dst_port=3389
    [HIGH    ] NET-005 DNS tunneling indicators :: domain=c2.example, sources=['10.10.20.31']
    [MEDIUM  ] NET-004 Outbound SMB to internet :: src=10.10.20.44, dst=198.51.100.150, dst_port=445
```

**7/7 scenarios detected and 0 false positives.** The allow-listed update server, which beacons every 5 minutes, was correctly ignored. Notice that `10.10.20.31` shows up for both beaconing and DNS tunneling. Correlating the two points to a single compromised host.

> **Tuning note.** The first version flagged 14 ordinary users as "horizontal scanners" because they visited many HTTPS sites. I fixed this by counting only probe-like connections (no response or no data returned) toward a sweep. That is the kind of false-positive tuning real detection work involves.

**Firewall audit**: the intentionally broken `sample_ruleset.json` produces 19 findings across all 10 checks. The remediated `hardened_ruleset.json` produces **0**.

```
[CRITICAL] FW-005 No default-deny
[CRITICAL] FW-001 rule 110: Any/any/any allow rule
[CRITICAL] FW-002 rule 30: Admin/database service exposed to the internet -> 3389/RDP
[HIGH    ] FW-008 rule 30: Expired temporary rule still present -> expired 2026-06-30 (121 days ago)
[HIGH    ] FW-004 rule 50: Conflicting shadowed rule -> never matches; fully covered by earlier rule 40
[HIGH    ] FW-010 rule 100: Unrestricted egress
...
```

Full reports: [`reports/network_findings.md`](reports/network_findings.md) · [`reports/firewall_audit.md`](reports/firewall_audit.md)

## Detection methods

| Rule | Method | ATT&CK |
|---|---|---|
| NET-001 Scan | Distinct ports per (src, dst) for vertical scans. Distinct hosts per (src, port) using only failed or unanswered connections for horizontal sweeps | T1046 |
| NET-002 Beacon | Coefficient of variation of inter-connection intervals ≤ 0.15 (low jitter) over ≥ 12 connections. Payload-size uniformity reported as supporting evidence | T1071, T1573 |
| NET-003 Exfil | Bytes out per internal→external pair ≥ 100 MB. Upload/download ratio > 20 raises severity to critical | T1048, T1041 |
| NET-004 Policy | Risky ports crossing trust zones (inbound admin/DB, outbound SMB/RDP/Telnet/IRC) | T1133, T1021 |
| NET-005 DNS tunnel | ≥ 50% of a domain's queries have labels ≥ 40 chars **and** mean Shannon entropy ≥ 3.8 | T1071.004 |

## Standards alignment

| Standard | Coverage |
|---|---|
| **NIST CSF 2.0** | DE.CM-01 (networks monitored), DE.AE-02 (events analyzed), PR.IR-01 (networks protected/segmented), PR.PS-01 (config mgmt) |
| **NIST SP 800-207** | Zero Trust segmentation design (`docs/`) |
| **NIST SP 800-41 Rev. 1** | Firewall policy: default deny, rule review, documentation |
| **CIS Controls v8.1** | 4.4/4.5 (firewalls), 12.2 (secure network architecture), 13.1/13.3/13.6 (alerting, network IDS, traffic flow logs), 13.4 (traffic filtering between segments) |
| **PCI DSS v4.0.1** | Req. 1 (network security controls, rule justification, periodic review) |
| **MITRE ATT&CK** | Every detection and Suricata rule is tagged |

## Repository layout

```
04-network-threat-detection/
├── netdetect.py                       # Flow/DNS analytics engine
├── config.json                        # Internal ranges, thresholds, allow-list
├── sample_data/
│   ├── generate_samples.py            # Deterministic synthetic Zeek data generator
│   ├── conn.log  dns.log              # Generated Zeek TSV logs
├── firewall/
│   ├── firewall_audit.py              # 10-check rule-set auditor
│   ├── sample_ruleset.json            # Intentionally misconfigured
│   └── hardened_ruleset.json          # Remediated (0 findings)
├── suricata/local.rules               # 11 custom IDS rules (SID 9000001+)
├── docs/segmentation-and-monitoring-design.md
├── reports/                           # Example outputs
└── tests/test_network.py
```

## Quick start

```bash
python3 netdetect.py --conn sample_data/conn.log --dns sample_data/dns.log --config config.json --out reports/
python3 firewall/firewall_audit.py firewall/sample_ruleset.json --as-of 2026-10-29 --out reports/
suricata -T -c /etc/suricata/suricata.yaml -S suricata/local.rules     # validate IDS rules
python3 -m unittest discover -s tests -v
```

## Adapting to any network

| Data source | How to use it |
|---|---|
| **Zeek** (Security Onion, Corelight, standalone) | `--conn conn.log --dns dns.log`. TSV and JSON both work |
| **Firewall / NetFlow / IPFIX** | Export CSV with `ts,src_ip,src_port,dst_ip,dst_port,proto,duration,bytes_out,bytes_in` and pass it as `--conn flows.csv` |
| **AWS VPC Flow Logs / Azure NSG flow logs / GCP VPC logs** | Map fields to the CSV schema above (e.g., `srcaddr→src_ip`, `bytes→bytes_out`) |
| **Firewalls** | Convert rule exports to the JSON schema (`_schema` in `sample_ruleset.json`). pfSense/OPNsense XML, FortiGate `show firewall policy`, Palo Alto `show running security-policy`, AWS SG `describe-security-groups`, and Azure NSG `az network nsg rule list` all map directly: src, dst, port, action, direction |
| **IDS** | Set `$HOME_NET`/`$EXTERNAL_NET` in `suricata.yaml` and add `local.rules` to `rule-files` |

Tune `config.json`:

- `internal_networks`: every internal and VPN range, so trust-zone logic is correct.
- `allowlist_destinations`: sanctioned periodic services (patch servers, EDR cloud, backup provider).
- Thresholds: a 50-user office can lower `exfil_bytes_threshold`. A data center may need to raise scan thresholds.

## Security & ethics

- All tools are **passive and read-only**. They analyze logs and never send traffic.
- Sample data uses RFC 5737 documentation IPs and the reserved `.example` TLD. No real organizations are involved.
- Packet and flow data can contain sensitive information. Handle it according to your data-retention and privacy policy, and only monitor networks you are authorized to monitor.

## Lessons learned

1. **Behavior beats signatures for C2.** Encrypted beacons on 443 look like normal HTTPS until you look at *timing*.
2. **Correlate across data sources.** The beaconing host was also tunneling DNS. Two medium-confidence signals on one host add up to a high-confidence incident.
3. **Tune before you deploy.** My first sweep rule would have buried analysts in alerts about ordinary browsing.
4. **Rule order matters.** The "deny DMZ→SQL" rule *looked* correct but never fired because a broader allow sat above it, so the firewall's real behavior didn't match its stated policy.
5. **Prevention and detection work together.** Every NET-004 finding has a matching FW-002/FW-010 misconfiguration. Fixing the firewall removes the alert at its source.
