# Cybersecurity Portfolio Projects

Four hands-on defensive security projects by **Xiome West**. Each one includes working code, synthetic sample data, generated reports, automated tests, and documentation mapped to current standards (NIST CSF 2.0, NIST SP 800-61r3, NIST SP 800-63B-4, CIS Controls v8.1, OWASP Top 10:2025, MITRE ATT&CK).

| # | Project | What it demonstrates | Key standards |
|---|---|---|---|
| 01 | [Incident Response Log Triage Toolkit](01-incident-response-log-triage/) | Linux and Windows auth-log correlation, 7 ATT&CK-mapped detections, chain-of-custody hashing, IR playbook, Incident Handler's Journal, Sigma rules | NIST SP 800-61r3, CSF 2.0, ATT&CK |
| 02 | [Vulnerability Assessment & Risk-Based Remediation](02-vulnerability-management/) | CVSS + CISA KEV + EPSS + asset context prioritization, SLA plans, read-only Linux and Windows hardening audits | CIS Controls v8.1, CISA KEV, NIST SP 800-115 |
| 03 | [Secure SQL, Injection Defense & SQL Threat Hunting](03-secure-sql-and-threat-hunting/) | Vulnerable vs. secure code, 10 SQL hunts, SQLi log detector, DB hardening checklist | OWASP Top 10:2025 A05, CWE-89, SP 800-63B-4 |
| 04 | [Network Threat Detection & Firewall Policy Audit](04-network-threat-detection/) | Zeek-based detection of scans, beacons, exfiltration and DNS tunneling, a 10-check firewall auditor, 11 Suricata rules, Zero Trust segmentation design | NIST SP 800-207, SP 800-41, CIS 12/13 |

## Design principles (shared by all four)

- **Adaptable to any environment.** Thresholds, network ranges, business hours, SLAs and allow-lists live in config files, not code. Each README has an "Adapting to your environment" section covering small organizations, enterprise, cloud, and air-gapped networks.
- **Safe by default.** Every tool is read-only or passive, and the audit scripts never change settings.
- **No dependencies.** Python tools use only the standard library (Python 3.9+), so they run on any analyst workstation or jump box.
- **Responsible data.** All sample data is synthetic. IPs come from the RFC 5737 documentation ranges, domains use `.example`, and placeholder CVEs use `CVE-2099-*`.
- **Tested.** `python3 -m unittest discover -s tests` passes in every project (39 tests total).

## Run everything

```bash
for p in 0*/; do (cd "$p" && echo "== $p" && python3 -m unittest discover -s tests); done
```

> ⚠️ Use these tools only on systems, networks and logs you own or are explicitly authorized to assess.
