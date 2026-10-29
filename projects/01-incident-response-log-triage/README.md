# Project 01: Incident Response Log Triage Toolkit

**Skills shown:** log analysis · detection engineering · incident handling · MITRE ATT&CK mapping · Python automation · evidence handling

A read-only Python toolkit that ingests **Linux** (`auth.log` / `secure`) and **Windows Security** event logs, correlates authentication activity, and produces an analyst-ready report of credential attacks, compromises, persistence and anti-forensics. It also includes a playbook built on NIST SP 800-61r3, Sigma detection rules, and an Incident Handler's Journal that documents the investigation of the sample dataset.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why this project

Most breaches still involve stolen or guessed credentials. A small IT team usually can't afford a full SOC, but it can run a repeatable triage process. This toolkit gives a single analyst a fast, defensible answer to the question: *was anyone trying to get in, and did they succeed?*

## Standards alignment

| Standard | How it's applied |
|---|---|
| **NIST SP 800-61 Rev. 3** (Apr 2025) | Playbook organized around CSF 2.0 Functions (Govern / Identify / Protect → Detect / Respond / Recover) |
| **NIST CSF 2.0** | DE.CM (continuous monitoring), DE.AE (adverse event analysis), RS.AN (incident analysis), RS.MI (mitigation) |
| **NIST SP 800-63B-4** | Password guidance in remediation steps (length, blocklists, no forced rotation) |
| **CIS Controls v8.1** | 5 Account Mgmt, 6 Access Control Mgmt, 8 Audit Log Mgmt, 17 Incident Response Mgmt |
| **MITRE ATT&CK** | Every detection tagged (T1110.001, T1110.003, T1078, T1136, T1098, T1070.001) |
| **Sigma** | Portable detection rules convertible to Splunk, Elastic, Sentinel, QRadar, etc. |

## Detections

| Rule | Detects | ATT&CK | Default logic |
|---|---|---|---|
| IR-001 | Brute force | T1110.001 | ≥ 10 failures from one IP in 10 min |
| IR-002 | Password spray | T1110.003 | ≥ 5 distinct users from one IP in 30 min |
| IR-003 | Success after failures | T1110 → T1078 | ≥ 3 failures then a success from same IP in 30 min |
| IR-004 | Off-hours logon | T1078 | Success outside business hours (service accounts excluded; external sources ranked higher) |
| IR-005 | Account creation | T1136 | `useradd` / Event 4720 |
| IR-006 | Privileged group add | T1098 | `usermod`/`gpasswd` to sudo/wheel; Events 4728/4732/4756 to admin groups |
| IR-007 | Audit log cleared | T1070.001 | Event 1102 |

## Repository layout

```
01-incident-response-log-triage/
├── triage.py                       # Parser + detection engine + report writer
├── config.json                     # Environment-specific tuning (thresholds, networks, hours)
├── export_windows_events.ps1       # Read-only Windows Security log exporter
├── sample_logs/                    # Synthetic Linux + Windows logs (RFC 5737 IPs)
├── reports/                        # Example output (JSON + Markdown)
├── detections/sigma/               # SIEM-portable Sigma rules
├── playbooks/compromised-credentials-playbook.md
├── journal/incident-handlers-journal.md
└── tests/test_triage.py
```

## Quick start

```bash
# Python 3.9+; no third-party packages
python3 triage.py \
  --linux   sample_logs/auth.log \
  --windows sample_logs/windows_security.csv \
  --config  config.json \
  --out     reports/

python3 -m unittest discover -s tests -v
```

Sample console output:

```
[+] Parsed 115 events, 11 findings
    [CRITICAL] IR-003 Successful logon after repeated failures (possible compromise) :: src_ip=203.0.113.77, user=deploy, host=web01, prior_failures=5
    [CRITICAL] IR-003 Successful logon after repeated failures (possible compromise) :: src_ip=198.51.100.200, user=Administrator, host=DC01.corp.example, prior_failures=25
    [CRITICAL] IR-007 Security audit log cleared :: host=DC01.corp.example, actor=Administrator
    [HIGH    ] IR-001 Brute-force authentication attempts :: src_ip=203.0.113.45
    ...
```

See [`reports/triage_report.md`](reports/triage_report.md) for the full generated report.

## Adapting to your environment

| Environment | How to collect input |
|---|---|
| Ubuntu / Debian | `/var/log/auth.log` |
| RHEL / Rocky / Alma / Amazon Linux | `/var/log/secure` |
| systemd-only hosts | `journalctl -u ssh -u sshd _COMM=sudo -o short-iso > auth.log` (ISO timestamps are supported) |
| Windows Server / workstation | `.\export_windows_events.ps1 -Hours 24` (run elevated) |
| Domain controllers | Same script with `-ComputerName DC01`; enable Advanced Audit Policy first |
| SIEM (Splunk/Elastic/Sentinel) | Export results to CSV with the same columns, or convert the Sigma rules in `detections/sigma/` with `sigma-cli` |
| Cloud VMs (AWS/Azure/GCP) | Pull the OS log from the instance or from the cloud log service export |

Tune `config.json`:

- `internal_networks`: your RFC 1918 / VPN ranges, so external logons rank higher.
- `business_hours` + `utc_offset_hours`: your operating hours and log time zone.
- `service_accounts`: accounts that legitimately log on overnight (backup, monitoring).
- Thresholds: lower them for small, quiet environments and raise them for noisy ones.

**Automation:** `--fail-on high` returns exit code 2 when a high or critical finding exists, so the tool can run from cron, Task Scheduler, or a CI pipeline and page someone.

## Security and handling

- **Read-only.** Input files are opened for reading only. Work on copies, never on the original evidence.
- **Chain of custody.** SHA-256 hashes of every input are written into both reports.
- **Data minimization.** Real logs contain PII (usernames, IPs). Store reports according to your data-retention policy, and never commit real logs to a public repo.
- **Authorization.** Only analyze logs you are authorized to access.

## Lessons learned

See the reflection at the end of the [Incident Handler's Journal](journal/incident-handlers-journal.md#reflection--lessons-learned).
