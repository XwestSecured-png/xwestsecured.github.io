# Project 14: Cloud Threat Detection Engineering (Detection as Code)

**Skills shown:** detection engineering · AWS CloudTrail · Microsoft Entra ID sign-in logs · Sigma (including correlation rules) · pySigma → Splunk SPL · MITRE ATT&CK Cloud matrix · detection unit testing · false-positive tuning · cloud incident triage

Most breaches now involve cloud identities rather than malware. This project builds 13 cloud detections the way mature security teams do: **as code**, with metadata, ATT&CK mapping, documented false positives, and **unit tests that prove each rule fires on the attack and stays quiet on the look-alike benign event**. The rules export to standard Sigma, so they run in Splunk, Microsoft Sentinel or Elastic.

| Component | What it does |
|---|---|
| [`detections/rules.py`](detections/rules.py) | 13 rules with metadata, Sigma-style detection logic, and positive/negative test fixtures |
| [`detections/sigma_lite.py`](detections/sigma_lite.py) | Small Sigma evaluator (field modifiers, boolean conditions, `event_count` / `value_count` correlation over sliding windows) so rules can be tested in Python |
| [`detections/engine.py`](detections/engine.py) | Runs every rule over CloudTrail (JSONL or native `{"Records": [...]}`) and Entra ID sign-in logs; writes an [alert timeline](reports/alerts.md) |
| [`sigma/`](sigma/) | 12 exported Sigma rules (correlation rules use the Sigma v2 correlation format). All parse and convert with **pySigma** |
| [`reports/splunk_queries.md`](reports/splunk_queries.md) | Splunk SPL generated from the Sigma rules by pySigma |
| [`data/generate.py`](data/generate.py) | Seeded generator for schema-accurate synthetic logs: 2 days of benign activity plus a planted two-part intrusion |

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Sigma](https://img.shields.io/badge/Sigma-v2%20correlations-green) ![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Cloud-red) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## The planted intrusion and what caught it

1,049 CloudTrail events and 138 sign-ins; 48 of them are attacker activity. **All 13 rules fired on the attack, with zero alerts on benign activity** (17 alerts total).

| Time (UTC) | Attacker action | Rule | ATT&CK |
|---|---|---|---|
| 06:02 | Password spray from one IP against 14 accounts | CLD-010 Password spray (`value_count`) | T1110.003 |
| 14:10 | Seven MFA push requests to jordan.lee until he approves | CLD-011 MFA fatigue (`event_count`) | T1621 |
| 14:17 | jordan.lee signs in from Bucharest 1.2 h after Atlanta (7,373 km/h) | CLD-013 Impossible travel | T1078.004 |
| 14:30 | Sprayed password reused over IMAP for casey.ford (no MFA possible) | CLD-012 Legacy auth success | T1078.004 |
| 15:00 | Leaked `ci-deploy` access key enumerates services; 10 calls denied | CLD-009 AccessDenied burst | T1580 |
| 15:08 | Attaches `AdministratorAccess` to itself | CLD-005 Admin policy attached | T1098.003 |
| 15:11 | Creates `backup-admin` and gives it a console password | CLD-006 Login profile created | T1098.001 |
| 15:13 | Stops the organization CloudTrail | CLD-003 CloudTrail tampering | T1562.008 |
| 15:14 | Deletes the GuardDuty detector | CLD-004 GuardDuty disabled | T1562.001 |
| 15:20 | Logs in to the console as `backup-admin` without MFA | CLD-002 Console login without MFA | T1078.004 |
| 15:23 | Launches 30 GPU instances in `ap-southeast-3` (crypto mining) | CLD-008 Unapproved region | T1578.002, T1496 |
| 15:30 | Removes S3 public access block and makes the finance bucket public | CLD-007 S3 opened to everyone | T1530 |
| 20:00 | Root console login (unrelated break-glass use; always reviewed) | CLD-001 Root login | T1078.004 |

**Benign look-alikes that correctly did *not* alert:** an admin attaching `ReadOnlyAccess`, a user who mistyped a password once, a pipeline role launching instances in `us-east-1`, a Lambda with one AccessDenied, MFA-backed console logins, and a legitimate Atlanta → New York business trip.

## Example rule (Sigma, exported)

```yaml
title: Entra ID MFA fatigue (repeated push denials)
logsource: {product: azure, service: signinlogs}
detection:
    sel:
        status.errorCode: 500121
    condition: sel
level: high
---
title: Entra ID MFA fatigue (repeated push denials) (correlation)
correlation:
    type: event_count
    rules: [cld_011]
    group-by: [userPrincipalName]
    timespan: 10m
    condition: {gte: 5}
```

## Triage quick reference

| Alert | First three steps |
|---|---|
| Password spray / MFA fatigue | Check for any success from the same IP; revoke sessions and reset the targeted user; block the IP in Conditional Access |
| Impossible travel | Confirm with the user out of band; check for inbox rules and OAuth consents created after the sign-in; revoke refresh tokens |
| Legacy auth success | Block legacy authentication tenant-wide with Conditional Access; reset the password; review mailbox access |
| Admin policy / login profile / new user | Identify the access key and its source IP; deactivate the key; detach the policy and delete the backdoor user after evidence is preserved |
| CloudTrail or GuardDuty disabled | Re-enable immediately; treat as SEV-1; pull the last events before logging stopped from the S3 trail bucket and the 90-day Event history |
| Unapproved region / public bucket | Terminate instances (snapshot first); re-apply S3 Block Public Access; check S3 server access logs for downloads |

## Quick start

```bash
python3 data/generate.py --out data/                         # regenerate synthetic logs (seeded)
python3 detections/engine.py --cloudtrail data/cloudtrail.jsonl --signin data/entra_signins.jsonl --out reports/
python3 detections/export_sigma.py --out sigma/
python3 -m unittest discover -s tests -v                     # 7 tests (13 rules × pos/neg fixtures, end-to-end, Sigma)

pip install pysigma pysigma-backend-splunk                   # optional: SIEM conversion
python3 detections/convert_sigma.py sigma/ --out reports/splunk_queries.md
```

## Standards alignment

| Standard | Coverage |
|---|---|
| **MITRE ATT&CK (Cloud, IaaS, Identity Provider)** | T1078.004, T1110.003, T1621, T1580, T1526, T1098.001, T1098.003, T1562.001, T1562.008, T1578.002, T1496, T1530 |
| **Sigma specification v2** | Rule format, modifiers, correlation rules (`event_count`, `value_count`) |
| **CIS AWS Foundations Benchmark** | Root usage, MFA for console users, CloudTrail enabled, S3 Block Public Access |
| **CIS Microsoft 365 Foundations Benchmark** | Block legacy authentication, MFA for all users |
| **NIST CSF 2.0** | DE.CM (continuous monitoring), DE.AE (adverse event analysis) |
| **NIST SP 800-207** | Identity as the perimeter: detections centered on identity misuse |

## Adapting to your environment

- **Real logs:** point the engine at CloudTrail files exported from your trail's S3 bucket (native `Records` format works) and Entra ID sign-in logs exported from the portal or Microsoft Graph (`/auditLogs/signIns`).
- **Tune:** edit `ALLOWED_REGIONS`, correlation thresholds, and `KNOWN_EGRESS` (VPN/proxy IPs) in `rules.py`. Add allow-listed pipeline ARNs as a `filter` block.
- **Deploy to a SIEM:** convert `sigma/` with the pySigma backend for your platform and add a field-mapping pipeline for your log add-on.
- **Add a rule:** append to `RULES` with `pos`/`neg` fixtures. The tests fail until the rule fires on the attack and not on the benign case.

All account IDs, users and IPs are synthetic (AWS documentation account `111122223333`, RFC 5737 addresses, `corp.example`).
