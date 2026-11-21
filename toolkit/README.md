# WestGuard

**A read-only security operations toolkit for small and mid-sized IT and security teams.**
One install gives you 16 analysis tools for incident response, detection, vulnerability management, cloud and identity auditing, and security program reporting. Use them from the command line, a scheduler, a CI pipeline, a container, or a web dashboard.

```bash
pip install "westguard @ git+https://github.com/XwestSecured-png/xwestsecured.github.io#subdirectory=toolkit"
westguard demo --out ./demo        # runs every tool on bundled sample data (smoke test)
westguard list
```

- **Read-only by design.** Tools analyse exported logs and files; nothing changes the systems you inspect, and samples are never executed.
- **No required dependencies.** The core runs on the Python 3.9+ standard library. Optional extras add YARA, Sigma and STIX validation.
- **Offline-capable.** Only `vuln --fetch` and `deps --fetch/--registry` go online, and only when asked.
- **Automation-friendly.** Stable exit codes, JSON + Markdown (+ CSV/SARIF/STIX/Sigma where relevant) on every run.

## Commands

| Area | Command | What it does | Main input |
|---|---|---|---|
| Incident response | `logs` | Brute force, password spraying, success-after-failure takeover, new accounts, privilege grants, log clearing | Linux `auth.log`/`secure`; Windows Security log CSV ([`export_windows_events.ps1`](src/westguard/data/collectors/export_windows_events.ps1)) |
| | `endpoint` | Sysmon/process/network/persistence analysis, LSASS dumping, PsExec, mass-encryption; super-timeline CSV | Triage folders from [`win_triage.ps1`](src/westguard/data/collectors/win_triage.ps1) / [`linux_triage.sh`](src/westguard/data/collectors/linux_triage.sh) |
| | `file-triage` | Hashes, true file type, entropy, PE sections/imports, packer and masquerade checks, PowerShell/VBA deobfuscation, IOCs, YARA | Files or folders |
| Detection | `network` | Port scans, C2 beaconing, large exfiltration, DNS tunneling | Zeek `conn.log`/`dns.log` (TSV or JSON) or flow CSV |
| | `cloud-detect` | 13 detections: root login, no-MFA console login, CloudTrail/GuardDuty tampering, admin policy, public S3, odd-region EC2, AccessDenied bursts, password spray, MFA fatigue, legacy auth, impossible travel | CloudTrail (S3 `.json.gz` folders work as-is); Entra ID sign-in export |
| | `sigma-export` | Writes the cloud detections as Sigma rules (incl. correlations) for Splunk, Sentinel, Elastic via pySigma | — |
| Vulnerability mgmt | `vuln` | Prioritises scanner findings by CISA KEV, EPSS, CVSS and asset context; owner plans with SLA dates | Scanner CSV (Nessus/Tenable/Qualys-style), asset CSV |
| | `sbom` | CycloneDX 1.6 SBOM | `requirements.txt`, `package-lock.json` |
| | `deps` | Known-vulnerable components (OSV, PyPI, npm) online or from an offline snapshot | SBOM |
| | `secrets` | Hard-coded credentials; SARIF for GitHub/GitLab code scanning | Source tree |
| Audit | `firewall` | Any-any rules, exposed admin ports, shadowed/unused rules, missing logging | Vendor-neutral JSON rule set |
| | `cloud-audit` | 34 checks: root/IAM keys, public S3, open security groups, MFA strength, Conditional Access gaps, guest admins, Kerberoastable accounts, krbtgt age | Exports from [`collect_aws.sh`](src/westguard/data/collectors/collect_aws.sh), [`collect_entra.ps1`](src/westguard/data/collectors/collect_entra.ps1), [`collect_ad.ps1`](src/westguard/data/collectors/collect_ad.ps1) |
| Program | `vendor-risk` | Inherent risk × verified controls → residual score, tier, review cycle, follow-ups | Vendor questionnaire JSON ([template](src/westguard/data/templates/vendors_example.json)) |
| | `kpi` | Self-contained HTML KPI dashboard with targets, status and trends | Monthly metrics CSV + [targets](src/westguard/data/templates/targets.json) |
| | `tabletop` | Scores exercise responses and drafts the after-action report | [Exercise](src/westguard/data/templates/ransomware_exercise.json) + responses JSON |
| | `intel` | STIX 2.1 bundle and detection-coverage matrix from a threat-actor TTP profile | [Profile JSON](src/westguard/data/templates/scattered_spider_ttps.json) |

`westguard <command> --help` shows every option. `westguard collectors --out DIR` exports the read-only collection scripts. More detail on inputs: [docs/data-sources.md](docs/data-sources.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; nothing at or above the tool's threshold |
| 1 | Completed; findings (e.g. secrets found, suspicious file, alerts, `--fail-on` hit) |
| 2 | Completed; critical findings (critical firewall/cloud issues, malicious file, high/critical cloud alerts) |
| 64 | Usage or input error: bad arguments, missing or unparseable file. No traceback |
| 70 | Internal error. Run with `--log-level DEBUG --log-file wg.log` and report it |

## Install options

| Method | Command |
|---|---|
| pip (core) | `pip install "westguard @ git+https://github.com/XwestSecured-png/xwestsecured.github.io#subdirectory=toolkit"` |
| pip (all extras) | append `[all]` after `westguard` (YARA, pySigma, stix2) |
| From a release wheel | `pip install westguard-1.0.0-py3-none-any.whl` (built by CI; air-gap friendly) |
| Container | `docker build -t westguard toolkit/` then `docker run --rm -v "$PWD:/work" westguard logs --linux auth.log --out reports` |

## Dashboard

```bash
export WESTGUARD_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
westguard web                         # http://127.0.0.1:8765, sign in with the token
```

Upload evidence, run `file-triage`, `logs`, `cloud-detect`, `vuln`, `firewall`, `vendor-risk` or `kpi`, and read the report in the browser. For a shared team server, run it behind TLS: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) (Caddy) or [`deploy/westguard-web.service`](deploy/westguard-web.service) (systemd + your reverse proxy). Security controls are listed in [SECURITY.md](SECURITY.md).

## Scheduling and pipelines

```bash
# nightly cloud detections over yesterday's CloudTrail, alert if anything high/critical (exit 2)
aws s3 sync s3://org-trail/AWSLogs/111122223333/CloudTrail/us-east-1/$(date -d yesterday +%Y/%m/%d)/ ./ct
westguard cloud-detect --cloudtrail ./ct --out /var/reports/$(date +%F) || notify-oncall

# block a merge if secrets or known-vulnerable dependencies are introduced
westguard secrets . --sarif secrets.sarif
westguard sbom . --out sbom.cdx.json && westguard deps sbom.cdx.json --fetch
```

More examples (Windows Task Scheduler, GitHub Actions, SIEM import): [docs/operations.md](docs/operations.md).

## Limitations (read before relying on it)

- Detections and scoring use sensible defaults, not your baseline. **Tune thresholds** (`--config`, `--policy`, `ALLOWED_REGIONS` etc.) during a two-week pilot before acting on results automatically.
- It is an analysis toolkit, not an EDR, SIEM or vulnerability scanner. It complements those tools.
- Static file triage gives a fast first opinion; it does not replace sandbox detonation or a malware analyst.
- The dashboard is single-tenant with one shared access token. Put SSO in front of it (your reverse proxy or an identity-aware proxy) if many people will use it.
- Only analyse systems and data you are authorised to access.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v   # tests run on Python 3.9 - 3.13
bandit -r src -ll -x src/westguard/data/samples          # static security analysis
python -m build                                          # sdist + wheel
```

CI ([`.github/workflows/westguard-ci.yml`](../.github/workflows/westguard-ci.yml)) runs the test matrix, bandit, a clean-venv install with the demo smoke test, and a non-root container build. Changes: [CHANGELOG.md](CHANGELOG.md). License: MIT.
