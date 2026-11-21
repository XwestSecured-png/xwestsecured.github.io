# Data sources: where each input comes from

| Command | Input | How to get it |
|---|---|---|
| `logs` | Linux auth log | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL); or `journalctl -u ssh --since -7d -o short-iso > auth.log` |
| | Windows Security CSV | Run `export_windows_events.ps1` (from `westguard collectors`) as an administrator; exports event IDs 4624, 4625, 4672, 4720, 4728, 4732, 4756 and 1102 |
| `endpoint` | Triage folder per host | `win_triage.ps1` (PowerShell 5.1+, admin) or `linux_triage.sh` (root). Collectors hash everything they collect; the analyzer verifies hashes first |
| `file-triage` | Files / folders | Quarantined attachments, EDR file retrievals, suspicious downloads. Keep samples in password-protected archives and analyse on an isolated host |
| `network` | Zeek `conn.log`, `dns.log` | Zeek sensor or Security Onion; TSV or JSON. Flow CSV with `ts,src_ip,src_port,dst_ip,dst_port,proto,bytes_out,bytes_in,duration` also works |
| `cloud-detect` | CloudTrail | The trail's S3 bucket: `aws s3 sync s3://<bucket>/AWSLogs/<acct>/CloudTrail/ ./ct` (`.json.gz` folders read as-is) or Event history export (JSON) |
| | Entra ID sign-ins | Entra admin center → Sign-in logs → Download JSON, or Microsoft Graph `GET /auditLogs/signIns` (needs `AuditLog.Read.All`); Graph pages and JSON arrays both load |
| `vuln` | Scanner CSV | Nessus/Tenable.sc/Tenable.io CSV, Qualys CSV, OpenVAS/Greenbone CSV, or a generic CSV with `host,cve,cvss,severity` |
| | Asset CSV | `host,ip,criticality,internet_facing,owner` from your CMDB or asset inventory |
| | KEV / EPSS | `--fetch` downloads both; for air-gapped use, download `known_exploited_vulnerabilities.json` (CISA) and `epss_scores-current.csv.gz` (FIRST) and pass `--kev/--epss` |
| `sbom`, `secrets` | Source tree | A checkout of the repository |
| `deps` | SBOM | Output of `westguard sbom` or any CycloneDX JSON |
| `firewall` | Rule set JSON | Export from your firewall manager and map to the documented schema (see `westguard firewall --help` and the sample in `data/samples/firewall/`) |
| `cloud-audit` | AWS | `collect_aws.sh` (read-only IAM, S3, EC2 describe calls; use a SecurityAudit-role profile) |
| | Entra ID | `collect_entra.ps1` (Microsoft Graph PowerShell, read-only scopes) |
| | Active Directory | `collect_ad.ps1` (RSAT ActiveDirectory module, any domain user) |
| `vendor-risk` | Vendor JSON | Questionnaire answers (SIG Lite / CAIQ style) mapped to the template fields |
| `kpi` | Metrics CSV | Monthly exports from your IdP (MFA coverage), EDR console (coverage), vulnerability tool (SLA, KEV past due), ticketing (MTTD/MTTR), phishing platform |
| `tabletop` | Responses JSON | The note-taker's record of actions named per inject |
| `intel` | TTP profile JSON | Built from advisories (CISA, ACSC, NCSC) and MITRE ATT&CK group pages |
