# Operations guide

## Rollout checklist

1. **Pilot (2 weeks):** run against real exports in report-only mode; record false positives.
2. **Tune:** adjust config files / flags (`--config` for `logs`, `network`, `cloud-audit`; `--policy` for `vuln`; allow-lists such as `ALLOWED_REGIONS`, `KNOWN_EGRESS` in `cloud_rules.py`).
3. **Approve:** have the security owner sign off on which commands may gate builds or page on-call.
4. **Automate:** schedule runs (below), forward outputs to your SIEM or ticketing, set report retention.
5. **Review quarterly:** re-run `westguard demo` after upgrades; review thresholds and the audit log.

## Scheduling

**Linux cron**
```cron
# 06:15 daily: cloud detections over the previous day's CloudTrail
15 6 * * * /opt/westguard/bin/westguard --log-file /var/log/westguard.log cloud-detect --cloudtrail /data/ct/$(date -d yesterday +\%Y/\%m/\%d) --out /var/reports/cloud/$(date +\%F); [ $? -ge 2 ] && /usr/local/bin/page-oncall "WestGuard: high/critical cloud alert"
# Mondays 07:00: vulnerability prioritisation with fresh KEV/EPSS
0 7 * * 1 /opt/westguard/bin/westguard vuln --findings /data/scans/latest.csv --assets /data/cmdb/assets.csv --fetch --out /var/reports/vuln/$(date +\%F)
# Retention: keep 90 days of reports and dashboard jobs
30 3 * * * find /var/reports /var/lib/westguard/jobs -mindepth 1 -maxdepth 2 -mtime +90 -exec rm -rf {} +
```

**Windows Task Scheduler (PowerShell)**
```powershell
$a = New-ScheduledTaskAction -Execute "westguard.exe" -Argument 'logs --windows C:\Exports\security.csv --out C:\Reports\logs --fail-on high'
$t = New-ScheduledTaskTrigger -Daily -At 6:30am
Register-ScheduledTask -TaskName "WestGuard log triage" -Action $a -Trigger $t -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

## CI/CD gates (GitHub Actions)

```yaml
- run: pip install "westguard @ git+https://github.com/XwestSecured-png/xwestsecured.github.io@<commit-sha>#subdirectory=toolkit"
- run: westguard secrets . --sarif secrets.sarif          # exit 1 fails the job if secrets are found
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: secrets.sarif }
- run: westguard sbom . --out sbom.cdx.json && westguard deps sbom.cdx.json --fetch
```
Pin to a commit SHA or a wheel hash, not a branch.

## SIEM integration

- **Sigma:** `westguard sigma-export --out sigma/`, then convert with pySigma (`sigma convert -t splunk -p splunk_windows sigma/` or the Kusto backend for Microsoft Sentinel). Add a field-mapping pipeline for your log source add-on.
- **Findings:** every command writes JSON; ingest with your SIEM's file monitor (Splunk `monitor://`, Sentinel AMA custom logs, Elastic Filebeat) and alert on `severity` / `level`.
- **Threat intel:** import `intel` STIX 2.1 bundles into MISP or OpenCTI.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Exit 64 "input could not be parsed" | Check the file format in [data-sources.md](data-sources.md); run with `--log-level DEBUG` |
| `--yara` error | `pip install "westguard[yara]"` |
| Dashboard refuses to start on 0.0.0.0 | Intentional. Add `--allow-remote` plus TLS flags or `--behind-proxy` |
| Everyone signed out after restart | Expected: sessions are in memory |
| Exit 70 | Internal error: send the `--log-file` output and the command (without sensitive data) to the maintainer |
