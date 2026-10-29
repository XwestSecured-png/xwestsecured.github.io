# Investigation Summary: DB-2026-1026 Insider Data Access

| Field | Value |
|---|---|
| Case ID | DB-2026-1026 |
| Subject | `mallory_cw` (Mallory Price, Caseworker, Westside Center) |
| Window | Mon 2026-10-26 22:05–22:40 EDT |
| Evidence | `audit.event` (hash chain verified **INTACT**, 87 events), database error log, `simulation_log.csv` |
| Method | Queries F1–F8 in `sql/07_forensic_queries.sql` |

> Synthetic scenario. All people and records are fictional.

## Findings

1. **Bulk export outside business hours.** At 22:08 the subject ran `export_site_clients()` and retrieved **120 client records** (names, DOB, phone) for her whole site. Her normal daytime activity is ~18 single-record lookups a day (F1, F2, F3).
2. **Probing beyond authorized scope.** **13 denied events** in total (F4): two wildcard searches refused by input rules just before the export, then 11 attempts to read or modify clients at **Eastside Center**, which row-level security blocked.
3. **Direct table access attempted** (`SELECT … FROM app.clients`): rejected with *permission denied*, so PII is reachable only through audited functions (error log).
4. **Data tampering.** Two clients' phone numbers were changed to the same number, `555-0199`, at 22:20–22:21. Before and after values are preserved (F5), and the records were restored.
5. **Privilege escalation and anti-forensics attempted.** `GRANT reporting TO mallory_cw` and `DELETE FROM audit.event` were both rejected. The audit chain was verified intact (F8).

## Scope for notification (F7)

| Site | Client records exposed | Of which minors |
|---|---|---|
| Westside Center | **120** | **17** |
| Eastside Center | 0 (all attempts blocked by RLS) | 0 |

Because the audit trail records the exact client IDs in every export, the organization can notify **exactly** the 120 affected individuals (with guardian notification for 17 minors) instead of the whole client base of 300. This decision belongs to legal counsel under applicable state breach laws and funder agreements.

## Actions

- Account disabled, sessions terminated, `caseworker` membership revoked; HR and legal engaged; evidence preserved (audit export + hash verification result).
- Phone numbers for clients 1161 and 1162 restored from F5 "before" values; clients contacted to verify.
- **Control improvements:** an alert on `EXPORT` outside business hours and on more than 3 `DENIED` events per hour (from the F2/F3/F4 logic); restrict `export_site_clients()` to a supervisor role with a ticket reference; add pgaudit object logging on `app.clients`.

## What the controls achieved

| Control | Effect in this incident |
|---|---|
| Row-level security | Limited exposure to one site: 120 records instead of 300 |
| Audited access functions | Exact list of exposed records, so notification is precise |
| Column privileges | Direct table reads and the reporting account were useless for PII theft |
| Append-only + hash-chained audit | Attempt to delete evidence failed, and integrity is provable |
| Least-privilege roles | Self-granted privilege escalation failed |
