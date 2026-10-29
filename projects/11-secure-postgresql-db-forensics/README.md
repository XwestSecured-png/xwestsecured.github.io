# Project 11: Secure PostgreSQL: Least Privilege, Row-Level Security, Tamper-Evident Auditing & Breach Forensics

**Skills shown:** secure SQL & database security · PostgreSQL roles, column privileges, row-level security · pgcrypto encryption · SECURITY DEFINER hardening · tamper-evident audit design · SQL-based breach forensics · CIS PostgreSQL Benchmark auditing

[Project 03](../03-secure-sql-and-threat-hunting/) secured SQL in application code. This project secures the **database itself**, then shows why that matters by investigating an **insider data theft** using only SQL.

The database is a multi-site client case-management system for a fictional nonprofit with 300 synthetic clients. All scripts were run and verified on **PostgreSQL 16**.

| Script | Control |
|---|---|
| [`01_schema.sql`](sql/01_schema.sql) / [`02_seed_data.sql`](sql/02_seed_data.sql) | Dedicated schemas (never `public`); synthetic PII; encrypted case notes |
| [`03_roles_least_privilege.sql`](sql/03_roles_least_privilege.sql) | Nothing granted to `PUBLIC`; NOLOGIN owner role; group vs. login roles; **column-level grants** keep PII from reporting; SCRAM-SHA-256; expiry and connection limits |
| [`04_row_level_security.sql`](sql/04_row_level_security.sql) | **FORCE ROW LEVEL SECURITY**: each caseworker only ever sees their own site, keyed to the login identity so the app can't spoof it |
| [`05_encryption_and_masking.sql`](sql/05_encryption_and_masking.sql) | **pgcrypto AES-256** column encryption (key held by the app/KMS, not the DB); de-identified demographics with **small-cell suppression** |
| [`06_audit_trail.sql`](sql/06_audit_trail.sql) | PII readable **only via audited SECURITY DEFINER functions** (pinned `search_path`); denied attempts logged; before/after DML trigger; **append-only, SHA-256 hash-chained** audit table |
| [`07_forensic_queries.sql`](sql/07_forensic_queries.sql) | 8 investigation queries: baselines, bulk access, off-hours, denials, tampering, suspect timeline, **exact breach scope**, **hash-chain verification** |
| [`08_security_audit_queries.sql`](sql/08_security_audit_queries.sql) | 8 configuration-audit queries for any PostgreSQL 13+ server, including RDS, Azure and Cloud SQL |
| [`run_lab.py`](run_lab.py) | Builds everything, **replays the incident through real role logins**, verifies 16 controls, runs the forensics and the audit |

![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791) ![SQL](https://img.shields.io/badge/SQL-RLS%20%7C%20pgcrypto%20%7C%20audit-blue) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Results

```
[*] Replaying scenario through real role logins…
    91 actions, 3 rejected by the database
[*] Verifying security controls…
    [PASS] Caseworker cannot SELECT client table directly
    [PASS] RLS: caseworker cannot read a client at another site
    [PASS] Reporting cannot read names/DOB/phone
    [PASS] Reporting demographics apply small-cell suppression
    [PASS] Audit trail is append-only (DELETE blocked even for auditor)
    [PASS] Audit trail rejects UPDATE even by its owner role
    [PASS] Caseworker cannot grant herself extra roles
    [PASS] Case notes are ciphertext at rest
    [PASS] Wrong key cannot decrypt notes
    [PASS] Lab passwords stored as SCRAM-SHA-256
    ... 16/16 PASS
    Breach scope (F7): 120 client records exposed by mallory_cw
    Audit chain (F8): INTACT (87 events)
```

### The investigation (SQL only)

A Westside caseworker logs in at **10:05 pm**, tries wildcard searches (refused), **exports all 120 of her site's client records**, probes another site 11 times (blocked by RLS), changes two clients' phone numbers, then tries to grant herself the reporting role and delete the audit log. Both attempts fail.

| Query | What it showed |
|---|---|
| **F1/F2** baseline vs. bulk | ~18 single lookups on a normal day → **121 records in one evening hour** |
| **F3** off-hours | Every suspect event fell between 22:05 and 22:40 local time |
| **F4** denials | 13 denied events, 11 of them targeting the *other* site's clients |
| **F5** tampering | Phone numbers for clients 1161 and 1162 → `555-0199`, with original values preserved for restoration |
| **F7** breach scope | **Exactly 120 clients (17 minors) at one site, 0 at the other.** This is what drives breach notification |
| **F8** integrity | Hash chain **INTACT**. In the test suite a superuser who disables the trigger and edits a row is caught: **TAMPERED** |

Full output: [`reports/forensics_report.md`](reports/forensics_report.md) · [`reports/security_audit_report.md`](reports/security_audit_report.md) · [`reports/simulation_log.csv`](reports/simulation_log.csv) · write-up: [`docs/investigation-summary.md`](docs/investigation-summary.md)

**The point:** row-level security cut the breach from 300 records to 120, and the audit design turned "we think someone took data" into a defensible, exact list of who was affected.

## Design decisions worth noting

- **Access through functions, not tables.** Caseworkers have *no* `SELECT` on `app.clients`. Every PII read goes through a `SECURITY DEFINER` function that logs the client ID, including attempts RLS blocks. The definer functions pin `search_path` to prevent hijacking (audit check S4).
- **Identity from `session_user`.** RLS keys off the database login mapped to `app.staff`, not an app-supplied setting an attacker could change.
- **Don't let exceptions eat the evidence.** An early version raised an error on wildcard searches, which rolled back the audit record of the attempt. The fix returns nothing and logs a denial.
- **Tamper-evident, not just tamper-resistant.** Grants and a trigger stop ordinary tampering. The SHA-256 hash chain catches what they can't: a superuser who disables the trigger.
- **The audit is honest about the lab.** Check S8 reports TLS and connection logging as **FAIL** on the throwaway test instance. [`docs/hardening-config.md`](docs/hardening-config.md) gives the production `postgresql.conf`, `pg_hba.conf` and pgaudit settings.

## Quick start

```bash
# Disposable local PostgreSQL 13+ (example for Debian/Ubuntu, PostgreSQL 16)
initdb -D /tmp/pgdata -A trust -U postgres
pg_ctl -D /tmp/pgdata -o "-k /tmp/pgsock -p 5433 -c listen_addresses=''" start

PGHOST=/tmp/pgsock PGPORT=5433 PGUSER=postgres python3 run_lab.py --out reports/
PGHOST=/tmp/pgsock PGPORT=5433 PGUSER=postgres python3 -m unittest discover -s tests -v   # 5 integration tests
```

`run_lab.py` drops and recreates the `caselab` database and the lab roles, so use a disposable instance only. The audit queries in `08_security_audit_queries.sql` are read-only and safe to run on any server you're authorized to assess.

## Adapting to your environment

| Situation | How |
|---|---|
| Other multi-tenant data (departments, clinics, schools, customers) | Swap `site_id` for your tenant key; the RLS pattern is identical |
| App uses one shared DB login (connection pooling) | Use `SET LOCAL app.user_id` inside a transaction plus a signed/validated mapping, or per-user roles via `SET ROLE` from a minimal pool role, and log the end-user ID in every audit record |
| Managed PostgreSQL (RDS, Azure, Cloud SQL) | All scripts work; enable pgaudit through the parameter group; export logs to CloudWatch, Azure Monitor or Cloud Logging and then the SIEM |
| SQL Server / Oracle / MySQL | Same concepts: RLS (SQL Server security policies, Oracle VPD), column grants, Always Encrypted/TDE, SQL Server Audit / Oracle Unified Auditing |

## Standards alignment

| Standard | Coverage |
|---|---|
| **CIS PostgreSQL 16 Benchmark** | Roles and privileges, logging, authentication, `search_path` safety, PUBLIC revocation |
| **NIST SP 800-53 Rev. 5** | AC-3 (enforcement, RLS), AC-6 (least privilege), AU-2/AU-9/AU-10 (audit events, protection, non-repudiation), SC-28 (encryption at rest), SI-12 |
| **NIST CSF 2.0** | PR.AA-05 (least privilege), PR.DS-01 (data at rest), DE.CM-03 (personnel activity), RS.AN-03/06/07 (forensics, evidence integrity) |
| **OWASP Top 10:2025** | A01 Broken Access Control, A04 Cryptographic Failures, A09 Security Logging & Alerting Failures |
| **HIPAA Security Rule (if PHI)** | §164.312(a) access control, (b) audit controls, (c) integrity |
| **MITRE ATT&CK** | T1213 Data from Information Repositories, T1078 Valid Accounts, T1565.001 Stored Data Manipulation, T1070 Indicator Removal (attempted) |

## Lessons learned

1. **Least privilege is measurable in records.** RLS limited the breach to one site, and that number is exactly what breach notification depends on.
2. **Log denials, not just successes.** The 13 blocked attempts showed intent, which is often what separates an investigation from a misunderstanding.
3. **Audit trails need their own threat model.** The insider tried to delete the evidence. Append-only grants, a trigger and a hash chain each defend against a different attacker.
4. **Test the controls by attacking them.** The 16 automated checks run as the real roles. A control that only exists on paper fails here.
