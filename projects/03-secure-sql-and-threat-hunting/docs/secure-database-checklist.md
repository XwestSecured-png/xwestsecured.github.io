# Secure Database & Query Checklist

A vendor-neutral checklist for any SQL database (PostgreSQL, MySQL/MariaDB, Microsoft SQL Server, Oracle, SQLite, and cloud-managed versions such as Amazon RDS, Azure SQL, and Cloud SQL).

**Alignment:** OWASP Top 10:2025 (A01, A02, A04, A05, A07, A09), OWASP ASVS 5.0, NIST SP 800-53 Rev. 5 (AC-6, AU-2, SC-8, SC-28, SI-10), CIS Controls v8.1 (3, 4, 6, 8, 16), and the CIS Benchmark for your specific DBMS.

## Application code (A05 Injection)

- [ ] **Every** query that includes user-influenced data uses parameterized queries or prepared statements. This includes stored procedures, ORM `raw()` calls, and dynamic reporting.
- [ ] Identifiers that can't be parameterized (table or column names, `ORDER BY`, `ASC`/`DESC`, `LIMIT`) go through an **allow-list**, never through escaping.
- [ ] ORM helpers that accept raw fragments (`.extra()`, `text()`, `FromSqlRaw`, `whereRaw`) have been reviewed.
- [ ] Input validation (type, length, format) is applied as defense in depth. It is **not** the primary control.
- [ ] SAST in CI flags string-built SQL (Semgrep, CodeQL, Bandit `B608`). DAST/IAST runs against staging.

## Authentication & secrets (A04, A07)

- [ ] Passwords are stored with a memory-hard KDF (Argon2id, scrypt, or bcrypt; PBKDF2 where FIPS is required) with a unique salt. Never plaintext, MD5, or SHA-1.
- [ ] Password policy follows **NIST SP 800-63B-4**: at least 15 characters for single-factor (8 with MFA), passwords screened against breached-password lists, no forced periodic rotation, and no composition rules.
- [ ] Logins return generic errors, do equivalent work for unknown users, and are rate-limited.
- [ ] DB credentials live in a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault) and are rotated. None are in code, config files in git, or environment dumps.

## Least privilege (A01)

- [ ] The application connects with a **dedicated account** that has only the permissions it needs (for example `SELECT, INSERT, UPDATE` on its own schema). It is never `sa`, `root`, `postgres`, or `dbo`.
- [ ] Read-only workloads such as reporting and BI use a separate read-only role or replica.
- [ ] Dangerous features are disabled: `xp_cmdshell`, `LOAD_FILE`/`INTO OUTFILE`, `COPY ... PROGRAM`, CLR, and external scripts.
- [ ] DBA access requires MFA and goes through a PAM or bastion with session recording.

## Configuration & network (A02)

- [ ] The DB is not reachable from the internet. It accepts connections only from the app tier or management subnet (security group, firewall, private endpoint).
- [ ] TLS 1.2+ is enforced in transit (`require_secure_transport`, `ssl=on`, `Force Encryption`).
- [ ] Data is encrypted at rest (TDE, encrypted volumes, or KMS-managed keys). Backups are encrypted and restores are tested.
- [ ] Default accounts and sample databases are removed. The DBMS is patched to a supported version.
- [ ] Verbose SQL errors are never shown to end users. They are logged server-side only.

## Logging & monitoring (A09)

- [ ] Authentication successes and failures, privilege changes, DDL, and access to sensitive tables are audited (pgaudit, SQL Server Audit, MySQL Enterprise Audit or the MariaDB audit plugin).
- [ ] DB and web logs are forwarded to the SIEM. The hunts in `hunting/threat_hunting_queries.sql` (H09/H10) and `detection/detect_sqli_logs.py` run on a schedule.
- [ ] WAF in front of the web tier with SQLi rules (OWASP CRS) in blocking mode, after tuning.
- [ ] Alerting covers spikes in DB errors and 5xx responses from a single source, which is a common sign of automated injection.

## Data minimization

- [ ] Only the data you need is collected and kept. Retention periods are defined and enforced.
- [ ] Sensitive fields (SSNs, payment data, health data) are tokenized or column-encrypted, and masked in non-production copies.
