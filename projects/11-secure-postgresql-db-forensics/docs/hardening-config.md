# PostgreSQL Server Hardening Configuration

The lab runs on a throwaway local instance, so the configuration audit (`S8`) correctly reports **FAIL** for TLS and connection/statement logging there. A production server should use the settings below. They are aligned with the **CIS PostgreSQL 16 Benchmark** themes and **NIST SP 800-53** AC-6, AU-2/AU-12, IA-5 and SC-8. Managed services (Amazon RDS/Aurora, Azure Database for PostgreSQL, Cloud SQL) expose the same parameters through parameter groups or flags.

## postgresql.conf

```ini
# --- Network & encryption in transit (SC-8) ---
listen_addresses = '10.20.5.10'          # private interface only; never 0.0.0.0 on an internet-facing host
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_cert_file = '/etc/postgresql/tls/server.crt'
ssl_key_file  = '/etc/postgresql/tls/server.key'

# --- Authentication (IA-5) ---
password_encryption = 'scram-sha-256'

# --- Logging (AU-2, AU-12) — ship to SIEM; DBAs must not be able to edit the copy ---
logging_collector = on
log_destination = 'csvlog'
log_connections = on
log_disconnections = on
log_statement = 'ddl'                    # role/privilege/schema changes
log_min_error_statement = 'error'        # captures "permission denied" attempts with the SQL text
log_line_prefix = '%m [%p] user=%u db=%d app=%a client=%h '
log_timezone = 'UTC'

# --- Fine-grained auditing (pgaudit) ---
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'role, ddl'                # plus object-level auditing on PII tables:
pgaudit.role = 'auditor'                 # GRANT SELECT ON app.clients TO auditor;  → every SELECT on clients is logged
pgaudit.log_parameter = on
```

## pg_hba.conf (first match wins)

```text
# TYPE   DATABASE  USER            ADDRESS          METHOD
local    all       postgres                         peer
hostssl  caselab   +caseworker     10.20.1.0/24     scram-sha-256     # app servers only
hostssl  caselab   reporting_svc   10.20.2.15/32    scram-sha-256     # BI server only
hostssl  caselab   audit_reader    10.20.9.0/28     scram-sha-256     # security team subnet
host     all       all             0.0.0.0/0        reject            # everything else, incl. non-TLS
host     all       all             ::/0             reject
```

## Operational controls

| Control | Practice |
|---|---|
| Patching | Track PostgreSQL minor releases and apply them within your vulnerability SLA (Project 02) |
| Backups | Encrypted, immutable copies; quarterly restore tests; backups are subject to the same access controls as production |
| Secrets | Application credentials and the notes encryption key in a vault/KMS, rotated; never in code (Project 07 scanner) |
| Access reviews | Quarterly recertification of `caseworker` membership against the HR roster (`app.staff.active`) |
| Separation of duties | DBAs administer the cluster, but the audit trail ships to a SIEM they can't modify; the hash chain (F8) detects in-database tampering |
