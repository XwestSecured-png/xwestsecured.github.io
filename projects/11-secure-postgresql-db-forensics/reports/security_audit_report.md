# PostgreSQL Security Configuration Audit

## S1 Roles with powerful attributes

_Superuser, BYPASSRLS, CREATEROLE and REPLICATION should be rare and named (CIS 4.x)._

| rolname | rolsuper | rolcreaterole | rolcreatedb | rolbypassrls | rolreplication | rolcanlogin |
|---|---|---|---|---|---|---|
| postgres | t | t | t | t | t | t |

## S2 Login roles: password expiry and connection limits

_Human accounts should expire and be recertified; unlimited connections aid brute force._

| rolname | rolvaliduntil | rolconnlimit | expiry_check | connlimit_check |
|---|---|---|---|---|
| alice_cw | 2027-04-30 00:00:00-04 | 5 | ok | ok |
| audit_reader |  | 2 | no expiry | ok |
| bob_cw | 2027-04-30 00:00:00-04 | 5 | ok | ok |
| mallory_cw | 2027-04-30 00:00:00-04 | 5 | ok | ok |
| postgres |  | -1 | no expiry | unlimited |
| reporting_svc |  | 3 | no expiry | ok |

## S3 Privileges granted to PUBLIC in application schemas

_Any grant to PUBLIC is a grant to every current and future login._

_no rows_

## S4 SECURITY DEFINER functions and their search_path (any "NO search_path SET" is a finding)

_Definer functions without SET search_path can be hijacked for privilege escalation._

| function | owner | config |
|---|---|---|
| app.client_demographics | app_owner | search_path=pg_catalog, app |
| app.export_site_clients | app_owner | search_path=pg_catalog, app |
| app.get_client | app_owner | search_path=pg_catalog, app |
| app.my_site | app_owner | search_path=pg_catalog, app |
| app.search_clients | app_owner | search_path=pg_catalog, app |
| app.update_client_phone | app_owner | search_path=pg_catalog, app |
| audit.client_change | audit_owner | search_path=pg_catalog, audit |
| audit.write | audit_owner | search_path=pg_catalog, audit, public |

## S5 Tables holding PII-like columns and their RLS status

_Personal data tables should be protected by row-level security (or equivalent)._

| schema | table_name | pii_columns | rls_enabled | rls_forced |
|---|---|---|---|---|
| app | clients | first_name, last_name, date_of_birth, phone, notes_enc | t | t |

## S6 Who can read PII columns directly

_Column grants should match the data-access matrix; access should go through audited functions._

_no rows_

## S7 Row-level security policies in force

_Documents exactly which roles see which rows._

| schemaname | tablename | policyname | roles | cmd | qual |
|---|---|---|---|---|---|
| app | clients | cw_clients_site | {caseworker} | ALL | (site_id = app.my_site()) |
| app | clients | owner_fn_site | {app_owner} | ALL | ((site_id = app.my_site()) OR pg_has_role(SESSION_USER, 'reporting'::name, 'MEMBER'::text)) |
| app | clients | rpt_clients_all | {reporting} | SELECT | true |
| app | services_provided | cw_services_site | {caseworker} | ALL | (site_id = app.my_site()) |
| app | services_provided | rpt_services_all | {reporting} | SELECT | true |

## S8 Security-relevant server settings

_Encryption in transit, strong password hashing and adequate logging (CIS PostgreSQL Benchmark)._

| name | setting | assessment |
|---|---|---|
| listen_addresses |  | ok |
| log_connections | off | FAIL: enable |
| log_disconnections | off | FAIL: enable |
| log_min_error_statement | error | ok |
| log_statement | none | FAIL: at least ddl |
| password_encryption | scram-sha-256 | ok |
| shared_preload_libraries |  | WARN: consider pgaudit |
| ssl | off | FAIL: enable TLS |
