-- =============================================================================
-- 08 Database security configuration audit (read-only catalog queries)
-- Portable to any PostgreSQL 13+ instance, including managed services (RDS, Azure, Cloud SQL).
-- =============================================================================

-- name: S1 Roles with powerful attributes
-- why: Superuser, BYPASSRLS, CREATEROLE and REPLICATION should be rare and named (CIS 4.x).
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, rolcanlogin
FROM pg_roles
WHERE (rolsuper OR rolcreaterole OR rolbypassrls OR rolreplication) AND rolname !~ '^pg_'
ORDER BY rolname;

-- name: S2 Login roles: password expiry and connection limits
-- why: Human accounts should expire and be recertified; unlimited connections aid brute force.
SELECT rolname, rolvaliduntil, rolconnlimit,
       CASE WHEN rolvaliduntil IS NULL THEN 'no expiry' ELSE 'ok' END AS expiry_check,
       CASE WHEN rolconnlimit = -1 THEN 'unlimited' ELSE 'ok' END AS connlimit_check
FROM pg_roles WHERE rolcanlogin AND rolname !~ '^pg_' ORDER BY rolname;

-- name: S3 Privileges granted to PUBLIC in application schemas
-- why: Any grant to PUBLIC is a grant to every current and future login.
SELECT table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'PUBLIC' AND table_schema IN ('app','audit')
UNION ALL
SELECT n.nspname, '(schema)', 'USAGE'
FROM pg_namespace n
WHERE n.nspname IN ('app','audit','public') AND has_schema_privilege('public', n.oid, 'USAGE');

-- name: S4 SECURITY DEFINER functions and their search_path (any "NO search_path SET" is a finding)
-- why: Definer functions without SET search_path can be hijacked for privilege escalation.
SELECT n.nspname || '.' || p.proname AS function, pg_get_userbyid(p.proowner) AS owner,
       coalesce(array_to_string(p.proconfig, ','), 'NO search_path SET') AS config
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
ORDER BY 1;

-- name: S5 Tables holding PII-like columns and their RLS status
-- why: Personal data tables should be protected by row-level security (or equivalent).
SELECT c.relnamespace::regnamespace AS schema, c.relname AS table_name,
       string_agg(a.attname, ', ') AS pii_columns, c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced
FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog','information_schema')
  AND a.attname ~* '(birth|dob|phone|ssn|email|address|first_name|last_name|notes)'
GROUP BY 1, 2, 4, 5 ORDER BY 1, 2;

-- name: S6 Who can read PII columns directly
-- why: Column grants should match the data-access matrix; access should go through audited functions.
SELECT grantee, column_name, privilege_type
FROM information_schema.column_privileges
WHERE table_schema = 'app' AND table_name = 'clients'
  AND column_name IN ('first_name','last_name','date_of_birth','phone','notes_enc')
  AND grantee NOT IN ('app_owner','postgres')
ORDER BY grantee, column_name;

-- name: S7 Row-level security policies in force
-- why: Documents exactly which roles see which rows.
SELECT schemaname, tablename, policyname, roles, cmd, qual
FROM pg_policies ORDER BY tablename, policyname;

-- name: S8 Security-relevant server settings
-- why: Encryption in transit, strong password hashing and adequate logging (CIS PostgreSQL Benchmark).
SELECT name, setting,
       CASE
         WHEN name = 'password_encryption' AND setting <> 'scram-sha-256' THEN 'FAIL: use scram-sha-256'
         WHEN name = 'ssl' AND setting <> 'on' THEN 'FAIL: enable TLS'
         WHEN name IN ('log_connections','log_disconnections') AND setting <> 'on' THEN 'FAIL: enable'
         WHEN name = 'log_statement' AND setting NOT IN ('ddl','mod','all') THEN 'FAIL: at least ddl'
         WHEN name = 'shared_preload_libraries' AND setting NOT LIKE '%pgaudit%' THEN 'WARN: consider pgaudit'
         ELSE 'ok' END AS assessment
FROM pg_settings
WHERE name IN ('ssl','password_encryption','log_connections','log_disconnections','log_statement',
               'log_min_error_statement','shared_preload_libraries','listen_addresses')
ORDER BY name;
