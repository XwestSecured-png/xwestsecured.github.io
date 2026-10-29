-- =============================================================================
-- 02 Roles & least privilege (CIS PostgreSQL Benchmark-style controls)
--   * Nothing granted to PUBLIC; objects owned by a NOLOGIN owner role
--   * Group roles carry privileges; login roles only inherit them
--   * Column-level privileges keep PII away from reporting
--   * SCRAM-SHA-256 passwords, connection limits, password expiry for humans
-- =============================================================================
SET password_encryption = 'scram-sha-256';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE caselab FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app, audit FROM PUBLIC;
REVOKE ALL ON SCHEMA app, audit FROM PUBLIC;

-- Owner (no login): owns objects so day-to-day accounts can't ALTER/DROP them
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE audit_owner NOLOGIN;
-- pgcrypto lives in "public": only the two owner roles that need it may use that schema
GRANT USAGE ON SCHEMA public TO app_owner, audit_owner;
ALTER SCHEMA app OWNER TO app_owner;
ALTER TABLE app.sites OWNER TO app_owner;
ALTER TABLE app.staff OWNER TO app_owner;
ALTER TABLE app.clients OWNER TO app_owner;
ALTER TABLE app.services_provided OWNER TO app_owner;

-- Group roles (privileges live here)
CREATE ROLE caseworker NOLOGIN;      -- reads/updates clients at own site (enforced by RLS in 03)
CREATE ROLE reporting  NOLOGIN;      -- aggregate reporting, no direct PII
CREATE ROLE auditor    NOLOGIN;      -- read-only access to audit schema

GRANT CONNECT ON DATABASE caselab TO caseworker, reporting, auditor;
GRANT USAGE ON SCHEMA app TO caseworker, reporting;
GRANT USAGE ON SCHEMA audit TO auditor;

-- Caseworkers: no direct table SELECT on clients; they must use the audited access
-- functions created in 05 (SECURITY DEFINER). They may record services.
GRANT SELECT ON app.sites, app.staff TO caseworker;
GRANT SELECT, INSERT ON app.services_provided TO caseworker;
GRANT USAGE ON SEQUENCE app.services_provided_service_id_seq TO caseworker;

-- Reporting: column-level grant. No names, DOB, phone or notes.
GRANT SELECT (client_id, site_id, created_at) ON app.clients TO reporting;
GRANT SELECT ON app.services_provided, app.sites TO reporting;

-- Login roles (people and services). In production: passwords from a vault, or
-- certificate/IAM auth; pg_hba.conf restricted to app subnets with hostssl + scram-sha-256.
CREATE ROLE alice_cw   LOGIN PASSWORD 'lab-only-Alice-2026!'   CONNECTION LIMIT 5 VALID UNTIL '2027-04-30' IN ROLE caseworker;
CREATE ROLE bob_cw     LOGIN PASSWORD 'lab-only-Bob-2026!'     CONNECTION LIMIT 5 VALID UNTIL '2027-04-30' IN ROLE caseworker;
CREATE ROLE mallory_cw LOGIN PASSWORD 'lab-only-Mallory-2026!' CONNECTION LIMIT 5 VALID UNTIL '2027-04-30' IN ROLE caseworker;
CREATE ROLE reporting_svc LOGIN PASSWORD 'lab-only-Reporting-2026!' CONNECTION LIMIT 3 IN ROLE reporting;
CREATE ROLE audit_reader  LOGIN PASSWORD 'lab-only-Auditor-2026!'   CONNECTION LIMIT 2 IN ROLE auditor;
