-- =============================================================================
-- 01 Schema: client case-management database for a multi-site nonprofit
-- All objects live in dedicated schemas (never "public"). Data is synthetic.
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA app;     -- business data
CREATE SCHEMA audit;   -- tamper-resistant audit trail

CREATE TABLE app.sites (
    site_id   int PRIMARY KEY,
    name      text NOT NULL
);

CREATE TABLE app.staff (
    staff_id  int PRIMARY KEY,
    db_role   text UNIQUE NOT NULL,          -- maps a database login to a person
    full_name text NOT NULL,
    site_id   int NOT NULL REFERENCES app.sites,
    title     text NOT NULL,
    active    boolean NOT NULL DEFAULT true
);

CREATE TABLE app.clients (
    client_id     int PRIMARY KEY,
    site_id       int NOT NULL REFERENCES app.sites,
    first_name    text NOT NULL,
    last_name     text NOT NULL,
    date_of_birth date NOT NULL,             -- PII
    phone         text,                      -- PII
    notes_enc     bytea,                     -- sensitive case notes, encrypted (pgcrypto)
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app.clients (site_id);

CREATE TABLE app.services_provided (
    service_id   serial PRIMARY KEY,
    client_id    int NOT NULL REFERENCES app.clients,
    site_id      int NOT NULL REFERENCES app.sites,
    service_date date NOT NULL,
    service_type text NOT NULL CHECK (service_type IN ('food','housing','counseling','job-training','legal-aid'))
);
