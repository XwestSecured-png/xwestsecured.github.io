-- =============================================================================
-- 05 Tamper-evident audit trail
--   * audit.event is append-only: no UPDATE/DELETE grants, and a trigger rejects them
--     even for the owner. Each row carries a SHA-256 hash chained to the previous row,
--     so deletions or edits made by a superuser are detectable (verify in 07, F8).
--   * PII is read only through SECURITY DEFINER functions that log WHO read WHICH client,
--     including attempts blocked by row-level security.
--   * A DML trigger records before/after values for every change to client records.
-- Production complement: pgaudit (SELECT/DDL/ROLE logging) + shipping logs to a SIEM,
-- where DBAs can't modify them.
-- =============================================================================
ALTER SCHEMA audit OWNER TO audit_owner;

CREATE TABLE audit.event (
    event_id     bigserial PRIMARY KEY,
    ts           timestamptz NOT NULL,
    db_user      text NOT NULL,               -- session_user (the real login)
    client_addr  inet,
    application  text,
    action       text NOT NULL,               -- READ / SEARCH / EXPORT / DENIED / INSERT / UPDATE / DELETE
    object       text NOT NULL,
    client_id    int,
    row_count    int,
    detail       jsonb,
    prev_hash    text NOT NULL,
    row_hash     text NOT NULL
);
ALTER TABLE audit.event OWNER TO audit_owner;
CREATE INDEX ON audit.event (db_user, ts);

-- Lab clock: lets the simulation replay a realistic timeline. Writable only by superusers.
-- Remove in production (the function then always uses clock_timestamp()).
CREATE TABLE audit.lab_clock (sim_time timestamptz);
ALTER TABLE audit.lab_clock OWNER TO postgres;
REVOKE ALL ON audit.lab_clock FROM PUBLIC;
GRANT SELECT ON audit.lab_clock TO audit_owner;

CREATE FUNCTION audit.write(p_action text, p_object text, p_client int, p_rows int, p_detail jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit, public AS $$
DECLARE
    v_prev text; v_ts timestamptz; v_hash text;
BEGIN
    LOCK TABLE audit.event IN SHARE ROW EXCLUSIVE MODE;          -- serialize the hash chain
    SELECT row_hash INTO v_prev FROM audit.event ORDER BY event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    SELECT coalesce(max(sim_time), clock_timestamp()) INTO v_ts FROM audit.lab_clock;
    v_hash := encode(digest(concat_ws('|', v_prev, v_ts, session_user, p_action, p_object,
                                      p_client, p_rows, p_detail::text), 'sha256'), 'hex');
    INSERT INTO audit.event(ts, db_user, client_addr, application, action, object, client_id, row_count,
                            detail, prev_hash, row_hash)
    VALUES (v_ts, session_user, inet_client_addr(), current_setting('application_name', true),
            p_action, p_object, p_client, p_rows, p_detail, v_prev, v_hash);
END $$;
ALTER FUNCTION audit.write(text, text, int, int, jsonb) OWNER TO audit_owner;
REVOKE ALL ON FUNCTION audit.write(text, text, int, int, jsonb) FROM PUBLIC;
GRANT USAGE ON SCHEMA audit TO app_owner;          -- needed to call audit.write, nothing else
GRANT EXECUTE ON FUNCTION audit.write(text, text, int, int, jsonb) TO app_owner;

CREATE FUNCTION audit.block_modification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit.event is append-only (% by %)', TG_OP, session_user;
END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit.event
    FOR EACH STATEMENT EXECUTE FUNCTION audit.block_modification();

GRANT SELECT ON audit.event TO auditor;

-- ---- Audited access functions (the ONLY way caseworkers read PII) ----------
CREATE FUNCTION app.get_client(p_client_id int)
RETURNS TABLE (client_id int, first_name text, last_name text, date_of_birth date, phone text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app AS $$
BEGIN
    RETURN QUERY SELECT c.client_id, c.first_name, c.last_name, c.date_of_birth, c.phone
                 FROM app.clients c WHERE c.client_id = p_client_id;
    IF FOUND THEN
        PERFORM audit.write('READ', 'app.clients', p_client_id, 1, NULL);
    ELSE   -- not found OR blocked by RLS (another site): both are worth recording
        PERFORM audit.write('DENIED', 'app.clients', p_client_id, 0,
                            jsonb_build_object('reason', 'not found or outside caller''s site'));
    END IF;
END $$;

CREATE FUNCTION app.search_clients(p_last_name_prefix text)
RETURNS TABLE (client_id int, first_name text, last_name text, phone text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app AS $$
DECLARE v_ids int[];
BEGIN
    IF length(coalesce(p_last_name_prefix, '')) < 2 THEN
        -- Return nothing instead of raising: an exception would roll back the audit record too.
        PERFORM audit.write('DENIED', 'app.search_clients', NULL, 0,
                            jsonb_build_object('reason', 'search term must be at least 2 characters',
                                               'term', p_last_name_prefix));
        RETURN;
    END IF;
    RETURN QUERY SELECT c.client_id, c.first_name, c.last_name, c.phone FROM app.clients c
                 WHERE c.last_name ILIKE p_last_name_prefix || '%' ORDER BY c.last_name LIMIT 25;
    SELECT array_agg(c.client_id) INTO v_ids FROM app.clients c
     WHERE c.last_name ILIKE p_last_name_prefix || '%';
    PERFORM audit.write('SEARCH', 'app.clients', NULL, least(coalesce(cardinality(v_ids), 0), 25),
                        jsonb_build_object('term', p_last_name_prefix, 'client_ids', v_ids[1:25]));
END $$;

CREATE FUNCTION app.export_site_clients()
RETURNS TABLE (client_id int, first_name text, last_name text, date_of_birth date, phone text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app AS $$
DECLARE v_ids int[];
BEGIN
    SELECT array_agg(c.client_id ORDER BY c.client_id) INTO v_ids FROM app.clients c;
    RETURN QUERY SELECT c.client_id, c.first_name, c.last_name, c.date_of_birth, c.phone
                 FROM app.clients c ORDER BY c.client_id;
    PERFORM audit.write('EXPORT', 'app.clients', NULL, coalesce(cardinality(v_ids), 0),
                        jsonb_build_object('client_ids', v_ids));
END $$;

CREATE FUNCTION app.update_client_phone(p_client_id int, p_phone text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app AS $$
BEGIN
    UPDATE app.clients SET phone = p_phone WHERE client_id = p_client_id;
    IF NOT FOUND THEN
        PERFORM audit.write('DENIED', 'app.clients', p_client_id, 0, jsonb_build_object('reason', 'update outside site'));
    END IF;
END $$;

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['app.get_client(int)', 'app.search_clients(text)', 'app.export_site_clients()',
                             'app.update_client_phone(int, text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO app_owner', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO caseworker', f);
    END LOOP;
END $$;

-- ---- Row-change trigger: before/after for every INSERT/UPDATE/DELETE on clients ----
CREATE FUNCTION audit.client_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit AS $$
BEGIN
    PERFORM audit.write(TG_OP, 'app.clients', coalesce(NEW.client_id, OLD.client_id), 1,
        jsonb_build_object('old', CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) - 'notes_enc' END,
                           'new', CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) - 'notes_enc' END));
    RETURN coalesce(NEW, OLD);
END $$;
ALTER FUNCTION audit.client_change() OWNER TO audit_owner;
CREATE TRIGGER clients_audit AFTER INSERT OR UPDATE OR DELETE ON app.clients
    FOR EACH ROW EXECUTE FUNCTION audit.client_change();
