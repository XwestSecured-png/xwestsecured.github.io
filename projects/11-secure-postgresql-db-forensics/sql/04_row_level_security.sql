-- =============================================================================
-- 03 Row-Level Security: a caseworker can only ever touch clients at their own site.
-- FORCE makes RLS apply even to the table owner. Policies key off the login role
-- (session_user) mapped through app.staff, so the app can't spoof another site.
-- =============================================================================
CREATE FUNCTION app.my_site() RETURNS int
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, app AS $$
    SELECT site_id FROM app.staff WHERE db_role = session_user AND active
$$;
ALTER FUNCTION app.my_site() OWNER TO app_owner;
REVOKE ALL ON FUNCTION app.my_site() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.my_site() TO caseworker;

ALTER TABLE app.clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.clients FORCE ROW LEVEL SECURITY;
ALTER TABLE app.services_provided ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.services_provided FORCE ROW LEVEL SECURITY;

-- Caseworkers: own site only, for reads and writes
CREATE POLICY cw_clients_site ON app.clients FOR ALL TO caseworker
    USING (site_id = app.my_site()) WITH CHECK (site_id = app.my_site());
CREATE POLICY cw_services_site ON app.services_provided FOR ALL TO caseworker
    USING (site_id = app.my_site()) WITH CHECK (site_id = app.my_site());

-- Reporting sees all rows, but only the columns granted in 02
CREATE POLICY rpt_clients_all ON app.clients FOR SELECT TO reporting USING (true);
CREATE POLICY rpt_services_all ON app.services_provided FOR SELECT TO reporting USING (true);

-- Owner-context functions (SECURITY DEFINER, run as app_owner) still pass through RLS
-- because of FORCE; this policy lets them act on behalf of the caller's site only.
CREATE POLICY owner_fn_site ON app.clients FOR ALL TO app_owner
    USING (site_id = app.my_site()) WITH CHECK (site_id = app.my_site());
