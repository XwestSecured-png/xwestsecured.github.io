-- =============================================================================
-- 04 Encryption & masking
--   * Case notes encrypted at column level with pgcrypto (AES-256 via OpenPGP symmetric).
--     The key is supplied by the application per call (from a secrets manager / KMS) and is
--     never stored in the database, so a stolen backup or table dump yields ciphertext only.
--   * Reporting gets de-identified demographics (age band, site) through a definer function,
--     never raw PII.
-- =============================================================================

-- Let owner-context functions serve reporting members (identity = login role, not spoofable)
DROP POLICY owner_fn_site ON app.clients;
CREATE POLICY owner_fn_site ON app.clients FOR ALL TO app_owner
    USING (site_id = app.my_site() OR pg_has_role(session_user, 'reporting', 'MEMBER'))
    WITH CHECK (site_id = app.my_site());

CREATE FUNCTION app.encrypt_note(p_note text, p_key text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $$
    SELECT pgp_sym_encrypt(p_note, p_key, 'cipher-algo=aes256, compress-algo=1, s2k-mode=3')
$$;

CREATE FUNCTION app.client_demographics()
RETURNS TABLE (site text, age_band text, clients bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, app AS $$
    SELECT s.name,
           CASE WHEN age(c.date_of_birth) < interval '18 years' THEN 'under 18'
                WHEN age(c.date_of_birth) < interval '35 years' THEN '18-34'
                WHEN age(c.date_of_birth) < interval '65 years' THEN '35-64'
                ELSE '65+' END,
           count(*)
    FROM app.clients c JOIN app.sites s USING (site_id)
    GROUP BY 1, 2
    HAVING count(*) >= 5          -- small-cell suppression: no groups that could identify people
    ORDER BY 1, 2
$$;
ALTER FUNCTION app.client_demographics() OWNER TO app_owner;
REVOKE ALL ON FUNCTION app.client_demographics() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.client_demographics() TO reporting;
