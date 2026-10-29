-- =============================================================================
-- 07 Database breach forensics: queries an investigator runs over audit.event
-- Run as an investigator role (lab: the admin account; production: auditor role plus a
-- site lookup view). Times are reported in the organization's local time zone.
-- =============================================================================

-- name: F1 Activity baseline per user per day
-- why: Normal volume is what makes abnormal volume visible.
SELECT db_user, (ts AT TIME ZONE 'America/New_York')::date AS local_day,
       count(*) AS events,
       count(*) FILTER (WHERE action = 'READ')   AS single_reads,
       count(*) FILTER (WHERE action = 'EXPORT') AS exports,
       count(*) FILTER (WHERE action = 'DENIED') AS denied,
       coalesce(sum(row_count) FILTER (WHERE action IN ('READ','SEARCH','EXPORT')), 0) AS records_exposed
FROM audit.event
GROUP BY 1, 2 ORDER BY 2, 1;

-- name: F2 Bulk access: records exposed per user per hour above threshold
-- why: Mass export is the signature of insider data theft (T1530 / T1213 equivalent for databases).
SELECT db_user, date_trunc('hour', ts AT TIME ZONE 'America/New_York') AS local_hour,
       sum(row_count) AS records_exposed, string_agg(DISTINCT action, ',') AS actions
FROM audit.event
WHERE action IN ('READ','SEARCH','EXPORT')
GROUP BY 1, 2
HAVING sum(row_count) > 50
ORDER BY records_exposed DESC;

-- name: F3 Access outside business hours (07:00-19:00 local, Mon-Fri)
-- why: Legitimate caseworkers rarely pull client records at night.
SELECT event_id, db_user, to_char(ts AT TIME ZONE 'America/New_York', 'Dy YYYY-MM-DD HH24:MI') AS local_time,
       action, client_id, row_count
FROM audit.event
WHERE action <> 'INSERT'
  AND (extract(hour FROM ts AT TIME ZONE 'America/New_York') NOT BETWEEN 7 AND 18
       OR extract(isodow FROM ts AT TIME ZONE 'America/New_York') > 5)
ORDER BY ts;

-- name: F4 Denied attempts (outside own site or policy violations)
-- why: Repeated denials show intent, i.e. probing beyond authorized scope.
SELECT e.db_user, count(*) AS denied_attempts,
       array_agg(e.client_id ORDER BY e.client_id) FILTER (WHERE e.client_id IS NOT NULL) AS client_ids,
       array_agg(DISTINCT s.name) FILTER (WHERE s.name IS NOT NULL) AS target_sites,
       min(e.ts AT TIME ZONE 'America/New_York') AS first_local, max(e.ts AT TIME ZONE 'America/New_York') AS last_local
FROM audit.event e LEFT JOIN app.clients c ON c.client_id = e.client_id LEFT JOIN app.sites s ON s.site_id = c.site_id
WHERE e.action = 'DENIED'
GROUP BY e.db_user ORDER BY denied_attempts DESC;

-- name: F5 Record modifications with before/after values
-- why: Tampering (e.g., changing a client's phone to divert benefits or contact) must be reversed.
SELECT event_id, db_user, to_char(ts AT TIME ZONE 'America/New_York', 'YYYY-MM-DD HH24:MI') AS local_time,
       action, client_id, detail->'old'->>'phone' AS phone_before, detail->'new'->>'phone' AS phone_after
FROM audit.event
WHERE action IN ('UPDATE','DELETE')
ORDER BY ts;

-- name: F6 Suspect timeline (mallory_cw, incident window)
-- why: A single ordered narrative for the investigation report.
SELECT event_id, to_char(ts AT TIME ZONE 'America/New_York', 'YYYY-MM-DD HH24:MI:SS') AS local_time,
       action, object, client_id, row_count,
       left(coalesce(detail->>'reason', detail->>'term', ''), 50) AS note
FROM audit.event
WHERE db_user = 'mallory_cw' AND ts >= '2026-10-27 01:00+00' AND ts < '2026-10-27 04:00+00'
ORDER BY ts;

-- name: F7 Breach scope: distinct client records exposed by the suspect during the incident
-- why: This number drives breach-notification decisions; it must be exact and defensible.
WITH exposed AS (
    SELECT client_id FROM audit.event
     WHERE db_user = 'mallory_cw' AND action IN ('READ','UPDATE') AND client_id IS NOT NULL
       AND ts >= '2026-10-27 01:00+00' AND ts < '2026-10-27 04:00+00'
    UNION
    SELECT jsonb_array_elements_text(detail->'client_ids')::int FROM audit.event
     WHERE db_user = 'mallory_cw' AND action IN ('SEARCH','EXPORT') AND detail ? 'client_ids'
       AND ts >= '2026-10-27 01:00+00' AND ts < '2026-10-27 04:00+00'
)
SELECT coalesce(s.name, 'TOTAL') AS site, count(*) AS clients_exposed,
       count(*) FILTER (WHERE age(c.date_of_birth) < interval '18 years') AS minors_exposed
FROM exposed x JOIN app.clients c USING (client_id) JOIN app.sites s USING (site_id)
GROUP BY ROLLUP (s.name) ORDER BY s.name NULLS LAST;

-- name: F8 Audit trail integrity: verify the SHA-256 hash chain
-- why: Proves the evidence was not edited or deleted after the fact.
WITH chain AS (
    SELECT event_id, prev_hash, row_hash,
           lag(row_hash) OVER (ORDER BY event_id) AS expected_prev,
           encode(digest(concat_ws('|', prev_hash, ts, db_user, action, object, client_id, row_count, detail::text),
                         'sha256'), 'hex') AS recomputed
    FROM audit.event
)
SELECT count(*) AS events_checked,
       count(*) FILTER (WHERE recomputed <> row_hash) AS altered_rows,
       count(*) FILTER (WHERE expected_prev IS NOT NULL AND expected_prev <> prev_hash) AS broken_links,
       CASE WHEN count(*) FILTER (WHERE recomputed <> row_hash OR (expected_prev IS NOT NULL AND expected_prev <> prev_hash)) = 0
            THEN 'INTACT' ELSE 'TAMPERED' END AS verdict
FROM chain;
