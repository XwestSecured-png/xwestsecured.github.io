-- =============================================================================
-- Threat-Hunting Queries (SQLite dialect; portable notes inline)
-- Each block starts with "-- name:" so hunting/run_hunts.py can execute it.
-- All queries are READ-ONLY (SELECT). Run with a read-only DB role in production.
-- =============================================================================

-- name: H01 Failed logins after business hours
-- why: After-hours failures are a common early sign of credential attacks (T1110).
-- portability: PostgreSQL/MySQL/SQL Server identical; adjust time literal format if needed.
SELECT event_id, username, login_date, login_time, country, ip_address
FROM   log_in_attempts
WHERE  success = 0
  AND  (login_time >= '18:00:00' OR login_time < '07:00:00')
ORDER  BY login_date, login_time;

-- name: H02 Logins from outside the expected country
-- why: Geographic anomalies may indicate compromised credentials (T1078).
-- tune: replace 'USA' with your operating countries, e.g. NOT IN ('USA','CAN').
SELECT username, login_date, login_time, country, ip_address, success
FROM   log_in_attempts
WHERE  country NOT IN ('USA')
ORDER  BY login_date, login_time;

-- name: H03 Brute force - many failures per source IP per day
-- why: Volume of failures from one source (T1110.001).
SELECT ip_address, login_date, COUNT(*) AS failures,
       COUNT(DISTINCT username) AS distinct_users
FROM   log_in_attempts
WHERE  success = 0
GROUP  BY ip_address, login_date
HAVING COUNT(*) >= 8
ORDER  BY failures DESC;

-- name: H04 Password spray - one IP, many accounts
-- why: Few attempts per account across many accounts evades lockout (T1110.003).
SELECT ip_address, login_date,
       COUNT(DISTINCT username) AS accounts_targeted,
       SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS successes
FROM   log_in_attempts
GROUP  BY ip_address, login_date
HAVING COUNT(DISTINCT username) >= 5
   AND SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) >= 5
ORDER  BY accounts_targeted DESC;

-- name: H05 Successful login from an IP that also produced failures (possible compromise)
-- why: Pivots spray/brute-force results to accounts that actually got in.
SELECT s.username, s.login_date, s.login_time, s.ip_address, s.country
FROM   log_in_attempts s
WHERE  s.success = 1
  AND  EXISTS (SELECT 1 FROM log_in_attempts f
               WHERE f.ip_address = s.ip_address AND f.success = 0
                 AND f.login_date = s.login_date)
  AND  s.ip_address NOT LIKE '10.%';

-- name: H06 Impossible travel - same user, different countries within 2 hours
-- why: Physically implausible movement indicates session/credential theft.
-- portability: SQLite uses julianday(); PostgreSQL use EXTRACT(EPOCH FROM ...).
SELECT a.username,
       a.login_date || ' ' || a.login_time AS first_login, a.country AS first_country,
       b.login_date || ' ' || b.login_time AS second_login, b.country AS second_country,
       ROUND((julianday(b.login_date || ' ' || b.login_time)
            - julianday(a.login_date || ' ' || a.login_time)) * 24 * 60) AS minutes_apart
FROM   log_in_attempts a
JOIN   log_in_attempts b
       ON a.username = b.username AND a.event_id < b.event_id
      AND a.country <> b.country AND a.success = 1 AND b.success = 1
WHERE  (julianday(b.login_date || ' ' || b.login_time)
      - julianday(a.login_date || ' ' || a.login_time)) BETWEEN 0 AND 2.0/24;

-- name: H07 Enrich suspicious logins with employee + device context (JOIN)
-- why: Analysts need department, device and patch level to scope impact.
SELECT l.username, e.department, e.office, m.device_id, m.operating_system,
       m.os_patch_date, l.ip_address, l.country, l.success
FROM   log_in_attempts l
JOIN   employees e ON e.username = l.username
LEFT   JOIN machines m ON m.device_id = e.device_id
WHERE  l.country <> 'USA'
ORDER  BY l.login_date, l.login_time;

-- name: H08 Devices behind on patches (> 60 days) - patch hygiene hunt
-- why: Unpatched endpoints are prime initial-access targets (CIS Control 7).
SELECT m.device_id, m.operating_system, m.os_patch_date, e.username, e.department
FROM   machines m
LEFT   JOIN employees e ON e.device_id = m.device_id
WHERE  julianday('2026-10-29') - julianday(m.os_patch_date) > 60
ORDER  BY m.os_patch_date;

-- name: H09 SQL injection patterns in web requests
-- why: Detect exploitation attempts against web apps (T1190, OWASP A05:2025).
-- note: LIKE is case-insensitive for ASCII in SQLite; use ILIKE in PostgreSQL.
SELECT src_ip, COUNT(*) AS hits, MIN(ts) AS first_seen, MAX(ts) AS last_seen,
       GROUP_CONCAT(DISTINCT user_agent) AS agents,
       SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS server_errors
FROM   web_requests
WHERE  uri LIKE '%''%'           OR uri LIKE '%\%27%' ESCAPE '\'
   OR  uri LIKE '%union%select%' OR uri LIKE '% or 1=1%'
   OR  uri LIKE '%sleep(%'       OR uri LIKE '%waitfor%delay%'
   OR  uri LIKE '%@@version%'    OR uri LIKE '%--%'
GROUP  BY src_ip
ORDER  BY hits DESC;

-- name: H10 Known attack tools by User-Agent
-- why: Low-effort but high-signal; attackers often forget to change defaults.
SELECT user_agent, src_ip, COUNT(*) AS requests
FROM   web_requests
WHERE  LOWER(user_agent) LIKE '%sqlmap%' OR LOWER(user_agent) LIKE '%nikto%'
    OR LOWER(user_agent) LIKE '%nmap%'   OR LOWER(user_agent) LIKE '%masscan%'
    OR LOWER(user_agent) LIKE '%nuclei%' OR LOWER(user_agent) LIKE '%gobuster%'
GROUP  BY user_agent, src_ip;
