# Project 03: Secure SQL, Injection Defense & SQL Threat Hunting

**Skills shown:** SQL (joins, aggregation, subqueries, time math) · secure coding · OWASP Top 10:2025 · threat hunting · detection engineering · Python

This project looks at SQL from both sides:

| Part | What it shows |
|---|---|
| **1. Secure coding:** `secure_coding/auth_demo.py` | Side-by-side **vulnerable vs. secure** login and search code. Five real injection attacks (auth bypass, UNION exfiltration, blind ORDER BY, error-based) succeed against one and fail against the other. |
| **2. Threat hunting:** `hunting/` | Ten documented SQL hunts over authentication, endpoint, and web logs: brute force, spray, impossible travel, compromise pivot, patch hygiene, SQLi, and attack tools. |
| **3. Detection:** `detection/detect_sqli_logs.py` | Weighted-signature SQLi detector for Apache, Nginx, and IIS logs. It decodes multi-layer URL encoding and comment obfuscation, and was tested against benign look-alikes. |
| **4. Hardening:** `docs/secure-database-checklist.md` | Vendor-neutral DB security checklist covering least privilege, TLS, encryption, auditing, and secrets. |

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![SQL](https://img.shields.io/badge/SQL-SQLite%20%7C%20PostgreSQL%20%7C%20MySQL%20%7C%20MSSQL-orange) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Standards alignment

| Standard | Coverage |
|---|---|
| **OWASP Top 10:2025** | A05 Injection (primary), A07 Authentication Failures, A01 Broken Access Control (least privilege), A04 Cryptographic Failures (password storage), A09 Security Logging & Alerting Failures |
| **CWE** | CWE-89 SQL Injection, CWE-209 Error Message Information Exposure, CWE-916 Weak Password Hash, CWE-204 Observable Response Discrepancy |
| **MITRE ATT&CK** | T1190 Exploit Public-Facing Application, T1110.001/.003, T1078 |
| **NIST SP 800-63B-4** | Password length, blocklist screening, no forced rotation |
| **NIST SP 800-53 Rev. 5** | SI-10 Input Validation, AC-6 Least Privilege, AU-2/AU-6 Audit & Review |
| **OWASP Cheat Sheets** | Query Parameterization, SQL Injection Prevention, Password Storage (scrypt parameters) |

## Part 1: Secure coding demo

```bash
python3 secure_coding/auth_demo.py
```

```
▶ Auth bypass (tautology)
  payload: ("admin' --", 'anything')
  ❌ vulnerable -> ('admin', 'admin')
  ✅ secure     -> rejected: invalid credentials / no rows

▶ UNION data exfiltration
  ❌ vulnerable -> [('admin', 'Correct-Horse-Battery-Staple-42'), ('asmith', ...), ...]
  ✅ secure     -> rejected: invalid credentials / no rows

▶ ORDER BY blind: is admin pw[1]=='C'?
  ❌ vulnerable -> [('admin', 'IT'), ('mlee', 'IT')]   <- row order leaks one bit
  ✅ secure     -> [('admin', 'IT'), ('mlee', 'IT')]   <- constant, allow-listed
...
▶ Write attempt through the read-only (least-privilege) connection:
  ✅ blocked: attempt to write a readonly database
```

Full output: [`reports/auth_demo_output.txt`](reports/auth_demo_output.txt)

**Controls in the secure version:** parameterized queries · allow-listed `ORDER BY` identifiers · scrypt password hashing with per-user salt and constant-time comparison · dummy-hash work for unknown users (stops username enumeration) · generic errors (no SQL error leakage) · length and type limits · read-only least-privilege connection.

## Part 2: SQL threat hunting

```bash
python3 lab/build_lab_db.py --db lab/soc_lab.db            # deterministic synthetic SOC data
python3 hunting/run_hunts.py --db lab/soc_lab.db --out reports/hunt_report.md
```

| Hunt | Technique | SQL concepts |
|---|---|---|
| H01 Failed logins after hours | T1110 | `WHERE`, `OR`, time ranges |
| H02 Logins from unexpected countries | T1078 | `NOT IN` |
| H03 Brute force per IP | T1110.001 | `GROUP BY`, `HAVING`, `COUNT` |
| H04 Password spray | T1110.003 | `COUNT(DISTINCT)`, conditional `SUM(CASE…)` |
| H05 Success after failures | T1078 | Correlated `EXISTS` subquery |
| H06 Impossible travel | T1078 | Self-join, date/time arithmetic |
| H07 Context enrichment | — | Multi-table `JOIN` / `LEFT JOIN` |
| H08 Unpatched devices | CIS 7 | Date math, `LEFT JOIN` |
| H09 SQLi in web logs | T1190 | `LIKE` patterns, `ESCAPE`, `GROUP_CONCAT` |
| H10 Attack tool user-agents | T1190 | `LOWER`, pattern matching |

Results: [`reports/hunt_report.md`](reports/hunt_report.md). Every planted attack was found: one spray (with one successful compromise), one impossible-travel event, and the SQLi source.

## Part 3: SQLi log detection

```bash
python3 detection/detect_sqli_logs.py detection/sample_access.log --json reports/sqli_alerts.json
```

```
[+] 318 requests analyzed, 18 SQLi alerts from 2 source(s)
  [HIGH] 203.0.113.99: 16 requests, max score 15, 5xx=6, tools=sqlmap
  [HIGH] 198.51.100.14: 2 requests, max score 12, 5xx=0, tools=-      <- manual attacker, normal UA
```

Benign look-alikes such as `?q=O'Brien jacket` and `/blog/what-is-sql-injection` are **not** flagged. A single quote scores 1, below the threshold of 5. The exit code is 1 when alerts exist, so the detector can run in cron or CI.

## Adapting to your environment

| Environment | How |
|---|---|
| PostgreSQL / MySQL / SQL Server | Queries are ANSI-style. Portability notes in each hunt cover date math (`julianday` → `EXTRACT(EPOCH…)` / `DATEDIFF`) and `ILIKE`. |
| SIEM (Splunk, Sentinel, Elastic) | Hunts translate directly: `GROUP BY/HAVING` → `stats count by … \| where`, or KQL `summarize … \| where`. |
| Real log tables | Map your columns to `log_in_attempts` / `web_requests` with a `VIEW`. The queries don't change. |
| Web servers | Apache and Nginx combined format, IIS W3C, or a plain list of URIs. |
| Your own app code | Apply the `SecureAuth` patterns. The same principles apply in Java (`PreparedStatement`), C# (`SqlParameter`), Node (`pg` `$1` placeholders), and PHP (PDO). |

## Testing

```bash
python3 -m unittest discover -s tests -v    # 12 tests: auth, injection, detector FP/TP, hunts
```

## Lessons learned

1. **Escaping is not a fix. Parameterization is.** The only reliable control separates code from data. For identifiers, use allow-lists.
2. **Blind injection needs no error messages.** The ORDER BY demo leaks data through row order alone, which is why "we hide errors" is not a defense.
3. **Least privilege limits the blast radius.** Even a missed injection can't `DELETE` or `DROP` through a read-only role.
4. **Hunting is SQL fluency.** Spray, impossible travel, and compromise pivots are all `GROUP BY`, `HAVING`, `EXISTS`, and self-joins.
5. **Tune for false positives.** Weighting signatures, rather than alerting on any `'`, kept real customer names and blog posts out of the alert queue.
