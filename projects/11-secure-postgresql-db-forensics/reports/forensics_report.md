# Database Security Controls & Breach Forensics: Lab Results

*Generated:* 2026-10-29 18:05 · PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

## Security control verification

| Control | Result | Evidence |
|---|---|---|
| Caseworker cannot SELECT client table directly | ✅ PASS | `ERROR:  permission denied for table clients` |
| RLS: caseworker cannot read a client at another site | ✅ PASS | `0` |
| RLS: caseworker can read own-site client | ✅ PASS | `1` |
| Reporting cannot read names/DOB/phone | ✅ PASS | `ERROR:  permission denied for table clients` |
| Reporting can read de-identified columns | ✅ PASS | `300` |
| Reporting demographics apply small-cell suppression | ✅ PASS | `t` |
| Wildcard / 1-char search returns nothing (and is logged) | ✅ PASS | `0` |
| Audit trail is append-only (DELETE blocked even for auditor) | ✅ PASS | `ERROR:  permission denied for table event` |
| Audit trail rejects UPDATE even by its owner role | ✅ PASS | `ERROR:  audit.event is append-only (UPDATE by postgres)` |
| Caseworker cannot grant herself extra roles | ✅ PASS | `ERROR:  permission denied to grant role "reporting"` |
| Caseworker cannot execute audit writer directly | ✅ PASS | `ERROR:  permission denied for schema audit` |
| Case notes are ciphertext at rest | ✅ PASS | `t` |
| Notes decrypt only with the application key | ✅ PASS | `t` |
| Wrong key cannot decrypt notes | ✅ PASS | `ERROR:  Wrong key or corrupt data` |
| PUBLIC has no privileges on app/audit tables | ✅ PASS | `0` |
| Lab passwords stored as SCRAM-SHA-256 | ✅ PASS | `t` |

## Attacker actions rejected by the database

| UTC | User | Intent | Result |
|---|---|---|---|
| 2026-10-27T02:11:00 | mallory_cw | direct table read | ERROR: permission denied for table clients |
| 2026-10-27T02:25:00 | mallory_cw | privilege escalation | ERROR: permission denied to grant role "reporting" |
| 2026-10-27T02:30:00 | mallory_cw | cover tracks | ERROR: permission denied for schema audit |

# Forensic investigation

## F1 Activity baseline per user per day

_Normal volume is what makes abnormal volume visible._

| db_user | local_day | events | single_reads | exports | denied | records_exposed |
|---|---|---|---|---|---|---|
| alice_cw | 2026-10-26 | 25 | 25 | 0 | 0 | 25 |
| bob_cw | 2026-10-26 | 21 | 20 | 0 | 0 | 23 |
| mallory_cw | 2026-10-26 | 35 | 19 | 1 | 13 | 139 |
| alice_cw | 2026-10-27 | 6 | 6 | 0 | 0 | 6 |

## F2 Bulk access: records exposed per user per hour above threshold

_Mass export is the signature of insider data theft (T1530 / T1213 equivalent for databases)._

| db_user | local_hour | records_exposed | actions |
|---|---|---|---|
| mallory_cw | 2026-10-26 22:00:00 | 121 | EXPORT,READ |

## F3 Access outside business hours (07:00-19:00 local, Mon-Fri)

_Legitimate caseworkers rarely pull client records at night._

| event_id | db_user | local_time | action | client_id | row_count |
|---|---|---|---|---|---|
| 65 | mallory_cw | Mon 2026-10-26 22:05 | DENIED |  | 0 |
| 66 | mallory_cw | Mon 2026-10-26 22:06 | DENIED |  | 0 |
| 67 | mallory_cw | Mon 2026-10-26 22:08 | EXPORT |  | 120 |
| 68 | mallory_cw | Mon 2026-10-26 22:13 | DENIED | 1001 | 0 |
| 69 | mallory_cw | Mon 2026-10-26 22:13 | DENIED | 1002 | 0 |
| 70 | mallory_cw | Mon 2026-10-26 22:13 | DENIED | 1003 | 0 |
| 71 | mallory_cw | Mon 2026-10-26 22:14 | DENIED | 1004 | 0 |
| 72 | mallory_cw | Mon 2026-10-26 22:14 | DENIED | 1005 | 0 |
| 73 | mallory_cw | Mon 2026-10-26 22:14 | DENIED | 1006 | 0 |
| 74 | mallory_cw | Mon 2026-10-26 22:15 | DENIED | 1007 | 0 |
| 75 | mallory_cw | Mon 2026-10-26 22:15 | DENIED | 1008 | 0 |
| 76 | mallory_cw | Mon 2026-10-26 22:15 | DENIED | 1009 | 0 |
| 77 | mallory_cw | Mon 2026-10-26 22:16 | DENIED | 1010 | 0 |
| 78 | mallory_cw | Mon 2026-10-26 22:20 | UPDATE | 1161 | 1 |
| 79 | mallory_cw | Mon 2026-10-26 22:21 | UPDATE | 1162 | 1 |
| 80 | mallory_cw | Mon 2026-10-26 22:22 | DENIED | 1001 | 0 |
| 81 | mallory_cw | Mon 2026-10-26 22:40 | READ | 1160 | 1 |

## F4 Denied attempts (outside own site or policy violations)

_Repeated denials show intent, i.e. probing beyond authorized scope._

| db_user | denied_attempts | client_ids | target_sites | first_local | last_local |
|---|---|---|---|---|---|
| mallory_cw | 13 | {1001,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010} | {"Eastside Center"} | 2026-10-26 22:05:00 | 2026-10-26 22:22:00 |

## F5 Record modifications with before/after values

_Tampering (e.g., changing a client's phone to divert benefits or contact) must be reversed._

| event_id | db_user | local_time | action | client_id | phone_before | phone_after |
|---|---|---|---|---|---|---|
| 78 | mallory_cw | 2026-10-26 22:20 | UPDATE | 1161 | 555-0101 | 555-0199 |
| 79 | mallory_cw | 2026-10-26 22:21 | UPDATE | 1162 | 555-0120 | 555-0199 |

## F6 Suspect timeline (mallory_cw, incident window)

_A single ordered narrative for the investigation report._

| event_id | local_time | action | object | client_id | row_count | note |
|---|---|---|---|---|---|---|
| 65 | 2026-10-26 22:05:00 | DENIED | app.search_clients |  | 0 | search term must be at least 2 characters |
| 66 | 2026-10-26 22:06:00 | DENIED | app.search_clients |  | 0 | search term must be at least 2 characters |
| 67 | 2026-10-26 22:08:00 | EXPORT | app.clients |  | 120 |  |
| 68 | 2026-10-26 22:13:00 | DENIED | app.clients | 1001 | 0 | not found or outside caller's site |
| 69 | 2026-10-26 22:13:20 | DENIED | app.clients | 1002 | 0 | not found or outside caller's site |
| 70 | 2026-10-26 22:13:40 | DENIED | app.clients | 1003 | 0 | not found or outside caller's site |
| 71 | 2026-10-26 22:14:00 | DENIED | app.clients | 1004 | 0 | not found or outside caller's site |
| 72 | 2026-10-26 22:14:20 | DENIED | app.clients | 1005 | 0 | not found or outside caller's site |
| 73 | 2026-10-26 22:14:40 | DENIED | app.clients | 1006 | 0 | not found or outside caller's site |
| 74 | 2026-10-26 22:15:00 | DENIED | app.clients | 1007 | 0 | not found or outside caller's site |
| 75 | 2026-10-26 22:15:20 | DENIED | app.clients | 1008 | 0 | not found or outside caller's site |
| 76 | 2026-10-26 22:15:40 | DENIED | app.clients | 1009 | 0 | not found or outside caller's site |
| 77 | 2026-10-26 22:16:00 | DENIED | app.clients | 1010 | 0 | not found or outside caller's site |
| 78 | 2026-10-26 22:20:00 | UPDATE | app.clients | 1161 | 1 |  |
| 79 | 2026-10-26 22:21:00 | UPDATE | app.clients | 1162 | 1 |  |
| 80 | 2026-10-26 22:22:00 | DENIED | app.clients | 1001 | 0 | update outside site |
| 81 | 2026-10-26 22:40:00 | READ | app.clients | 1160 | 1 |  |

## F7 Breach scope: distinct client records exposed by the suspect during the incident

_This number drives breach-notification decisions; it must be exact and defensible._

| site | clients_exposed | minors_exposed |
|---|---|---|
| Westside Center | 120 | 17 |
| TOTAL | 120 | 17 |

## F8 Audit trail integrity: verify the SHA-256 hash chain

_Proves the evidence was not edited or deleted after the fact._

| events_checked | altered_rows | broken_links | verdict |
|---|---|---|---|
| 87 | 0 | 0 | INTACT |
