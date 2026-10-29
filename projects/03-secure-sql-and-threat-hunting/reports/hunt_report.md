# Threat Hunt Report

*Database:* `soc_lab.db` · *Run:* 2026-10-29 13:44 UTC

## Summary

| Hunt | Rows |
|---|---|
| H01 Failed logins after business hours | 20 |
| H02 Logins from outside the expected country | 10 |
| H03 Brute force - many failures per source IP per day | 2 |
| H04 Password spray - one IP, many accounts | 1 |
| H05 Successful login from an IP that also produced failures (possible compromise) | 1 |
| H06 Impossible travel - same user, different countries within 2 hours | 1 |
| H07 Enrich suspicious logins with employee + device context (JOIN) | 10 |
| H08 Devices behind on patches (> 60 days) - patch hygiene hunt | 12 |
| H09 SQL injection patterns in web requests | 1 |
| H10 Known attack tools by User-Agent | 1 |

## H01 Failed logins after business hours

_After-hours failures are a common early sign of credential attacks (T1110)._

**Rows returned:** 20

| event_id | username | login_date | login_time | country | ip_address |
|---|---|---|---|---|---|
| 843 | jordan09 | 2026-10-24 | 23:00:00 | USA | 198.51.100.9 |
| 844 | jordan09 | 2026-10-24 | 23:01:00 | USA | 198.51.100.9 |
| 845 | jordan09 | 2026-10-24 | 23:02:00 | USA | 198.51.100.9 |
| 846 | jordan09 | 2026-10-24 | 23:03:00 | USA | 198.51.100.9 |
| 847 | jordan09 | 2026-10-24 | 23:04:00 | USA | 198.51.100.9 |
| 848 | jordan09 | 2026-10-24 | 23:05:00 | USA | 198.51.100.9 |
| 849 | jordan09 | 2026-10-24 | 23:06:00 | USA | 198.51.100.9 |
| 850 | jordan09 | 2026-10-24 | 23:07:00 | USA | 198.51.100.9 |
| 851 | jordan09 | 2026-10-24 | 23:08:00 | USA | 198.51.100.9 |
| 852 | jordan09 | 2026-10-24 | 23:09:00 | USA | 198.51.100.9 |
| 853 | jordan09 | 2026-10-24 | 23:10:00 | USA | 198.51.100.9 |
| 854 | jordan09 | 2026-10-24 | 23:11:00 | USA | 198.51.100.9 |
| 855 | uri20 | 2026-10-25 | 02:00:00 | RUS | 198.51.100.77 |
| 856 | val21 | 2026-10-25 | 02:01:00 | RUS | 198.51.100.77 |
| 857 | wren22 | 2026-10-25 | 02:02:00 | RUS | 198.51.100.77 |

…5 more rows

## H02 Logins from outside the expected country

_Geographic anomalies may indicate compromised credentials (T1078)._

**Rows returned:** 10

| username | login_date | login_time | country | ip_address | success |
|---|---|---|---|---|---|
| finley05 | 2026-10-23 | 09:47:00 | NLD | 203.0.113.60 | 1 |
| uri20 | 2026-10-25 | 02:00:00 | RUS | 198.51.100.77 | 0 |
| val21 | 2026-10-25 | 02:01:00 | RUS | 198.51.100.77 | 0 |
| wren22 | 2026-10-25 | 02:02:00 | RUS | 198.51.100.77 | 0 |
| xen23 | 2026-10-25 | 02:03:00 | RUS | 198.51.100.77 | 0 |
| yael24 | 2026-10-25 | 02:04:00 | RUS | 198.51.100.77 | 0 |
| zion25 | 2026-10-25 | 02:05:00 | RUS | 198.51.100.77 | 0 |
| alex26 | 2026-10-25 | 02:06:00 | RUS | 198.51.100.77 | 0 |
| blake27 | 2026-10-25 | 02:07:00 | RUS | 198.51.100.77 | 0 |
| wren22 | 2026-10-25 | 02:15:00 | RUS | 198.51.100.77 | 1 |

## H03 Brute force - many failures per source IP per day

_Volume of failures from one source (T1110.001)._

**Rows returned:** 2

| ip_address | login_date | failures | distinct_users |
|---|---|---|---|
| 198.51.100.9 | 2026-10-24 | 12 | 1 |
| 198.51.100.77 | 2026-10-25 | 8 | 8 |

## H04 Password spray - one IP, many accounts

_Few attempts per account across many accounts evades lockout (T1110.003)._

**Rows returned:** 1

| ip_address | login_date | accounts_targeted | successes |
|---|---|---|---|
| 198.51.100.77 | 2026-10-25 | 8 | 1 |

## H05 Successful login from an IP that also produced failures (possible compromise)

_Pivots spray/brute-force results to accounts that actually got in._

**Rows returned:** 1

| username | login_date | login_time | ip_address | country |
|---|---|---|---|---|
| wren22 | 2026-10-25 | 02:15:00 | 198.51.100.77 | RUS |

## H06 Impossible travel - same user, different countries within 2 hours

_Physically implausible movement indicates session/credential theft._

**Rows returned:** 1

| username | first_login | first_country | second_login | second_country | minutes_apart |
|---|---|---|---|---|---|
| finley05 | 2026-10-23 09:05:00 | USA | 2026-10-23 09:47:00 | NLD | 42.0 |

## H07 Enrich suspicious logins with employee + device context (JOIN)

_Analysts need department, device and patch level to scope impact._

**Rows returned:** 10

| username | department | office | device_id | operating_system | os_patch_date | ip_address | country | success |
|---|---|---|---|---|---|---|---|---|
| finley05 | Sales | East-170 | d1005 | Windows 10 22H2 | 2025-10-14 | 203.0.113.60 | NLD | 1 |
| uri20 | Sales | West-210 | d1020 | macOS 15 | 2026-10-01 | 198.51.100.77 | RUS | 0 |
| val21 | Operations | South-150 | d1021 | Windows 11 24H2 | 2026-10-14 | 198.51.100.77 | RUS | 0 |
| wren22 | Marketing | North-110 | d1022 | macOS 15 | 2026-10-01 | 198.51.100.77 | RUS | 0 |
| xen23 | Operations | North-110 | d1023 | Ubuntu 24.04 LTS | 2026-10-20 | 198.51.100.77 | RUS | 0 |
| yael24 | Marketing | South-150 | d1024 | Ubuntu 24.04 LTS | 2026-10-20 | 198.51.100.77 | RUS | 0 |
| zion25 | HR | North-110 | d1025 | macOS 15 | 2026-10-01 | 198.51.100.77 | RUS | 0 |
| alex26 | Finance | West-210 | d1026 | Windows 10 22H2 | 2025-10-14 | 198.51.100.77 | RUS | 0 |
| blake27 | Marketing | South-150 | d1027 | Ubuntu 24.04 LTS | 2026-10-20 | 198.51.100.77 | RUS | 0 |
| wren22 | Marketing | North-110 | d1022 | macOS 15 | 2026-10-01 | 198.51.100.77 | RUS | 1 |

## H08 Devices behind on patches (> 60 days) - patch hygiene hunt

_Unpatched endpoints are prime initial-access targets (CIS Control 7)._

**Rows returned:** 12

| device_id | operating_system | os_patch_date | username | department |
|---|---|---|---|---|
| d1005 | Windows 10 22H2 | 2025-10-14 | finley05 | Sales |
| d1009 | Windows 10 22H2 | 2025-10-14 | jordan09 | Marketing |
| d1010 | Windows 10 22H2 | 2025-10-14 | kai10 | Sales |
| d1012 | Windows 10 22H2 | 2025-10-14 | morgan12 | Sales |
| d1026 | Windows 10 22H2 | 2025-10-14 | alex26 | Finance |
| d1028 | Windows 10 22H2 | 2025-10-14 | casey28 | IT |
| d1031 | Windows 10 22H2 | 2025-10-14 | finley31 | Finance |
| d1034 | Windows 10 22H2 | 2025-10-14 | indy34 | IT |
| d1040 | Windows 10 22H2 | 2025-10-14 | oak40 | Finance |
| d1044 | Windows 10 22H2 | 2025-10-14 | sage44 | Sales |
| d1049 | Windows 10 22H2 | 2025-10-14 | xen49 | Finance |
| d1070 | Windows 10 22H2 | 2025-10-14 | sage70 | Marketing |

## H09 SQL injection patterns in web requests

_Detect exploitation attempts against web apps (T1190, OWASP A05:2025)._

**Rows returned:** 1

| src_ip | hits | first_seen | last_seen | agents | server_errors |
|---|---|---|---|---|---|
| 203.0.113.99 | 21 | 2026-10-24 14:02:00 | 2026-10-24 14:03:20 | sqlmap/1.8 | 7 |

## H10 Known attack tools by User-Agent

_Low-effort but high-signal; attackers often forget to change defaults._

**Rows returned:** 1

| user_agent | src_ip | requests |
|---|---|---|
| sqlmap/1.8 | 203.0.113.99 | 21 |
