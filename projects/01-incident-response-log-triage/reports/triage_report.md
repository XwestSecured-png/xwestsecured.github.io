# Incident Triage Report

*Generated:* 2026-10-29T13:37:02.422751Z  
*Events parsed:* 115  
*Findings:* 11 (critical: 3, high: 3, medium: 5)

## Evidence integrity (chain of custody)

| File | SHA-256 | Bytes |
|---|---|---|
| `sample_logs/auth.log` | `69e733856353f802fb414defea9c542b12fbb7e24085b073d8068001771a68f3` | 7831 |
| `sample_logs/windows_security.csv` | `70cefd4830a764a44627e9afa205a0f7fc7e067dc46c7d5025003ac7a67f12f3` | 3339 |

## Findings

| # | Severity | Rule | Title | ATT&CK | First seen | Key entities |
|---|---|---|---|---|---|---|
| 1 | **CRITICAL** | IR-003 | Successful logon after repeated failures (possible compromise) | T1110, T1078 | 2026-10-28T02:47:00Z | src_ip=203.0.113.77, user=deploy, host=web01, prior_failures=5 |
| 2 | **CRITICAL** | IR-003 | Successful logon after repeated failures (possible compromise) | T1110, T1078 | 2026-10-28T06:30:00Z | src_ip=198.51.100.200, user=Administrator, host=DC01.corp.example, prior_failures=25 |
| 3 | **CRITICAL** | IR-007 | Security audit log cleared | T1070.001 | 2026-10-28T06:45:00Z | host=DC01.corp.example, actor=Administrator |
| 4 | **HIGH** | IR-001 | Brute-force authentication attempts | T1110.001 | 2026-10-28T02:10:00Z | src_ip=203.0.113.45 |
| 5 | **HIGH** | IR-006 | Account added to privileged group | T1098 | 2026-10-28T02:53:10Z | user=sysupdate, group=sudo, host=web01 |
| 6 | **HIGH** | IR-002 | Password spraying (one source, many accounts) | T1110.003 | 2026-10-28T03:00:00Z | src_ip=198.51.100.23, distinct_users=5 |
| 7 | **MEDIUM** | IR-004 | Successful logon outside business hours | T1078 | 2026-10-28T02:50:00Z | user=deploy, src_ip=203.0.113.77, host=web01, external_source=True |
| 8 | **MEDIUM** | IR-005 | New local/domain account created | T1136 | 2026-10-28T02:53:00Z | user=sysupdate, host=web01 |
| 9 | **MEDIUM** | IR-001 | Brute-force authentication attempts | T1110.001 | 2026-10-28T06:30:00Z | src_ip=198.51.100.200 |
| 10 | **MEDIUM** | IR-004 | Successful logon outside business hours | T1078 | 2026-10-28T06:38:00Z | user=Administrator, src_ip=198.51.100.200, host=DC01.corp.example, external_source=True |
| 11 | **MEDIUM** | IR-005 | New local/domain account created | T1136 | 2026-10-28T06:40:00Z | user=helpdesk_tmp, host=DC01.corp.example |

## Details

### 1. Successful logon after repeated failures (possible compromise) (IR-003)

- **Severity:** critical
- **MITRE ATT&CK:** T1110, T1078
- **Window:** 2026-10-28T02:47:00Z → 2026-10-28T02:50:00Z (6 events)
- **Entities:** `{"src_ip": "203.0.113.77", "user": "deploy", "host": "web01", "prior_failures": 5}`
- **Recommended action:** Treat as a likely compromised account: disable/reset credentials, revoke sessions and keys, isolate host if post-logon activity is found, and preserve evidence before remediation.

<details><summary>Evidence sample</summary>

```
Oct 28 02:47:20 web01 sshd[5561]: Failed password for deploy from 203.0.113.77 port 42001 ssh2
Oct 28 02:47:40 web01 sshd[7804]: Failed password for deploy from 203.0.113.77 port 42002 ssh2
Oct 28 02:48:00 web01 sshd[6878]: Failed password for deploy from 203.0.113.77 port 42003 ssh2
Oct 28 02:48:20 web01 sshd[7233]: Failed password for deploy from 203.0.113.77 port 42004 ssh2
Oct 28 02:50:00 web01 sshd[4780]: Accepted password for deploy from 203.0.113.77 port 42010 ssh2
```
</details>

### 2. Successful logon after repeated failures (possible compromise) (IR-003)

- **Severity:** critical
- **MITRE ATT&CK:** T1110, T1078
- **Window:** 2026-10-28T06:30:00Z → 2026-10-28T06:38:00Z (26 events)
- **Entities:** `{"src_ip": "198.51.100.200", "user": "Administrator", "host": "DC01.corp.example", "prior_failures": 25}`
- **Recommended action:** Treat as a likely compromised account: disable/reset credentials, revoke sessions and keys, isolate host if post-logon activity is found, and preserve evidence before remediation.

<details><summary>Evidence sample</summary>

```
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4624 LogonType=10
```
</details>

### 3. Security audit log cleared (IR-007)

- **Severity:** critical
- **MITRE ATT&CK:** T1070.001
- **Window:** 2026-10-28T06:45:00Z → 2026-10-28T06:45:00Z (1 events)
- **Entities:** `{"host": "DC01.corp.example", "actor": "Administrator"}`
- **Recommended action:** Indicator of anti-forensics. Pull logs from SIEM/forwarder copy, isolate host, escalate to incident commander.

<details><summary>Evidence sample</summary>

```
EventID=1102 LogonType=
```
</details>

### 4. Brute-force authentication attempts (IR-001)

- **Severity:** high
- **MITRE ATT&CK:** T1110.001
- **Window:** 2026-10-28T02:10:00Z → 2026-10-28T02:15:51Z (40 events)
- **Entities:** `{"src_ip": "203.0.113.45", "users": ["admin", "root"], "hosts": ["web01"]}`
- **Recommended action:** Block source at perimeter/host firewall, confirm no successful logon from this IP, enforce MFA and account lockout/throttling.

<details><summary>Evidence sample</summary>

```
Oct 28 02:10:00 web01 sshd[5070]: Failed password for root from 203.0.113.45 port 50000 ssh2
Oct 28 02:10:09 web01 sshd[3945]: Failed password for root from 203.0.113.45 port 50001 ssh2
Oct 28 02:10:18 web01 sshd[4999]: Failed password for root from 203.0.113.45 port 50002 ssh2
Oct 28 02:10:27 web01 sshd[2341]: Failed password for root from 203.0.113.45 port 50003 ssh2
Oct 28 02:10:36 web01 sshd[5919]: Failed password for root from 203.0.113.45 port 50004 ssh2
```
</details>

### 5. Account added to privileged group (IR-006)

- **Severity:** high
- **MITRE ATT&CK:** T1098
- **Window:** 2026-10-28T02:53:10Z → 2026-10-28T02:53:10Z (1 events)
- **Entities:** `{"user": "sysupdate", "group": "sudo", "host": "web01"}`
- **Recommended action:** Verify against approved change; remove membership and investigate the actor if unapproved.

<details><summary>Evidence sample</summary>

```
group=sudo | Oct 28 02:53:10 web01 usermod: add 'sysupdate' to group 'sudo'
```
</details>

### 6. Password spraying (one source, many accounts) (IR-002)

- **Severity:** high
- **MITRE ATT&CK:** T1110.003
- **Window:** 2026-10-28T03:00:00Z → 2026-10-28T03:08:00Z (5 events)
- **Entities:** `{"src_ip": "198.51.100.23", "distinct_users": 5, "users": ["asmith", "backup", "jdoe", "mlee", "svc_web"]}`
- **Recommended action:** Block source, review all targeted accounts for successful logons, screen passwords against a breached-password blocklist (NIST SP 800-63B-4), require phishing-resistant MFA.

<details><summary>Evidence sample</summary>

```
Oct 28 03:00:00 web01 sshd[9134]: Failed password for jdoe from 198.51.100.23 port 41000 ssh2
Oct 28 03:02:00 web01 sshd[2320]: Failed password for asmith from 198.51.100.23 port 41001 ssh2
Oct 28 03:04:00 web01 sshd[3725]: Failed password for mlee from 198.51.100.23 port 41002 ssh2
Oct 28 03:06:00 web01 sshd[8359]: Failed password for backup from 198.51.100.23 port 41003 ssh2
Oct 28 03:08:00 web01 sshd[7580]: Failed password for svc_web from 198.51.100.23 port 41004 ssh2
```
</details>

### 7. Successful logon outside business hours (IR-004)

- **Severity:** medium
- **MITRE ATT&CK:** T1078
- **Window:** 2026-10-28T02:50:00Z → 2026-10-28T02:50:00Z (1 events)
- **Entities:** `{"user": "deploy", "src_ip": "203.0.113.77", "host": "web01", "external_source": true}`
- **Recommended action:** Validate with the account owner; if unexpected, follow the compromised-account playbook.

<details><summary>Evidence sample</summary>

```
Oct 28 02:50:00 web01 sshd[4780]: Accepted password for deploy from 203.0.113.77 port 42010 ssh2
```
</details>

### 8. New local/domain account created (IR-005)

- **Severity:** medium
- **MITRE ATT&CK:** T1136
- **Window:** 2026-10-28T02:53:00Z → 2026-10-28T02:53:00Z (1 events)
- **Entities:** `{"user": "sysupdate", "host": "web01"}`
- **Recommended action:** Confirm a change ticket exists for this account; disable if unapproved.

<details><summary>Evidence sample</summary>

```
Oct 28 02:53:00 web01 useradd: new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1
```
</details>

### 9. Brute-force authentication attempts (IR-001)

- **Severity:** medium
- **MITRE ATT&CK:** T1110.001
- **Window:** 2026-10-28T06:30:00Z → 2026-10-28T06:36:00Z (25 events)
- **Entities:** `{"src_ip": "198.51.100.200", "users": ["Administrator"], "hosts": ["DC01.corp.example"]}`
- **Recommended action:** Block source at perimeter/host firewall, confirm no successful logon from this IP, enforce MFA and account lockout/throttling.

<details><summary>Evidence sample</summary>

```
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4625 LogonType=10
EventID=4625 LogonType=10
```
</details>

### 10. Successful logon outside business hours (IR-004)

- **Severity:** medium
- **MITRE ATT&CK:** T1078
- **Window:** 2026-10-28T06:38:00Z → 2026-10-28T06:38:00Z (1 events)
- **Entities:** `{"user": "Administrator", "src_ip": "198.51.100.200", "host": "DC01.corp.example", "external_source": true}`
- **Recommended action:** Validate with the account owner; if unexpected, follow the compromised-account playbook.

<details><summary>Evidence sample</summary>

```
EventID=4624 LogonType=10
```
</details>

### 11. New local/domain account created (IR-005)

- **Severity:** medium
- **MITRE ATT&CK:** T1136
- **Window:** 2026-10-28T06:40:00Z → 2026-10-28T06:40:00Z (1 events)
- **Entities:** `{"user": "helpdesk_tmp", "host": "DC01.corp.example"}`
- **Recommended action:** Confirm a change ticket exists for this account; disable if unapproved.

<details><summary>Evidence sample</summary>

```
EventID=4720 LogonType=
```
</details>
