# Playbook: Brute Force, Password Spray & Compromised Credentials

| Field | Value |
|---|---|
| Playbook ID | PB-IR-001 |
| Version | 1.0 (2026-10-29) |
| Owner | Security Operations / IT Director |
| Framework alignment | NIST SP 800-61 Rev. 3 (CSF 2.0 Detect → Respond → Recover), NIST CSF 2.0, CIS Controls v8.1 (5, 6, 8, 17), MITRE ATT&CK T1110, T1078, T1098, T1136, T1070.001 |
| Triggers | `triage.py` rules IR-001 through IR-007, SIEM correlation, EDR identity alerts, user report |

> **Scope note.** NIST SP 800-61 Rev. 3 (April 2025) retires the old four-phase lifecycle as the organizing model and instead maps incident response activities onto the six CSF 2.0 Functions. This playbook follows that structure: **Govern / Identify / Protect** are preparation, and **Detect / Respond / Recover** are the incident itself.

---

## 0. Preparation (Govern · Identify · Protect)

- [ ] Incident response roles defined (Incident Commander, Technical Lead, Communications, Legal/Privacy, Executive sponsor) with backups and an out-of-band contact list.
- [ ] Authentication logs centralized and retained (≥ 90 days hot, 1 year archive or per regulatory requirement), with time sync (NTP) on all sources.
- [ ] Windows Advanced Audit Policy enabled for *Logon*, *Special Logon*, *User Account Management*, *Security Group Management*, *Audit Policy Change*.
- [ ] Linux `sshd` `LogLevel VERBOSE`; `auth`/`authpriv` forwarded to SIEM.
- [ ] Phishing-resistant MFA (FIDO2/WebAuthn or PKI) on all remote access, admin and cloud accounts.
- [ ] Password policy per **NIST SP 800-63B-4**: ≥ 15 characters for password-only accounts (≥ 8 when used with MFA), no forced composition rules or periodic rotation, screening against breached/common-password blocklists, and change on evidence of compromise.
- [ ] Account lockout / throttling configured (e.g., Windows lockout policy, `fail2ban` or `sshd MaxAuthTries`).
- [ ] Remote admin interfaces (SSH, RDP, WinRM) are **not** exposed directly to the internet; access via VPN / ZTNA / bastion.

## 1. Detect & Analyze (Detect)

| Step | Action | Evidence to capture |
|---|---|---|
| 1.1 | Run triage across all relevant hosts: `python3 triage.py --linux <auth.log> --windows <export.csv> --config config.json` | `triage_report.json` / `.md` and SHA-256 hashes of every input |
| 1.2 | Classify the pattern: **brute force** (IR-001), **spray** (IR-002), **success after failures** (IR-003) | Source IP(s), target accounts, time window |
| 1.3 | Enrich source IPs: ASN, geolocation, threat-intel reputation, known VPN/Tor exit | Enrichment notes in ticket |
| 1.4 | Check for **any** successful logon from the attacking IPs across *all* systems (VPN, M365/Entra ID, Okta, SSH, RDP) | Query + result screenshots |
| 1.5 | If success found, review post-logon activity: `sudo` commands, process creation (4688/Sysmon 1), new accounts (IR-005), group changes (IR-006), log clearing (IR-007), outbound connections | Timeline |
| 1.6 | Assign severity using the matrix below and open/upgrade the incident ticket | Ticket ID |

**Severity matrix**

| Condition | Severity | Response time |
|---|---|---|
| Failed attempts only, blocked, no success anywhere | Low / Medium | Next business day |
| Spray against many accounts, or attempts against privileged accounts | High | 4 hours |
| Any successful logon by an attacker, privileged group change, or log clearing | **Critical** – declare incident | Immediate (≤ 1 hour) |

## 2. Contain (Respond)

**Short-term containment** – stop the bleeding, preserve evidence:

1. Block offending IPs/ranges at perimeter firewall, WAF, and host firewall (`ufw deny from <ip>` / Windows Defender Firewall rule / cloud security group).
2. **Disable** (do not delete) affected accounts; reset passwords; revoke sessions, refresh tokens, API keys and SSH `authorized_keys` entries.
3. If attacker activity occurred on a host, **network-isolate** it via EDR or switch port/VLAN — do not power off (volatile memory is evidence).
4. Collect volatile data before changes when feasible: running processes, network connections, logged-on users, memory image.

**Long-term containment** – keep business running safely:

5. Temporarily restrict the affected service to VPN/allow-listed sources.
6. Enforce MFA on any account in scope that lacked it.

## 3. Eradicate (Respond)

- Remove attacker-created accounts (e.g., `sysupdate`, `helpdesk_tmp` in the sample) and privileged group memberships.
- Remove persistence: cron jobs, systemd units, scheduled tasks, services, Run keys, web shells, unauthorized SSH keys.
- Patch / harden the exposed service (see Project 02 hardening audit).
- Hunt for the same IOCs (IPs, usernames, file hashes, user-agents) across the estate.

## 4. Recover (Recover)

- Rebuild from known-good images where integrity is in doubt; restore data from backups verified clean.
- Re-enable accounts with new credentials and MFA; monitor with heightened alerting for 30 days.
- Confirm logging is flowing from every recovered host (validate IR-007 condition cannot recur silently).

## 5. Post-Incident Activity (Govern · Identify — continuous improvement)

- Lessons-learned meeting within 5 business days; document root cause, detection gap, and time-to-detect / time-to-contain.
- Update detections (Sigma rules in `detections/sigma/`) and this playbook.
- Determine notification obligations with Legal (state breach laws, contracts, sector regulators, cyber insurance carrier).
- Track remediation items to closure in the risk register.

## Communication template (internal)

> **Subject:** [SEV-<level>] Security incident <ID> – Credential attack on <system>
> **What happened:** At <time UTC> we detected <brute-force / spray / unauthorized logon> from <source> against <system/accounts>.
> **Current status:** <Contained / Investigating>. Affected accounts disabled and source blocked.
> **Impact:** <Known / under assessment>. No evidence of data access at this time / <details>.
> **Next update:** <time>.
> **Contact:** Incident Commander <name, phone>.
