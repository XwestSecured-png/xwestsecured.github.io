# Phishing Incident: Scope & Timeline

## Exposure funnel

| Received | Clicked | Opened attachment | Submitted credentials | Compromised |
|---|---|---|---|---|
| 6 | 2 | 1 | 2 | 1 |

## Impacted users & required actions

| User | Highest stage | Stages | Action |
|---|---|---|---|
| jdoe | **compromised** | received, clicked, submitted credentials, compromised | Disable sign-in, revoke sessions/refresh tokens, reset password, re-register MFA, remove inbox rules, review mailbox audit for data access and onward phishing |
| tnguyen | **submitted credentials** | received, opened attachment, submitted credentials | Reset password, revoke sessions, confirm MFA blocked attacker, monitor sign-ins 30 days |
| mlee | **clicked** | received, clicked | Confirm no submission in proxy/EDR; targeted awareness follow-up |
| asmith | **received** | received | Message purged; no action beyond awareness |
| kpatel | **received** | received | Message purged; no action beyond awareness |
| accounts.payable | **received** | received | Message purged; no action beyond awareness |

## New IOCs discovered during scoping

Attacker infrastructure not present in the original email (found by pivoting on sign-ins). Block it, then hunt for it across all users:

- `203.0.113.88` (ipv4-addr)

## Super-timeline (UTC)

| Time | Source | User | Event | ATT&CK |
|---|---|---|---|---|
| 2026-10-27T14:03:05Z | email | - | Phish sent: 'Action Required: Payroll portal password expires today' from Corp IT Helpdesk <helpdesk@c0rp.example> (origin 203.0.113.45) | - |
| 2026-10-27T14:03:12Z | message trace | jdoe | Delivered to jdoe@corp.example | T1566 |
| 2026-10-27T14:03:12Z | message trace | asmith | Delivered to asmith@corp.example | T1566 |
| 2026-10-27T14:03:12Z | message trace | mlee | Delivered to mlee@corp.example | T1566 |
| 2026-10-27T14:03:12Z | message trace | kpatel | Delivered to kpatel@corp.example | T1566 |
| 2026-10-27T14:03:12Z | message trace | rgarcia | Quarantined for rgarcia@corp.example (no user exposure) | - |
| 2026-10-27T14:03:12Z | message trace | tnguyen | Delivered to tnguyen@corp.example | T1566 |
| 2026-10-27T14:09:44Z | proxy | jdoe | Clicked phishing link c0rp-portal.example | T1204.001 |
| 2026-10-27T14:10:31Z | proxy | jdoe | POST (credential submission) to c0rp-portal.example from 10.10.20.31 | T1566.002 → T1056.003 |
| 2026-10-27T14:12:02Z | proxy | mlee | Clicked phishing link c0rp-portal.example | T1204.001 |
| 2026-10-27T14:25:58Z | EDR WS-0102 | tnguyen | FileCreate: outlook.exe ← - (C:\Users\tnguyen\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\Payroll_Update_Nov2026.pdf.html) | T1204.002 |
| 2026-10-27T14:26:05Z | EDR WS-0102 | tnguyen | ProcessCreate: msedge.exe ← outlook.exe (C:\Users\tnguyen\...\Payroll_Update_Nov2026.pdf.html) | T1204.002 |
| 2026-10-27T14:26:40Z | proxy | tnguyen | POST (credential submission) to 198.51.100.23 from 10.10.20.102 | T1566.002 → T1056.003 |
| 2026-10-27T14:31:55Z | Entra sign-in | jdoe | SUCCESSFUL sign-in from 203.0.113.88 (NL) to Office 365 Exchange Online | T1078.004 |
| 2026-10-27T14:33:10Z | Entra sign-in | jdoe | SUCCESSFUL sign-in from 203.0.113.88 (NL) to Office 365 Exchange Online | T1078.004 |
| 2026-10-27T14:34:20Z | M365 audit | jdoe | Suspicious inbox rule created: Name='..' MoveToFolder=RSS Subscriptions; SubjectOrBodyContainsWords=payroll,invoice,bank | T1564.008 |
| 2026-10-27T14:40:02Z | Entra sign-in | tnguyen | Attacker sign-in attempt from 203.0.113.88 (NL): Failure: MFA denied | T1078.004 |
| 2026-10-27T14:41:30Z | Entra sign-in | tnguyen | Attacker sign-in attempt from 203.0.113.88 (NL): Failure: MFA denied | T1078.004 |
| 2026-10-28T16:41:22Z | email | - | Phish sent: 'RE: Invoice INV-20931 overdue - updated banking details' from Dana Whitfield <dana.whitfield@payflow-billing.example> (origin 198.51.100.77) | - |
| 2026-10-28T16:41:30Z | message trace | accounts.payable | Delivered to accounts.payable@corp.example | T1566 |
