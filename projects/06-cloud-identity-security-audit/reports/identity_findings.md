# Cloud & Identity Security Audit

*As of:* 2026-10-29 · *Findings:* 46 (critical 10, high 19, medium 13, low 4)  
*Platforms:* AWS (23), Active Directory (11), Entra ID (12)

## AWS

| Sev | Check | Finding | Resource | Detail | Fix | Reference |
|---|---|---|---|---|---|---|
| **CRITICAL** | AWS-IAM-01 | Root account without MFA | `<root_account>` | mfa_active=false | Enable hardware/passkey MFA on root; store securely. | CIS AWS Foundations (IAM: root MFA); MITRE T1078.004 |
| **CRITICAL** | AWS-IAM-02 | Root account has access keys | `<root_account>` | active root access key | Delete root access keys; use IAM roles. | CIS AWS Foundations (IAM: no root access keys) |
| **CRITICAL** | AWS-NET-01 | Security group exposes admin/DB ports to the internet | `sg-0a1b2c3d4e5f60002 (legacy-admin)` | 0.0.0.0/0 → 3389/RDP | Remove world access; use SSM Session Manager / bastion / VPN, or restrict to known CIDRs. | CIS AWS Foundations (Networking: no 0.0.0.0/0 to admin ports); MITRE T1133 |
| **CRITICAL** | AWS-NET-01 | Security group exposes admin/DB ports to the internet | `sg-0a1b2c3d4e5f60003 (db-temp)` | ::/0 → 22/SSH, 3389/RDP, 445/SMB, 5985/WinRM, 5986/WinRM, 1433/MSSQL | Remove world access; use SSM Session Manager / bastion / VPN, or restrict to known CIDRs. | CIS AWS Foundations (Networking: no 0.0.0.0/0 to admin ports); MITRE T1133 |
| **CRITICAL** | AWS-S3-02 | S3 bucket policy is public | `ecs-website-assets-example` | PolicyStatus.IsPublic=true | Remove public principals; serve public content through CloudFront with OAC. | MITRE T1530 (Data from Cloud Storage) |
| **HIGH** | AWS-IAM-04 | Console user without MFA | `jdoe` | password_enabled, mfa_active=false | Require MFA (or move users to IAM Identity Center with SSO + MFA). | CIS AWS Foundations (IAM: MFA for console users) |
| **HIGH** | AWS-IAM-05 | Access key not rotated | `backup-svc key1` | 2096 days old | Rotate or replace with role-based temporary credentials. | CIS AWS Foundations (IAM: rotate keys ≤ 90 days) |
| **HIGH** | AWS-IAM-05 | Access key not rotated | `backup-svc key2` | 362 days old | Rotate or replace with role-based temporary credentials. | CIS AWS Foundations (IAM: rotate keys ≤ 90 days) |
| **HIGH** | AWS-IAM-05 | Access key not rotated | `former-contractor key1` | 1028 days old | Rotate or replace with role-based temporary credentials. | CIS AWS Foundations (IAM: rotate keys ≤ 90 days) |
| **HIGH** | AWS-IAM-09 | Full admin (*:*) attached directly to IAM user | `ci-deploy` | arn:aws:iam::aws:policy/AdministratorAccess | Grant admin only via roles assumed with MFA (or IAM Identity Center permission sets); attach policies to groups/roles, not users. | CIS AWS Foundations (IAM: no *:* policies); least privilege |
| **HIGH** | AWS-IAM-09 | Full admin (*:*) attached directly to IAM user | `former-contractor` | inline *:* policy | Grant admin only via roles assumed with MFA (or IAM Identity Center permission sets); attach policies to groups/roles, not users. | CIS AWS Foundations (IAM: no *:* policies); least privilege |
| **HIGH** | AWS-LOG-01 | No multi-region CloudTrail trail | `account` | 1 trails | Create an organization/multi-region trail to a locked-down logging account. | CIS AWS Foundations (Logging: CloudTrail all regions) |
| **HIGH** | AWS-S3-01 | S3 Block Public Access not fully enabled | `ecs-website-assets-example` | public_policy=True | Enable all four Block Public Access settings (account and bucket level). | CIS AWS Foundations (Storage: S3 Block Public Access) |
| **MEDIUM** | AWS-IAM-03 | Root account used recently | `<root_account>` | password_last_used=2026-10-20 | Reserve root for break-glass tasks; alert on root use. | CIS AWS Foundations (IAM: avoid root use) |
| **MEDIUM** | AWS-IAM-06 | Unused active access key | `backup-svc key2` | last used never | Deactivate and delete unused keys. | CIS AWS Foundations (IAM: disable unused credentials ≥ 45 days) |
| **MEDIUM** | AWS-IAM-06 | Unused active access key | `former-contractor key1` | last used 2025-12-14 | Deactivate and delete unused keys. | CIS AWS Foundations (IAM: disable unused credentials ≥ 45 days) |
| **MEDIUM** | AWS-IAM-08 | Stale console password | `former-contractor` | last login 2025-12-15 | Disable console access for inactive users. | CIS AWS Foundations (IAM) |
| **MEDIUM** | AWS-LOG-02 | CloudTrail log file validation disabled | `mgmt-events-us-east-1` |  | Enable log file integrity validation. | CIS AWS Foundations (Logging) |
| **MEDIUM** | AWS-S3-01 | S3 Block Public Access not fully enabled | `ecs-client-intake-exports-example` | public_policy=False | Enable all four Block Public Access settings (account and bucket level). | CIS AWS Foundations (Storage: S3 Block Public Access) |
| **LOW** | AWS-IAM-07 | User has two active access keys | `backup-svc` | 2 active keys | Keep at most one active key per user. | CIS AWS Foundations (IAM) |
| **LOW** | AWS-LOG-03 | CloudTrail logs not encrypted with KMS CMK | `mgmt-events-us-east-1` |  | Encrypt with a customer-managed KMS key. | CIS AWS Foundations (Logging) |
| **LOW** | AWS-S3-03 | S3 versioning disabled | `ecs-website-assets-example` | Versioning=Suspended | Enable versioning (and Object Lock for backups) to survive ransomware/deletion. | CSF 2.0 PR.DS-11 |
| **LOW** | AWS-S3-03 | S3 versioning disabled | `ecs-client-intake-exports-example` | Versioning=None | Enable versioning (and Object Lock for backups) to survive ransomware/deletion. | CSF 2.0 PR.DS-11 |

## Active Directory

| Sev | Check | Finding | Resource | Detail | Fix | Reference |
|---|---|---|---|---|---|---|
| **CRITICAL** | AD-KRB-02 | Kerberoastable privileged account | `svc_sql` | SPN=MSSQLSvc/sql01.corp.example:1433; pwd age 3331 days | Use gMSA for services; otherwise 25+ char random password, AES-only encryption, and remove privileged rights. | MITRE T1558.003 (Kerberoasting) |
| **CRITICAL** | AD-KRB-02 | Kerberoastable privileged account | `svc_backup` | SPN=HTTP/backup01.corp.example; pwd age 1753 days | Use gMSA for services; otherwise 25+ char random password, AES-only encryption, and remove privileged rights. | MITRE T1558.003 (Kerberoasting) |
| **HIGH** | AD-ACC-01 | Stale enabled account | `old.helpdesk` | last logon 2025-11-03 | Disable after confirming with the manager; delete after 30 days. | CIS Controls v8.1 5.3; MITRE T1078.002 |
| **HIGH** | AD-KRB-01 | krbtgt password not rotated | `krbtgt` | last set 2019-06-02 (2706 days) | Rotate krbtgt twice (allowing replication between resets) at least every 180 days and after any DA compromise. | MITRE T1558.001 (Golden Ticket) |
| **HIGH** | AD-KRB-03 | Kerberos pre-authentication disabled (AS-REP roastable) | `scanner` | DoesNotRequirePreAuth=True | Enable Kerberos pre-authentication. | MITRE T1558.004 (AS-REP Roasting) |
| **HIGH** | AD-KRB-04 | Unconstrained delegation on user account | `app_legacy` | TrustedForDelegation=True | Remove unconstrained delegation; use resource-based constrained delegation; mark admins 'sensitive and cannot be delegated'. | MITRE T1558 / T1134 |
| **HIGH** | AD-PRIV-01 | Too many Domain Admins | `Domain Admins` | 6 members: Administrator, xw-admin, svc_sql, old.helpdesk, jdoe.admin, vendor.it | Reduce to 2-4 named admin accounts; delegate with least-privileged groups; adopt a tiered admin model. | Microsoft AD tiering guidance; CIS Controls v8.1 5.4 |
| **MEDIUM** | AD-ACC-01 | Stale enabled account | `intern2024` | last logon 2024-08-15 | Disable after confirming with the manager; delete after 30 days. | CIS Controls v8.1 5.3; MITRE T1078.002 |
| **MEDIUM** | AD-PWD-01 | Privileged account with non-expiring, aged password | `Administrator` | PasswordNeverExpires; last set 2018-04-01 | Privileged passwords should be managed (PAM/LAPS) or rotated on compromise; enforce 15+ chars + MFA. | NIST SP 800-63B-4; CIS Controls v8.1 5.2 |
| **MEDIUM** | AD-PWD-01 | Privileged account with non-expiring, aged password | `svc_sql` | PasswordNeverExpires; last set 2017-09-15 | Privileged passwords should be managed (PAM/LAPS) or rotated on compromise; enforce 15+ chars + MFA. | NIST SP 800-63B-4; CIS Controls v8.1 5.2 |
| **MEDIUM** | AD-PWD-01 | Privileged account with non-expiring, aged password | `svc_backup` | PasswordNeverExpires; last set 2022-01-10 | Privileged passwords should be managed (PAM/LAPS) or rotated on compromise; enforce 15+ chars + MFA. | NIST SP 800-63B-4; CIS Controls v8.1 5.2 |

## Entra ID

| Sev | Check | Finding | Resource | Detail | Fix | Reference |
|---|---|---|---|---|---|---|
| **CRITICAL** | ENT-CA-01 | Legacy authentication not blocked | `Conditional Access` | no enabled policy blocks exchangeActiveSync + other client apps for all users | Create CA policy: All users, client apps = Exchange ActiveSync + Other clients, Grant = Block. | CISA SCuBA M365 baseline (legacy auth); MITRE T1110.003 |
| **CRITICAL** | ENT-MFA-01 | Admin without any MFA method | `exchange.admin@corp.example` | methods=none | Require MFA registration via Conditional Access; prioritize admins. | CISA SCuBA M365 baseline (Entra ID); CSF 2.0 PR.AA-03; MITRE T1078.004 |
| **CRITICAL** | ENT-PRIV-02 | Guest account holds privileged role | `it.vendor_partner.example#EXT#@corp.example` | Global Administrator | Remove privileged roles from guest/external accounts. | CISA SCuBA M365 baseline |
| **HIGH** | ENT-CA-03 | Admin roles not required to use phishing-resistant MFA | `Conditional Access` |  | CA policy: include directory roles (Global Admin, Privileged Role Admin, etc.), Grant = authentication strength 'Phishing-resistant MFA'. | CISA SCuBA M365 baseline |
| **HIGH** | ENT-MFA-01 | User without MFA registered | `frontdesk.site3@corp.example` | methods=none | Require MFA registration via Conditional Access; prioritize admins. | CISA SCuBA M365 baseline (Entra ID); CSF 2.0 PR.AA-03; MITRE T1078.004 |
| **HIGH** | ENT-MFA-02 | Admin lacks phishing-resistant MFA | `globaladmin2@corp.example` | methods=['microsoftAuthenticatorPush', 'mobilePhone'] | Register FIDO2 security keys / passkeys or WHfB; enforce 'Phishing-resistant MFA' auth strength for admin roles. | CISA SCuBA M365 baseline; OMB M-22-09; NIST SP 800-63B-4 (phishing resistance) |
| **HIGH** | ENT-PRIV-01 | Global Administrator count outside recommended range | `Global Administrator` | 6 members (policy 2-4; CISA SCuBA allows at most 8) | Use least-privileged roles (User/Exchange/Security Admin) and PIM just-in-time activation. | CISA SCuBA M365 baseline (privileged access) |
| **HIGH** | ENT-PRIV-03 | Privileged role assigned to on-prem synced account | `globaladmin2@corp.example` | Global Administrator | Use cloud-only admin accounts so an AD compromise can't escalate to the cloud tenant. | Microsoft privileged access guidance; CISA SCuBA M365 baseline |
| **HIGH** | ENT-PRIV-03 | Privileged role assigned to on-prem synced account | `ops.manager@corp.example` | Global Administrator | Use cloud-only admin accounts so an AD compromise can't escalate to the cloud tenant. | Microsoft privileged access guidance; CISA SCuBA M365 baseline |
| **MEDIUM** | ENT-CA-04 | Conditional Access policy left in report-only mode | `Block legacy authentication` | state=enabledForReportingButNotEnforced | Review sign-in impact and switch to On. | CSF 2.0 PR.AA-05 |
| **MEDIUM** | ENT-CA-05 | Conditional Access policy with many user exclusions | `Require MFA - all users` | 5 excluded users | Limit exclusions to break-glass accounts; review quarterly. | CSF 2.0 PR.AA-05 |
| **MEDIUM** | ENT-MFA-03 | User relies only on SMS/voice/email MFA | `asmith@corp.example` | methods=['mobilePhone'] | Move users to Authenticator with number matching or passkeys; SMS is vulnerable to SIM swap. | NIST SP 800-63B-4 (restricted authenticators) |
