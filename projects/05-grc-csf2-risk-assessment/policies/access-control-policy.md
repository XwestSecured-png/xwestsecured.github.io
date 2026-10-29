# Access Control Policy

| Field | Value |
|---|---|
| Policy ID | POL-AC-002 |
| Version | 1.0 (template) |
| Owner | IT Director |
| Framework mapping | NIST CSF 2.0 PR.AA-01–06 · NIST SP 800-63B-4 · CIS Controls v8.1 Controls 5 & 6 · NIST SP 800-53 AC-2, AC-6, IA-2, IA-5 |

## 1. Principles
- **Least privilege.** People get only the access their role needs, and only for as long as they need it.
- **Unique identities.** Every person has their own named account. Shared and generic logins are prohibited unless a documented exception exists (for example, a kiosk with no data access).
- **Separation of privileged access.** Administrators use a separate admin account that has no email or web browsing.

## 2. Account lifecycle
| Event | Requirement | Timeline |
|---|---|---|
| Onboarding | Access requested by the manager and approved by the system owner, using role-based templates | Before start date |
| Role change | Access no longer needed is removed and new access is approved | Within 5 business days |
| Termination | All accounts disabled, sessions and tokens revoked, devices recovered | **Same day** (immediately for involuntary termination) |
| Inactivity | Accounts unused for 45 days are disabled | Automated |
| Access review | Managers recertify their team's access. Privileged access is reviewed **quarterly** and all other access twice a year | Scheduled |

## 3. Authentication (aligned with NIST SP 800-63B-4)
| Requirement | Standard |
|---|---|
| MFA | Required for all users on email, cloud apps, VPN and remote access. **Phishing-resistant** MFA (FIDO2/WebAuthn passkeys, security keys, or certificate-based) is required for administrators and finance staff |
| Password length | At least **15 characters** when a password is the only factor; at least **8** when used as part of MFA. Accept at least 64 characters and allow spaces and all printable characters |
| Composition rules | **None.** Don't require mixes of character types |
| Rotation | **No periodic expiry.** Change only when there's evidence of compromise |
| Blocklist | New passwords are screened against breached, common and context-specific words (organization name, username) |
| Throttling | Failed attempts are rate-limited and lockout is configured, so brute force and spraying are throttled |
| Password manager | An organization-provided password manager is required for storing work credentials |
| Legacy authentication | Protocols that can't do MFA (POP, IMAP, SMTP AUTH basic) are blocked |

## 4. Privileged access
- Admin accounts are listed in the privileged access inventory and reviewed every quarter.
- Domain/Global Admin membership is kept to a minimum (target: 2–4 people), with break-glass accounts stored offline and monitored.
- Admin work is done from a management network or privileged access workstation through a bastion. Admin protocols are never exposed to the internet.
- Every privileged action is logged and forwarded to the SIEM.

## 5. Remote & third-party access
Vendors get time-bound, named accounts with MFA. Their sessions are brokered through a remote access gateway and recorded where possible. Vendor access is disabled when the contract ends.

## 6. Monitoring
Failed logins, MFA fatigue patterns, impossible travel, and changes to privileged groups are alerted on. The detections in Projects 01 and 03 apply here.
