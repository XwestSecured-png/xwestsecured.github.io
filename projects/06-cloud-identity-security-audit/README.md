# Project 06: Cloud & Identity Security Audit (AWS · Entra ID / M365 · Active Directory)

**Skills shown:** cloud security posture management · identity & access management · Microsoft Entra ID Conditional Access · AWS IAM / S3 / CloudTrail · Active Directory attack paths (Kerberoasting, AS-REP, delegation) · KQL / Athena detections · Bash / PowerShell / Python

Most modern breaches don't start with an exploit. They start with a **valid account** (MITRE ATT&CK T1078). This project audits the three identity planes a typical hybrid organization runs on, using **read-only collectors** and an **offline analyzer**. It runs 34 checks and outputs a prioritized report, a 30-day hardening plan, and detections for the attacks each gap enables.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20S3%20%7C%20CloudTrail-orange) ![Entra](https://img.shields.io/badge/Entra%20ID-Conditional%20Access-0078d4) ![AD](https://img.shields.io/badge/Active%20Directory-Kerberos-555) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## How it works

```
 collectors/ (read-only)                     cloud_identity_audit.py (offline)          reports/
 ├─ collect_aws.sh     ── IAM, SG, S3, CT ─┐
 ├─ collect_entra.ps1  ── MFA, CA, roles ──┼──► 34 checks, severity, fix, reference ──► identity_findings.md / .json
 └─ collect_ad.ps1     ── users, groups ───┘
```

Splitting collection from analysis is deliberate:

- The collectors need only **read** permissions: AWS `SecurityAudit`, Graph `*.Read.All` scopes, or a standard domain user for AD.
- The analyzer needs **no credentials**, so exports can be reviewed on an isolated workstation, by an auditor, or by a consultant who never gets access to the tenant.
- Every export is hashed (SHA-256) for evidence integrity.

## Results on the sample tenant

```
[+] 46 findings (critical 10, high 19, medium 13, low 4)
    [CRITICAL] AWS              AWS-IAM-01  Root account without MFA
    [CRITICAL] AWS              AWS-NET-01  Security group exposes admin/DB ports to the internet :: sg-...0002 (legacy-admin)
    [CRITICAL] AWS              AWS-S3-02   S3 bucket policy is public :: ecs-website-assets-example
    [CRITICAL] Active Directory AD-KRB-02   Kerberoastable privileged account :: svc_sql
    [CRITICAL] Entra ID         ENT-CA-01   Legacy authentication not blocked :: Conditional Access
    [CRITICAL] Entra ID         ENT-MFA-01  Admin without any MFA method :: exchange.admin@corp.example
    [CRITICAL] Entra ID         ENT-PRIV-02 Guest account holds privileged role
    [HIGH    ] Entra ID         ENT-MFA-02  Admin lacks phishing-resistant MFA :: globaladmin2@corp.example
    [HIGH    ] Active Directory AD-KRB-01   krbtgt password not rotated
    ...
```

Full report: [`reports/identity_findings.md`](reports/identity_findings.md)

Some of the subtler cases the checks handle:

- A "Block legacy authentication" policy that exists but is stuck in **report-only** mode doesn't count as protection.
- An admin with Authenticator push **and** SMS has MFA but is **not phishing-resistant**. One with a passkey passes.
- Security groups are evaluated for IPv4 **and** IPv6 (`::/0`), and for "all protocols" (`-1`) rules.
- Admin rights are detected whether they come from a managed policy or an **inline `*:*`** statement.
- `svc_sql` is flagged critical rather than high because it's both Kerberoastable **and** a Domain Admin. That's an offline password crack away from domain compromise.

## Checks

| Platform | Checks |
|---|---|
| **AWS** (16) | Root MFA · root access keys · root usage · console users without MFA · key age > 90d · unused keys > 45d · two active keys · stale console passwords · admin `*:*` on users (managed + inline) · SG admin/DB ports open to the world (v4/v6/all-proto) · S3 Block Public Access · public bucket policy · S3 versioning · CloudTrail multi-region / validation / KMS |
| **Entra ID / M365** (11) | Users and admins without MFA · admins without phishing-resistant MFA · SMS/voice-only users · Global Admin count · guest privileged users · on-prem-synced privileged accounts · legacy auth blocked · MFA for all users · phishing-resistant auth strength for admin roles · report-only policies · excessive CA exclusions |
| **Active Directory** (7) | krbtgt age (Golden Ticket) · Kerberoastable SPN accounts · AS-REP roastable · unconstrained delegation · Domain Admin count · privileged non-expiring passwords · stale enabled accounts |

## Standards alignment

| Standard | Coverage |
|---|---|
| **CIS AWS Foundations Benchmark** | IAM, Storage, Logging and Networking sections |
| **CISA SCuBA Microsoft 365 Secure Configuration Baselines** (Entra ID) | Legacy auth, phishing-resistant MFA, privileged role limits, guest privilege |
| **NIST SP 800-63B-4 / OMB M-22-09** | Phishing-resistant authenticators; SMS as a restricted authenticator |
| **NIST CSF 2.0** | PR.AA-01–06 (identity, authentication, access), DE.CM-03, PR.DS-11 |
| **CIS Controls v8.1** | 5 (Account Mgmt), 6 (Access Control Mgmt), 3.3 (Data access) |
| **MITRE ATT&CK** | T1078.002/.004, T1110.003, T1558.001/.003/.004, T1530, T1098.003, T1133 |

## Quick start

```bash
# Offline demo
python3 cloud_identity_audit.py --aws sample_data/aws --entra sample_data/entra --ad sample_data/ad \
    --as-of 2026-10-29 --out reports/
python3 -m unittest discover -s tests -v

# Real environment: collect (read-only), then analyze
./collectors/collect_aws.sh aws_export us-east-1
pwsh ./collectors/collect_entra.ps1 -OutDir entra_export
powershell .\collectors\collect_ad.ps1 -OutDir ad_export
python3 cloud_identity_audit.py --aws aws_export --entra entra_export --ad ad_export
```

The exit code is 2 when critical findings exist, so the audit can gate a scheduled job or CI.

## Adapting to your environment

- **Only one platform?** Pass only the flags you need (`--entra` alone works fine for an M365-only nonprofit).
- **Policy thresholds** (`--config my.json`): `key_max_age_days`, `stale_days`, `ad_stale_days`, `krbtgt_max_days`, `ga_min`/`ga_max`, `da_max`, `ca_max_exclusions`.
- **AWS Organizations:** run `collect_aws.sh` per account through an audit role, or point it at each member account profile.
- **No Entra P1/P2 license?** The registration report needs P1. Export MFA status from the M365 admin center instead and map the columns.

## Remediation & detection

[`docs/remediation-and-detection-playbook.md`](docs/remediation-and-detection-playbook.md) contains:

- a **30-day hardening sequence** ordered by risk reduction
- a **least-privilege CI/CD role** that replaces `AdministratorAccess` with GitHub OIDC (no long-lived keys)
- **KQL and Athena SQL detections** for legacy-auth spraying, role assignment, root usage, Kerberoasting and AS-REP roasting

## Security & ethics

The collectors are strictly read-only. Their exports contain account names and configuration details, so treat them as **Confidential**. The sample data is fictional and uses AWS's documentation account ID `123456789012` and `corp.example`. Only audit tenants and domains you're authorized to assess.

## Lessons learned

1. **"We have MFA" isn't a yes/no answer.** Coverage gaps (exclusions, report-only policies, legacy protocols) and method strength (SMS vs. passkeys) matter more than whether a policy exists.
2. **Identity planes are linked.** An on-prem-synced Global Admin means an AD compromise becomes a cloud compromise. Cloud-only admin accounts break that path.
3. **Service accounts are the soft underbelly.** Long-lived AWS keys and Kerberoastable SPNs with decade-old passwords appear in nearly every real assessment.
4. **Separate collection from analysis.** It keeps assessments least-privilege, repeatable and auditable.
