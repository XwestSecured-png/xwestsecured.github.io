# Identity Hardening & Detection Playbook

Remediation in the order that removes the most risk first, followed by detections that catch the attacks these gaps enable.

## 30-day hardening sequence

| Week | Action | Closes |
|---|---|---|
| 1 | Turn **Block legacy authentication** on (it's currently report-only). Register **phishing-resistant MFA** (FIDO2 keys or passkeys) for every admin, plus 2 cloud-only break-glass accounts with FIDO2 keys stored in a safe | ENT-CA-01, ENT-CA-04, ENT-MFA-01/02 |
| 1 | AWS: enable MFA on **root**, delete root access keys, close RDP/all-ports `0.0.0.0/0` and `::/0` security group rules | AWS-IAM-01/02, AWS-NET-01 |
| 2 | Remove the guest Global Admin. Move admins to **cloud-only** accounts. Cut Global Admins down to 2 named accounts + 2 break-glass, and use PIM for the rest | ENT-PRIV-01/02/03 |
| 2 | Disable `former-contractor`. Replace `ci-deploy` long-lived keys with **GitHub OIDC → IAM role** (short-lived credentials, least privilege) | AWS-IAM-05/06/09 |
| 3 | AD: move `svc_sql` / `svc_backup` to **gMSA**, take service accounts out of Domain Admins, enable pre-auth on `scanner`, remove unconstrained delegation | AD-KRB-02/03/04, AD-PRIV-01 |
| 3 | Rotate **krbtgt twice** (wait for replication between the two resets) | AD-KRB-01 |
| 4 | Turn on account-level S3 Block Public Access and serve website assets through CloudFront + OAC. Create an org-wide multi-region CloudTrail with validation + KMS | AWS-S3-*, AWS-LOG-* |
| 4 | Disable stale accounts and schedule quarterly access reviews | AD-ACC-01, AWS-IAM-08 |

## Least-privilege example: CI/CD deploy role (replaces AdministratorAccess on `ci-deploy`)

Trust policy that lets only a specific GitHub repo and branch assume the role through OIDC, with no stored keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:example-org/website:ref:refs/heads/main" }
    }
  }]
}
```

Permissions policy scoped to the one stack and bucket it deploys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet",
                                    "cloudformation:DescribeStacks", "cloudformation:DescribeChangeSet"],
      "Resource": "arn:aws:cloudformation:us-east-1:123456789012:stack/website-prod/*" },
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::ecs-website-assets-example", "arn:aws:s3:::ecs-website-assets-example/*"] }
  ]
}
```

## Detections for the attacks these gaps enable

**Microsoft Sentinel / Defender (KQL): legacy-auth sign-ins (password spray path)**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients")
| summarize attempts = count(), users = dcount(UserPrincipalName), succeeded = countif(ResultType == 0)
    by IPAddress, ClientAppUsed
| where users > 5 or succeeded > 0
```

**KQL: privileged role added (persistence)**
```kql
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend role = tostring(TargetResources[0].modifiedProperties[1].newValue),
         target = tostring(TargetResources[0].userPrincipalName),
         actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, actor, target, role
```

**AWS CloudTrail (Athena SQL): root account activity**
```sql
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.type = 'Root'
  AND eventtype <> 'AwsServiceEvent'
ORDER BY eventtime DESC;
```

**Windows Security log: Kerberoasting (RC4 service tickets)**
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"            // RC4-HMAC
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize tickets = count(), services = dcount(ServiceName) by Account = TargetUserName, IpAddress
| where services >= 3
```

**AS-REP roasting:** Event **4768** with `PreAuthType = 0` for a user account.

| Detection | ATT&CK |
|---|---|
| Legacy-auth spray | T1110.003 |
| Role assignment | T1098.003 |
| Root usage | T1078.004 |
| Kerberoasting | T1558.003 |
| AS-REP roasting | T1558.004 |
