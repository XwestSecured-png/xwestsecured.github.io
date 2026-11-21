# Cloud Detection Alerts (attack timeline)

Events analysed: 1,049 CloudTrail, 138 Entra ID sign-ins. Alerts: 17.

| First seen (UTC) | Level | Rule | ATT&CK | What happened |
|---|---|---|---|---|
| 2026-11-17 06:02:00 | 🟧 high | CLD-010 Entra ID password spray (one IP, many accounts) | T1110.003 | 14 distinct userPrincipalName for ipAddress=203.0.113.50 (06:02–06:10); last: avery.lane@corp.example from 203.0.113.50 via Browser |
| 2026-11-17 13:05:00 | 🟧 high | CLD-013 Entra ID impossible travel | T1078.004 | Atlanta → Bucharest: 8,848 km in 1.2 h (7,373 km/h) |
| 2026-11-17 14:10:00 | 🟧 high | CLD-011 Entra ID MFA fatigue (repeated push denials) | T1621 | 7 events for userPrincipalName=jordan.lee@corp.example (14:10–14:15); last: jordan.lee@corp.example from 198.51.100.77 via Browser |
| 2026-11-17 14:30:00 | 🟨 medium | CLD-012 Successful legacy-authentication sign-in (MFA bypass) | T1078.004 | casey.ford@corp.example from 198.51.100.77 via IMAP4 |
| 2026-11-17 14:30:00 | 🟧 high | CLD-013 Entra ID impossible travel | T1078.004 | Bucharest → Atlanta: 8,848 km in 4.6 h (1,917 km/h) |
| 2026-11-17 15:00:00 | 🟨 medium | CLD-009 Burst of AccessDenied errors from one principal (cloud discovery) | T1580, T1526 | 10 events for userIdentity.arn=arn:aws:iam::111122223333:user/ci-deploy (15:00–15:03); last: ListUsers by arn:aws:iam::111122223333:user/ci-deploy from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:08:00 | 🟧 high | CLD-005 Administrator policy attached to IAM identity | T1098.003 | AttachUserPolicy by arn:aws:iam::111122223333:user/ci-deploy from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:11:00 | 🟨 medium | CLD-006 Console password created for IAM user | T1098.001 | CreateLoginProfile by arn:aws:iam::111122223333:user/ci-deploy from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:13:00 | 🟥 critical | CLD-003 CloudTrail logging stopped or deleted | T1562.008 | StopLogging by arn:aws:iam::111122223333:user/ci-deploy from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:14:00 | 🟧 high | CLD-004 GuardDuty detector deleted or disassociated | T1562.001 | DeleteDetector by arn:aws:iam::111122223333:user/ci-deploy from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:20:00 | 🟨 medium | CLD-002 AWS console login without MFA | T1078.004 | ConsoleLogin by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:23:00 | 🟧 high | CLD-008 EC2 instances launched in an unapproved region | T1578.002, T1496 | RunInstances by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in ap-southeast-3 |
| 2026-11-17 15:24:00 | 🟧 high | CLD-008 EC2 instances launched in an unapproved region | T1578.002, T1496 | RunInstances by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in ap-southeast-3 |
| 2026-11-17 15:25:00 | 🟧 high | CLD-008 EC2 instances launched in an unapproved region | T1578.002, T1496 | RunInstances by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in ap-southeast-3 |
| 2026-11-17 15:30:00 | 🟧 high | CLD-007 S3 public access block removed or bucket opened to everyone | T1530 | DeleteBucketPublicAccessBlock by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in us-east-1 |
| 2026-11-17 15:31:00 | 🟧 high | CLD-007 S3 public access block removed or bucket opened to everyone | T1530 | PutBucketPolicy by arn:aws:iam::111122223333:user/backup-admin from 203.0.113.200 in us-east-1 |
| 2026-11-17 20:00:00 | 🟧 high | CLD-001 AWS root account console login | T1078.004 | ConsoleLogin by arn:aws:iam::111122223333:root from 192.0.2.20 in us-east-1 |
