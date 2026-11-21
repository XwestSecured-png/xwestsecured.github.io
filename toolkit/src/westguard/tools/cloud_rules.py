"""
Cloud detection rules (AWS CloudTrail + Microsoft Entra ID sign-in logs).
Each rule carries metadata, a Sigma-style detection, and positive/negative fixtures that
the unit tests run, so a rule cannot be merged unless it fires on the attack and stays
quiet on the look-alike benign event.
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import math

AWS = {"product": "aws", "service": "cloudtrail"}
ENTRA = {"product": "azure", "service": "signinlogs"}
ALLOWED_REGIONS = ["us-east-1", "us-east-2", "us-west-2"]     # edit for your org

RULES = [
    {"id": "CLD-001", "title": "AWS root account console login", "level": "high", "logsource": AWS,
     "attack": ["T1078.004"], "tactic": "Initial Access / Privilege Escalation",
     "description": "The root user should only be used for a handful of account-level tasks. Any root login needs review.",
     "falsepositives": ["Documented break-glass use (verify against change ticket)"],
     "detection": {"sel": {"eventName": "ConsoleLogin", "userIdentity.type": "Root"}, "condition": "sel"},
     "pos": {"eventName": "ConsoleLogin", "userIdentity": {"type": "Root"}},
     "neg": {"eventName": "ConsoleLogin", "userIdentity": {"type": "IAMUser"}}},

    {"id": "CLD-002", "title": "AWS console login without MFA", "level": "medium", "logsource": AWS,
     "attack": ["T1078.004"], "tactic": "Initial Access",
     "description": "Successful IAM user console login where MFA was not used.",
     "falsepositives": ["Federated (SSO) users, where MFA is enforced at the IdP; these are filtered"],
     "detection": {"sel": {"eventName": "ConsoleLogin", "additionalEventData.MFAUsed": "No",
                           "responseElements.ConsoleLogin": "Success"},
                   "filter": {"userIdentity.type": ["AssumedRole", "FederatedUser"]}, "condition": "sel and not filter"},
     "pos": {"eventName": "ConsoleLogin", "userIdentity": {"type": "IAMUser"}, "additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"}},
     "neg": {"eventName": "ConsoleLogin", "userIdentity": {"type": "IAMUser"}, "additionalEventData": {"MFAUsed": "Yes"}, "responseElements": {"ConsoleLogin": "Success"}}},

    {"id": "CLD-003", "title": "CloudTrail logging stopped or deleted", "level": "critical", "logsource": AWS,
     "attack": ["T1562.008"], "tactic": "Defense Evasion",
     "description": "An attacker turning off the audit trail to hide what comes next.",
     "falsepositives": ["Trail migration during a planned change"],
     "detection": {"sel": {"eventSource": "cloudtrail.amazonaws.com",
                           "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]}, "condition": "sel"},
     "pos": {"eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging"},
     "neg": {"eventSource": "cloudtrail.amazonaws.com", "eventName": "DescribeTrails"}},

    {"id": "CLD-004", "title": "GuardDuty detector deleted or disassociated", "level": "high", "logsource": AWS,
     "attack": ["T1562.001"], "tactic": "Defense Evasion",
     "description": "Threat detection service disabled.",
     "falsepositives": ["Account decommissioning"],
     "detection": {"sel": {"eventSource": "guardduty.amazonaws.com",
                           "eventName": ["DeleteDetector", "DisassociateFromAdministratorAccount", "StopMonitoringMembers", "DeleteMembers"]},
                   "condition": "sel"},
     "pos": {"eventSource": "guardduty.amazonaws.com", "eventName": "DeleteDetector"},
     "neg": {"eventSource": "guardduty.amazonaws.com", "eventName": "ListFindings"}},

    {"id": "CLD-005", "title": "Administrator policy attached to IAM identity", "level": "high", "logsource": AWS,
     "attack": ["T1098.003"], "tactic": "Privilege Escalation / Persistence",
     "description": "AdministratorAccess (or another *Admin* managed policy) attached to a user, role or group.",
     "falsepositives": ["Approved admin onboarding via IaC pipeline role; tune with an allow-list of pipeline ARNs"],
     "detection": {"sel": {"eventSource": "iam.amazonaws.com", "eventName": ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"],
                           "requestParameters.policyArn|endswith": ["/AdministratorAccess", "/IAMFullAccess"]}, "condition": "sel"},
     "pos": {"eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
     "neg": {"eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}},

    {"id": "CLD-006", "title": "Console password created for IAM user", "level": "medium", "logsource": AWS,
     "attack": ["T1098.001"], "tactic": "Persistence",
     "description": "CreateLoginProfile / UpdateLoginProfile gives an identity (often a programmatic one) a console password.",
     "falsepositives": ["Helpdesk password reset for a human user"],
     "detection": {"sel": {"eventSource": "iam.amazonaws.com", "eventName": ["CreateLoginProfile", "UpdateLoginProfile"]}, "condition": "sel"},
     "pos": {"eventSource": "iam.amazonaws.com", "eventName": "CreateLoginProfile"},
     "neg": {"eventSource": "iam.amazonaws.com", "eventName": "GetLoginProfile"}},

    {"id": "CLD-007", "title": "S3 public access block removed or bucket opened to everyone", "level": "high", "logsource": AWS,
     "attack": ["T1530"], "tactic": "Collection / Exfiltration",
     "description": "Bucket-level guardrails removed or an ACL/policy grants access to AllUsers.",
     "falsepositives": ["Intentional static-website buckets (should be behind CloudFront instead)"],
     "detection": {"sel1": {"eventSource": "s3.amazonaws.com", "eventName": "DeleteBucketPublicAccessBlock"},
                   "sel2": {"eventSource": "s3.amazonaws.com", "eventName": ["PutBucketAcl", "PutBucketPolicy"],
                            "requestParameters|contains": ["AllUsers", "\"Principal\": \"*\"", "'Principal': '*'"]},
                   "condition": "sel1 or sel2"},
     "pos": {"eventSource": "s3.amazonaws.com", "eventName": "DeleteBucketPublicAccessBlock"},
     "neg": {"eventSource": "s3.amazonaws.com", "eventName": "PutBucketAcl", "requestParameters": {"AccessControlPolicy": "private"}}},

    {"id": "CLD-008", "title": "EC2 instances launched in an unapproved region", "level": "high", "logsource": AWS,
     "attack": ["T1578.002", "T1496"], "tactic": "Defense Evasion / Impact",
     "description": "Attackers with stolen keys launch crypto-mining instances in regions nobody watches.",
     "falsepositives": ["New region adoption (update ALLOWED_REGIONS)"],
     "detection": {"sel": {"eventSource": "ec2.amazonaws.com", "eventName": "RunInstances"},
                   "filter": {"awsRegion": ALLOWED_REGIONS}, "condition": "sel and not filter"},
     "pos": {"eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "awsRegion": "ap-southeast-3"},
     "neg": {"eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "awsRegion": "us-east-1"}},

    {"id": "CLD-009", "title": "Burst of AccessDenied errors from one principal (cloud discovery)", "level": "medium", "logsource": AWS,
     "attack": ["T1580", "T1526"], "tactic": "Discovery",
     "description": "Stolen keys are tested by enumerating services; most calls fail.",
     "falsepositives": ["Misconfigured automation after a permission change"],
     "detection": {"sel": {"errorCode": ["AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation"]}, "condition": "sel"},
     "correlation": {"type": "event_count", "group_by": ["userIdentity.arn"], "timespan_s": 600, "gte": 10},
     "pos_series": [{"errorCode": "AccessDenied", "userIdentity": {"arn": "x"}, "eventTime": f"2026-11-01T10:00:{i:02d}Z"} for i in range(12)],
     "neg_series": [{"errorCode": "AccessDenied", "userIdentity": {"arn": "x"}, "eventTime": f"2026-11-01T1{i % 10}:00:00Z"} for i in range(12)]},

    {"id": "CLD-010", "title": "Entra ID password spray (one IP, many accounts)", "level": "high", "logsource": ENTRA,
     "attack": ["T1110.003"], "tactic": "Credential Access",
     "description": "Failed password (50126) against 10+ distinct users from one IP within 30 minutes.",
     "falsepositives": ["Shared NAT egress with a misconfigured app; check user agent"],
     "detection": {"sel": {"status.errorCode": [50126, 50053]}, "condition": "sel"},
     "correlation": {"type": "value_count", "field": "userPrincipalName", "group_by": ["ipAddress"], "timespan_s": 1800, "gte": 10},
     "pos_series": [{"status": {"errorCode": 50126}, "ipAddress": "203.0.113.9", "userPrincipalName": f"u{i}@corp.example", "createdDateTime": f"2026-11-01T10:{i:02d}:00Z"} for i in range(12)],
     "neg_series": [{"status": {"errorCode": 50126}, "ipAddress": "203.0.113.9", "userPrincipalName": "u1@corp.example", "createdDateTime": f"2026-11-01T10:{i:02d}:00Z"} for i in range(12)]},

    {"id": "CLD-011", "title": "Entra ID MFA fatigue (repeated push denials)", "level": "high", "logsource": ENTRA,
     "attack": ["T1621"], "tactic": "Credential Access",
     "description": "5+ MFA denials or timeouts (500121) for one user in 10 minutes: an attacker has the password and is spamming pushes.",
     "falsepositives": ["User with a broken authenticator app"],
     "detection": {"sel": {"status.errorCode": 500121}, "condition": "sel"},
     "correlation": {"type": "event_count", "group_by": ["userPrincipalName"], "timespan_s": 600, "gte": 5},
     "pos_series": [{"status": {"errorCode": 500121}, "userPrincipalName": "a@corp.example", "createdDateTime": f"2026-11-01T10:0{i}:00Z"} for i in range(6)],
     "neg_series": [{"status": {"errorCode": 500121}, "userPrincipalName": "a@corp.example", "createdDateTime": f"2026-11-01T1{i}:00:00Z"} for i in range(6)]},

    {"id": "CLD-012", "title": "Successful legacy-authentication sign-in (MFA bypass)", "level": "medium", "logsource": ENTRA,
     "attack": ["T1078.004"], "tactic": "Initial Access / Defense Evasion",
     "description": "IMAP, POP, SMTP AUTH and ActiveSync basic auth cannot do MFA; a success means the password alone was enough.",
     "falsepositives": ["Legacy printers/scanners using SMTP AUTH (move to an app-specific connector)"],
     "detection": {"sel": {"status.errorCode": 0, "clientAppUsed": ["IMAP4", "POP3", "Authenticated SMTP", "Exchange ActiveSync", "Other clients"]},
                   "condition": "sel"},
     "pos": {"status": {"errorCode": 0}, "clientAppUsed": "IMAP4"},
     "neg": {"status": {"errorCode": 0}, "clientAppUsed": "Browser"}},

    {"id": "CLD-013", "title": "Entra ID impossible travel", "level": "high", "logsource": ENTRA,
     "attack": ["T1078.004"], "tactic": "Initial Access",
     "description": "Two successful sign-ins for one user whose distance / time implies travel faster than 900 km/h.",
     "falsepositives": ["Corporate VPN or cloud proxy egress in another country (add to KNOWN_EGRESS)"],
     "python_only": "Needs geo-distance between consecutive events, which Sigma cannot express. Use the SIEM's native UEBA rule or this logic as a scheduled query.",
     "pos_series": [
         {"status": {"errorCode": 0}, "userPrincipalName": "a@corp.example", "createdDateTime": "2026-11-01T10:00:00Z", "ipAddress": "192.0.2.10", "location": {"city": "Atlanta", "geoCoordinates": {"latitude": 33.75, "longitude": -84.39}}},
         {"status": {"errorCode": 0}, "userPrincipalName": "a@corp.example", "createdDateTime": "2026-11-01T11:00:00Z", "ipAddress": "198.51.100.7", "location": {"city": "Lagos", "geoCoordinates": {"latitude": 6.52, "longitude": 3.38}}}],
     "neg_series": [
         {"status": {"errorCode": 0}, "userPrincipalName": "a@corp.example", "createdDateTime": "2026-11-01T08:00:00Z", "ipAddress": "192.0.2.10", "location": {"city": "Atlanta", "geoCoordinates": {"latitude": 33.75, "longitude": -84.39}}},
         {"status": {"errorCode": 0}, "userPrincipalName": "a@corp.example", "createdDateTime": "2026-11-01T14:00:00Z", "ipAddress": "192.0.2.80", "location": {"city": "New York", "geoCoordinates": {"latitude": 40.71, "longitude": -74.0}}}]},
]

KNOWN_EGRESS: set[str] = set()      # VPN / proxy IPs to ignore for impossible travel
MAX_KMH = 900


def haversine_km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a["latitude"], a["longitude"], b["latitude"], b["longitude"]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))
