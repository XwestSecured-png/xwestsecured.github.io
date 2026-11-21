#!/usr/bin/env python3
"""
Generate synthetic but schema-accurate AWS CloudTrail and Entra ID sign-in logs:
~2 days of benign activity plus a planted two-part intrusion. Deterministic (seeded).
All IPs are RFC 5737 documentation ranges; account 111122223333 is AWS's documentation ID.

    python3 data/generate.py --out data/
"""
from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCT = "111122223333"
T0 = datetime(2026, 11, 16, 0, 0, tzinfo=timezone.utc)
R = random.Random(1337)
iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
ATL = {"city": "Atlanta", "state": "Georgia", "countryOrRegion": "US", "geoCoordinates": {"latitude": 33.749, "longitude": -84.388}}
NYC = {"city": "New York", "state": "New York", "countryOrRegion": "US", "geoCoordinates": {"latitude": 40.713, "longitude": -74.006}}
ABROAD = {"city": "Bucharest", "state": "Bucuresti", "countryOrRegion": "RO", "geoCoordinates": {"latitude": 44.426, "longitude": 26.102}}
USERS = [f"{n}@corp.example" for n in ("jordan.lee", "maria.ortiz", "sam.patel", "dana.kim", "chris.wu", "alex.brown", "taylor.green",
                                       "morgan.hill", "riley.james", "casey.ford", "jamie.cole", "drew.price", "quinn.reed", "avery.lane")]


def ct(t, name, source, ident, region="us-east-1", ip="192.0.2.20", req=None, resp=None, err=None, extra=None):
    e = {"eventVersion": "1.10", "userIdentity": ident, "eventTime": iso(t), "eventSource": source, "eventName": name,
         "awsRegion": region, "sourceIPAddress": ip, "userAgent": "aws-cli/2.17.0 Python/3.12", "requestParameters": req,
         "responseElements": resp, "requestID": str(uuid.UUID(int=R.getrandbits(128))), "eventID": str(uuid.UUID(int=R.getrandbits(128))),
         "readOnly": name.startswith(("Describe", "Get", "List")), "eventType": "AwsApiCall", "managementEvent": True,
         "recipientAccountId": ACCT, "eventCategory": "Management"}
    if err:
        e["errorCode"], e["errorMessage"] = err, f"User is not authorized to perform: {name}"
    if extra:
        e.update(extra)
    return e


def iam(user):
    return {"type": "IAMUser", "principalId": "AIDA" + user.upper()[:8].ljust(8, "X"), "arn": f"arn:aws:iam::{ACCT}:user/{user}",
            "accountId": ACCT, "accessKeyId": "AKIAIOSFODNN7EXAMPLE", "userName": user}


def role(name):
    return {"type": "AssumedRole", "principalId": "AROA" + name.upper()[:8], "arn": f"arn:aws:sts::{ACCT}:assumed-role/{name}/session",
            "accountId": ACCT, "sessionContext": {"sessionIssuer": {"type": "Role", "userName": name}}}


def login(t, ident, mfa, ok=True, ip="192.0.2.20"):
    return ct(t, "ConsoleLogin", "signin.amazonaws.com", ident, ip=ip, resp={"ConsoleLogin": "Success" if ok else "Failure"},
              extra={"additionalEventData": {"MFAUsed": "Yes" if mfa else "No", "LoginTo": "https://console.aws.amazon.com/"},
                     "eventType": "AwsConsoleSignIn"})


def signin(t, user, code=0, ip="192.0.2.10", app="Browser", loc=ATL, appname="Office 365 Exchange Online"):
    return {"id": str(uuid.UUID(int=R.getrandbits(128))), "createdDateTime": iso(t), "userPrincipalName": user, "appDisplayName": appname,
            "ipAddress": ip, "clientAppUsed": app, "status": {"errorCode": code, "failureReason": {0: None, 50126: "Invalid username or password",
            500121: "Authentication failed during strong authentication request"}.get(code)}, "location": loc,
            "conditionalAccessStatus": "success" if code == 0 else "notApplied", "isInteractive": True}


def benign():
    cte, sie = [], []
    for h in range(48):
        base = T0 + timedelta(hours=h)
        work = 12 <= base.hour <= 23          # 8am-7pm US Eastern in UTC
        for _ in range(R.randint(25, 45) if work else R.randint(5, 10)):
            t = base + timedelta(seconds=R.randint(0, 3599))
            who = R.choice([role("ci-deploy-role"), role("lambda-etl"), iam("maria.ortiz"), iam("sam.patel")])
            name, src = R.choice([("DescribeInstances", "ec2.amazonaws.com"), ("GetObject", "s3.amazonaws.com"), ("ListBuckets", "s3.amazonaws.com"),
                                  ("DescribeTrails", "cloudtrail.amazonaws.com"), ("ListFindings", "guardduty.amazonaws.com"),
                                  ("GetRole", "iam.amazonaws.com"), ("AssumeRole", "sts.amazonaws.com"), ("PutObject", "s3.amazonaws.com")])
            cte.append(ct(t, name, src, who, region=R.choice(["us-east-1", "us-east-1", "us-west-2"])))
        if work:
            cte.append(ct(base + timedelta(minutes=R.randint(0, 59)), "RunInstances", "ec2.amazonaws.com", role("ci-deploy-role"),
                          req={"instanceType": "t3.small", "minCount": 1}))
            for u in R.sample(USERS, 4):
                sie.append(signin(base + timedelta(minutes=R.randint(0, 59)), u))
            if R.random() < 0.3:                                        # a normal typo, then success
                u = R.choice(USERS); t = base + timedelta(minutes=R.randint(0, 50))
                sie += [signin(t, u, 50126), signin(t + timedelta(minutes=1), u)]
    for d in range(2):
        for u in ("maria.ortiz", "sam.patel"):
            cte.append(login(T0 + timedelta(days=d, hours=13, minutes=R.randint(0, 30)), iam(u), mfa=True))
        cte.append(ct(T0 + timedelta(days=d, hours=15), "AccessDenied-noise", "s3.amazonaws.com", role("lambda-etl"), err="AccessDenied"))
        cte.append(ct(T0 + timedelta(days=d, hours=16), "AttachUserPolicy", "iam.amazonaws.com", iam("maria.ortiz"),
                      req={"userName": "new.analyst", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    # legitimate business trip: Atlanta morning, New York 6 h later (well under 900 km/h)
    sie += [signin(T0 + timedelta(hours=12), "dana.kim"), signin(T0 + timedelta(hours=18), "dana.kim", ip="192.0.2.140", loc=NYC)]
    return cte, sie


def attack():
    cte, sie = [], []
    # Part 1: Entra ID account takeover
    t = T0 + timedelta(days=1, hours=6, minutes=2)
    for i, u in enumerate(USERS):                                       # password spray from one IP
        sie.append(signin(t + timedelta(seconds=40 * i), u, 50126, ip="203.0.113.50", loc=ABROAD))
    sie.append(signin(T0 + timedelta(days=1, hours=13, minutes=5), "jordan.lee@corp.example"))   # real user, Atlanta
    t = T0 + timedelta(days=1, hours=14, minutes=10)
    for i in range(7):                                                  # MFA push spam
        sie.append(signin(t + timedelta(seconds=55 * i), "jordan.lee@corp.example", 500121, ip="198.51.100.77", loc=ABROAD))
    sie.append(signin(t + timedelta(minutes=7), "jordan.lee@corp.example", 0, ip="198.51.100.77", loc=ABROAD))  # user gives in
    sie.append(signin(t + timedelta(minutes=20), "casey.ford@corp.example", 0, ip="198.51.100.77", app="IMAP4", loc=ABROAD,
                      appname="Exchange Online IMAP"))                  # legacy auth with sprayed password
    # Part 2: leaked AWS access key for ci-deploy user
    k = iam("ci-deploy"); ip = "203.0.113.200"
    t = T0 + timedelta(days=1, hours=15)
    for i, (n, s) in enumerate([("ListUsers", "iam"), ("GetAccountAuthorizationDetails", "iam"), ("DescribeDBInstances", "rds"),
                                ("ListSecrets", "secretsmanager"), ("GetSecretValue", "secretsmanager"), ("ListKeys", "kms"),
                                ("DescribeTable", "dynamodb"), ("ListFunctions", "lambda"), ("GetCostAndUsage", "ce"),
                                ("ListRoles", "iam"), ("DescribeVpcs", "ec2"), ("ListUsers", "iam")]):
        cte.append(ct(t + timedelta(seconds=20 * i), n, f"{s}.amazonaws.com", k, ip=ip, err="AccessDenied" if i not in (5, 10) else None))
    t += timedelta(minutes=8)
    cte.append(ct(t, "AttachUserPolicy", "iam.amazonaws.com", k, ip=ip, req={"userName": "ci-deploy", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    cte.append(ct(t + timedelta(minutes=2), "CreateUser", "iam.amazonaws.com", k, ip=ip, req={"userName": "backup-admin"}))
    cte.append(ct(t + timedelta(minutes=3), "CreateLoginProfile", "iam.amazonaws.com", k, ip=ip, req={"userName": "backup-admin", "passwordResetRequired": False}))
    cte.append(ct(t + timedelta(minutes=5), "StopLogging", "cloudtrail.amazonaws.com", k, ip=ip, req={"name": f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/org-trail"}))
    cte.append(ct(t + timedelta(minutes=6), "DeleteDetector", "guardduty.amazonaws.com", k, ip=ip, req={"detectorId": "12abc34d567e8fa901bc2d34e56789f0"}))
    cte.append(login(t + timedelta(minutes=12), iam("backup-admin"), mfa=False, ip=ip))
    for i in range(3):
        cte.append(ct(t + timedelta(minutes=15 + i), "RunInstances", "ec2.amazonaws.com", iam("backup-admin"), region="ap-southeast-3", ip=ip,
                      req={"instanceType": "p3.16xlarge", "minCount": 10, "maxCount": 10}))
    cte.append(ct(t + timedelta(minutes=22), "DeleteBucketPublicAccessBlock", "s3.amazonaws.com", iam("backup-admin"), ip=ip, req={"bucketName": "corp-finance-exports"}))
    cte.append(ct(t + timedelta(minutes=23), "PutBucketPolicy", "s3.amazonaws.com", iam("backup-admin"), ip=ip,
                  req={"bucketName": "corp-finance-exports", "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}))
    # unrelated but reviewable: break-glass root login with MFA
    cte.append(ct(T0 + timedelta(days=1, hours=20), "ConsoleLogin", "signin.amazonaws.com", {"type": "Root", "principalId": ACCT, "arn": f"arn:aws:iam::{ACCT}:root", "accountId": ACCT},
                  ip="192.0.2.20", resp={"ConsoleLogin": "Success"}, extra={"additionalEventData": {"MFAUsed": "Yes"}, "eventType": "AwsConsoleSignIn"}))
    return cte, sie


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, default=Path("data")); a = ap.parse_args(argv)
    b1, b2 = benign(); a1, a2 = attack()
    ct_all = sorted(b1 + a1, key=lambda e: e["eventTime"]); si_all = sorted(b2 + a2, key=lambda e: e["createdDateTime"])
    for e in ct_all:
        if e["eventName"] == "AccessDenied-noise":
            e["eventName"] = "GetObject"
    (a.out / "cloudtrail.jsonl").write_text("\n".join(json.dumps(e) for e in ct_all) + "\n")
    (a.out / "entra_signins.jsonl").write_text("\n".join(json.dumps(e) for e in si_all) + "\n")
    print(f"cloudtrail: {len(ct_all)} events ({len(a1)} attack)  signins: {len(si_all)} ({len(a2)} attack)")


if __name__ == "__main__":
    main()
