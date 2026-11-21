# Splunk SPL generated from the Sigma rules (pySigma)

Field names follow the raw CloudTrail / Entra ID JSON. Add a field-mapping pipeline for your add-on (for example Splunk_TA_aws).

## AWS root account console login

```spl
eventName="ConsoleLogin" userIdentity.type="Root"
```

## AWS console login without MFA

```spl
eventName="ConsoleLogin" additionalEventData.MFAUsed="No" responseElements.ConsoleLogin="Success" NOT (userIdentity.type IN ("AssumedRole", "FederatedUser"))
```

## CloudTrail logging stopped or deleted

```spl
eventSource="cloudtrail.amazonaws.com" (eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"))
```

## GuardDuty detector deleted or disassociated

```spl
eventSource="guardduty.amazonaws.com" (eventName IN ("DeleteDetector", "DisassociateFromAdministratorAccount", "StopMonitoringMembers", "DeleteMembers"))
```

## Administrator policy attached to IAM identity

```spl
eventSource="iam.amazonaws.com" (eventName IN ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy")) (requestParameters.policyArn IN ("*/AdministratorAccess", "*/IAMFullAccess"))
```

## Console password created for IAM user

```spl
eventSource="iam.amazonaws.com" (eventName IN ("CreateLoginProfile", "UpdateLoginProfile"))
```

## S3 public access block removed or bucket opened to everyone

```spl
(eventSource="s3.amazonaws.com" eventName="DeleteBucketPublicAccessBlock") OR (eventSource="s3.amazonaws.com" (eventName IN ("PutBucketAcl", "PutBucketPolicy")) (requestParameters IN ("*AllUsers*", "*\"Principal\": \"*\"*", "*'Principal': '*'*")))
```

## EC2 instances launched in an unapproved region

```spl
eventSource="ec2.amazonaws.com" eventName="RunInstances" NOT (awsRegion IN ("us-east-1", "us-east-2", "us-west-2"))
```

## Burst of AccessDenied errors from one principal (cloud discovery)

```spl
errorCode IN ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation")

| bin _time span=10m
| stats count as event_count by _time userIdentity.arn

| search event_count >= 10
```

## Entra ID password spray (one IP, many accounts)

```spl
status.errorCode IN (50126, 50053)

| bin _time span=30m
| stats dc(userPrincipalName) as value_count by _time ipAddress

| search value_count >= 10
```

## Entra ID MFA fatigue (repeated push denials)

```spl
status.errorCode=500121

| bin _time span=10m
| stats count as event_count by _time userPrincipalName

| search event_count >= 5
```

## Successful legacy-authentication sign-in (MFA bypass)

```spl
status.errorCode=0 (clientAppUsed IN ("IMAP4", "POP3", "Authenticated SMTP", "Exchange ActiveSync", "Other clients"))
```
