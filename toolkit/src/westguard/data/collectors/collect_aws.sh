#!/usr/bin/env bash
# Read-only AWS evidence collector for cloud_identity_audit.py
# Requires AWS CLI v2 and a principal with the AWS-managed "SecurityAudit" (or ReadOnlyAccess) policy.
#   ./collect_aws.sh [output_dir] [region]
set -euo pipefail
OUT="${1:-aws_export}"; REGION="${2:-us-east-1}"
mkdir -p "$OUT"
echo "[*] Account: $(aws sts get-caller-identity --query Account --output text)"

# IAM credential report (may take a few seconds to generate)
aws iam generate-credential-report >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do
  if aws iam get-credential-report --query Content --output text 2>/dev/null | base64 -d > "$OUT/credential_report.csv"; then break; fi
  sleep 3
done

aws iam get-account-authorization-details --filter User Role Group LocalManagedPolicy --output json \
  > "$OUT/account_authorization_details.json"
aws ec2 describe-security-groups --region "$REGION" --output json > "$OUT/security_groups.json"
aws cloudtrail describe-trails --include-shadow-trails --output json > "$OUT/cloudtrail_trails.json"

# S3: per-bucket public access block, policy status, versioning
echo "[" > "$OUT/s3_buckets.json"; first=1
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  pab=$(aws s3api get-public-access-block --bucket "$b" --query PublicAccessBlockConfiguration --output json 2>/dev/null || echo null)
  pub=$(aws s3api get-bucket-policy-status --bucket "$b" --query PolicyStatus.IsPublic --output json 2>/dev/null || echo false)
  ver=$(aws s3api get-bucket-versioning --bucket "$b" --query Status --output json 2>/dev/null || echo null)
  [[ $first -eq 0 ]] && echo "," >> "$OUT/s3_buckets.json"; first=0
  printf '{"Name":"%s","PublicAccessBlockConfiguration":%s,"PolicyIsPublic":%s,"Versioning":%s}' "$b" "$pab" "$pub" "$ver" >> "$OUT/s3_buckets.json"
done
echo "]" >> "$OUT/s3_buckets.json"

sha256sum "$OUT"/* > "$OUT/SHA256SUMS"
echo "[+] Export complete: $OUT (treat as CONFIDENTIAL)"
