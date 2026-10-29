#!/usr/bin/env python3
"""
Cloud & Identity Security Posture Audit
=======================================

Offline analyzer for read-only exports from three identity planes, where most
modern breaches start (valid accounts, T1078):

  AWS          IAM credential report (CSV), IAM authorization details, security groups,
               S3 public-access settings, CloudTrail trails       -> collectors/collect_aws.sh
  Entra ID     MFA registration details, Conditional Access policies,
  (M365)       privileged role members                            -> collectors/collect_entra.ps1
  Active       Users, privileged group members, krbtgt age        -> collectors/collect_ad.ps1
  Directory

The collectors use only read permissions. Analysis runs anywhere with Python 3.9+
and needs no cloud credentials, so exports can be reviewed off-network.

    python3 cloud_identity_audit.py --aws sample_data/aws --entra sample_data/entra \
        --ad sample_data/ad --as-of 2026-10-29 --out reports/

Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import date, datetime
from pathlib import Path

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PHISHING_RESISTANT = {"fido2SecurityKey", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator",
                      "passKeyDeviceBoundWindowsHello", "windowsHelloForBusiness", "x509Certificate",
                      "certificateBasedAuthentication"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 5985: "WinRM", 5986: "WinRM", 1433: "MSSQL",
               3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
AD_PRIV_GROUPS = {"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                  "Account Operators", "Backup Operators", "Server Operators", "Print Operators"}


@dataclass
class Finding:
    platform: str
    check: str
    severity: str
    title: str
    resource: str
    detail: str
    fix: str
    references: str


def _d(v) -> date | None:
    if not v or str(v).lower() in ("n/a", "no_information", "not_supported", "none", "null"):
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


# =========================================================================== #
# AWS
# =========================================================================== #

def audit_aws(d: Path, today: date, cfg: dict) -> list[Finding]:
    F, out = "AWS", []

    def add(*a):
        out.append(Finding(F, *a))

    cr = d / "credential_report.csv"
    if cr.exists():
        with cr.open(encoding="utf-8-sig", newline="") as fh:
            for u in csv.DictReader(fh):
                name = u["user"]
                if name == "<root_account>":
                    if u.get("mfa_active") != "true":
                        add("AWS-IAM-01", "critical", "Root account without MFA", name,
                            "mfa_active=false", "Enable hardware/passkey MFA on root; store securely.",
                            "CIS AWS Foundations (IAM: root MFA); MITRE T1078.004")
                    if "true" in (u.get("access_key_1_active"), u.get("access_key_2_active")):
                        add("AWS-IAM-02", "critical", "Root account has access keys", name,
                            "active root access key", "Delete root access keys; use IAM roles.",
                            "CIS AWS Foundations (IAM: no root access keys)")
                    last = _d(u.get("password_last_used"))
                    if last and (today - last).days < 30:
                        add("AWS-IAM-03", "medium", "Root account used recently", name,
                            f"password_last_used={last}", "Reserve root for break-glass tasks; alert on root use.",
                            "CIS AWS Foundations (IAM: avoid root use)")
                    continue
                if u.get("password_enabled") == "true" and u.get("mfa_active") != "true":
                    add("AWS-IAM-04", "high", "Console user without MFA", name, "password_enabled, mfa_active=false",
                        "Require MFA (or move users to IAM Identity Center with SSO + MFA).",
                        "CIS AWS Foundations (IAM: MFA for console users)")
                active_keys = 0
                for k in ("1", "2"):
                    if u.get(f"access_key_{k}_active") != "true":
                        continue
                    active_keys += 1
                    rot = _d(u.get(f"access_key_{k}_last_rotated"))
                    used = _d(u.get(f"access_key_{k}_last_used_date"))
                    if rot and (today - rot).days > cfg["key_max_age_days"]:
                        add("AWS-IAM-05", "high", "Access key not rotated", f"{name} key{k}",
                            f"{(today - rot).days} days old", "Rotate or replace with role-based temporary credentials.",
                            "CIS AWS Foundations (IAM: rotate keys ≤ 90 days)")
                    if (used is None and rot and (today - rot).days > cfg["stale_days"]) or \
                            (used and (today - used).days > cfg["stale_days"]):
                        add("AWS-IAM-06", "medium", "Unused active access key", f"{name} key{k}",
                            f"last used {used or 'never'}", "Deactivate and delete unused keys.",
                            "CIS AWS Foundations (IAM: disable unused credentials ≥ 45 days)")
                if active_keys == 2:
                    add("AWS-IAM-07", "low", "User has two active access keys", name, "2 active keys",
                        "Keep at most one active key per user.", "CIS AWS Foundations (IAM)")
                pw_used = _d(u.get("password_last_used"))
                created = _d(u.get("user_creation_time"))
                if u.get("password_enabled") == "true" and (
                        (pw_used and (today - pw_used).days > cfg["stale_days"]) or
                        (not pw_used and created and (today - created).days > cfg["stale_days"])):
                    add("AWS-IAM-08", "medium", "Stale console password", name, f"last login {pw_used or 'never'}",
                        "Disable console access for inactive users.", "CIS AWS Foundations (IAM)")

    auth = _load(d / "account_authorization_details.json")
    if auth:
        admin_arns = set()
        for p in auth.get("Policies", []):
            for v in p.get("PolicyVersionList", []):
                if v.get("IsDefaultVersion") and _is_admin_doc(v.get("Document", {})):
                    admin_arns.add(p["Arn"])
        admin_arns.add("arn:aws:iam::aws:policy/AdministratorAccess")
        for u in auth.get("UserDetailList", []):
            attached = {p["PolicyArn"] for p in u.get("AttachedManagedPolicies", [])}
            inline_admin = any(_is_admin_doc(p.get("PolicyDocument", {})) for p in u.get("UserPolicyList", []))
            if attached & admin_arns or inline_admin:
                add("AWS-IAM-09", "high", "Full admin (*:*) attached directly to IAM user", u["UserName"],
                    ", ".join(sorted(attached & admin_arns)) or "inline *:* policy",
                    "Grant admin only via roles assumed with MFA (or IAM Identity Center permission sets); "
                    "attach policies to groups/roles, not users.", "CIS AWS Foundations (IAM: no *:* policies); least privilege")

    sgs = _load(d / "security_groups.json")
    if sgs:
        for sg in sgs.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not (open_v4 or open_v6):
                    continue
                proto = perm.get("IpProtocol")
                lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                if proto == "-1":
                    lo, hi = 0, 65535
                exposed = [f"{p}/{n}" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
                if exposed:
                    add("AWS-NET-01", "critical", "Security group exposes admin/DB ports to the internet",
                        f"{sg['GroupId']} ({sg.get('GroupName', '')})", f"{'0.0.0.0/0' if open_v4 else '::/0'} → {', '.join(exposed[:6])}",
                        "Remove world access; use SSM Session Manager / bastion / VPN, or restrict to known CIDRs.",
                        "CIS AWS Foundations (Networking: no 0.0.0.0/0 to admin ports); MITRE T1133")

    s3 = _load(d / "s3_buckets.json")
    if s3:
        for b in s3:
            pab = b.get("PublicAccessBlockConfiguration") or {}
            if not all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                add("AWS-S3-01", "high" if b.get("PolicyIsPublic") else "medium", "S3 Block Public Access not fully enabled",
                    b["Name"], f"public_policy={b.get('PolicyIsPublic', False)}",
                    "Enable all four Block Public Access settings (account and bucket level).",
                    "CIS AWS Foundations (Storage: S3 Block Public Access)")
            if b.get("PolicyIsPublic"):
                add("AWS-S3-02", "critical", "S3 bucket policy is public", b["Name"], "PolicyStatus.IsPublic=true",
                    "Remove public principals; serve public content through CloudFront with OAC.",
                    "MITRE T1530 (Data from Cloud Storage)")
            if not b.get("Versioning") == "Enabled":
                add("AWS-S3-03", "low", "S3 versioning disabled", b["Name"], f"Versioning={b.get('Versioning')}",
                    "Enable versioning (and Object Lock for backups) to survive ransomware/deletion.", "CSF 2.0 PR.DS-11")

    trails = _load(d / "cloudtrail_trails.json")
    if trails is not None:
        tl = trails.get("trailList", [])
        if not any(t.get("IsMultiRegionTrail") for t in tl):
            add("AWS-LOG-01", "high", "No multi-region CloudTrail trail", "account", f"{len(tl)} trails",
                "Create an organization/multi-region trail to a locked-down logging account.",
                "CIS AWS Foundations (Logging: CloudTrail all regions)")
        for t in tl:
            if not t.get("LogFileValidationEnabled"):
                add("AWS-LOG-02", "medium", "CloudTrail log file validation disabled", t["Name"], "",
                    "Enable log file integrity validation.", "CIS AWS Foundations (Logging)")
            if not t.get("KmsKeyId"):
                add("AWS-LOG-03", "low", "CloudTrail logs not encrypted with KMS CMK", t["Name"], "",
                    "Encrypt with a customer-managed KMS key.", "CIS AWS Foundations (Logging)")
    return out


def _is_admin_doc(doc: dict) -> bool:
    st = doc.get("Statement", [])
    st = [st] if isinstance(st, dict) else st
    for s in st:
        if s.get("Effect") != "Allow":
            continue
        acts = s.get("Action", [])
        res = s.get("Resource", [])
        acts = [acts] if isinstance(acts, str) else acts
        res = [res] if isinstance(res, str) else res
        if "*" in acts and "*" in res:
            return True
    return False


# =========================================================================== #
# Entra ID / Microsoft 365
# =========================================================================== #

def audit_entra(d: Path, today: date, cfg: dict) -> list[Finding]:
    F, out = "Entra ID", []

    def add(*a):
        out.append(Finding(F, *a))

    reg = _load(d / "user_registration_details.json") or {}
    users = reg.get("value", reg if isinstance(reg, list) else [])
    for u in users:
        upn = u.get("userPrincipalName")
        methods = set(u.get("methodsRegistered") or [])
        if not u.get("isMfaRegistered"):
            add("ENT-MFA-01", "critical" if u.get("isAdmin") else "high",
                "Admin without any MFA method" if u.get("isAdmin") else "User without MFA registered",
                upn, f"methods={sorted(methods) or 'none'}",
                "Require MFA registration via Conditional Access; prioritize admins.",
                "CISA SCuBA M365 baseline (Entra ID); CSF 2.0 PR.AA-03; MITRE T1078.004")
        elif u.get("isAdmin") and not (methods & PHISHING_RESISTANT):
            add("ENT-MFA-02", "high", "Admin lacks phishing-resistant MFA", upn,
                f"methods={sorted(methods)}",
                "Register FIDO2 security keys / passkeys or WHfB; enforce 'Phishing-resistant MFA' auth strength for admin roles.",
                "CISA SCuBA M365 baseline; OMB M-22-09; NIST SP 800-63B-4 (phishing resistance)")
        elif methods and methods <= {"mobilePhone", "email", "alternateMobilePhone", "officePhone"}:
            add("ENT-MFA-03", "medium", "User relies only on SMS/voice/email MFA", upn, f"methods={sorted(methods)}",
                "Move users to Authenticator with number matching or passkeys; SMS is vulnerable to SIM swap.",
                "NIST SP 800-63B-4 (restricted authenticators)")

    roles = _load(d / "privileged_role_members.json") or {}
    ga = roles.get("Global Administrator", [])
    if ga and not (cfg["ga_min"] <= len(ga) <= cfg["ga_max"]):
        add("ENT-PRIV-01", "high" if len(ga) > cfg["ga_max"] else "medium",
            "Global Administrator count outside recommended range", "Global Administrator",
            f"{len(ga)} members (policy {cfg['ga_min']}-{cfg['ga_max']}; CISA SCuBA allows at most 8)",
            "Use least-privileged roles (User/Exchange/Security Admin) and PIM just-in-time activation.",
            "CISA SCuBA M365 baseline (privileged access)")
    for role, members in roles.items():
        for m in members:
            if m.get("userType") == "Guest":
                add("ENT-PRIV-02", "critical", "Guest account holds privileged role", m.get("userPrincipalName"),
                    role, "Remove privileged roles from guest/external accounts.", "CISA SCuBA M365 baseline")
            if m.get("onPremisesSyncEnabled"):
                add("ENT-PRIV-03", "high", "Privileged role assigned to on-prem synced account", m.get("userPrincipalName"),
                    role, "Use cloud-only admin accounts so an AD compromise can't escalate to the cloud tenant.",
                    "Microsoft privileged access guidance; CISA SCuBA M365 baseline")

    ca = _load(d / "conditional_access_policies.json") or {}
    pols = [p for p in ca.get("value", []) if p.get("state") == "enabled"]
    report_only = [p for p in ca.get("value", []) if p.get("state") == "enabledForReportingButNotEnforced"]

    def grants(p):
        return set((p.get("grantControls") or {}).get("builtInControls") or [])

    def strength(p):
        return ((p.get("grantControls") or {}).get("authenticationStrength") or {}).get("displayName", "")

    def all_users(p):
        u = p.get("conditions", {}).get("users", {})
        return "All" in (u.get("includeUsers") or [])

    legacy = any("block" in grants(p) and all_users(p) and
                 {"exchangeActiveSync", "other"} <= set(p.get("conditions", {}).get("clientAppTypes") or [])
                 for p in pols)
    if not legacy:
        add("ENT-CA-01", "critical", "Legacy authentication not blocked", "Conditional Access",
            "no enabled policy blocks exchangeActiveSync + other client apps for all users",
            "Create CA policy: All users, client apps = Exchange ActiveSync + Other clients, Grant = Block.",
            "CISA SCuBA M365 baseline (legacy auth); MITRE T1110.003")
    if not any(all_users(p) and ("mfa" in grants(p) or strength(p)) for p in pols):
        add("ENT-CA-02", "high", "No enforced MFA policy for all users", "Conditional Access", "",
            "Require MFA (or an authentication strength) for All users / All cloud apps, with break-glass exclusions only.",
            "CISA SCuBA M365 baseline; CSF 2.0 PR.AA-03")
    if not any(p.get("conditions", {}).get("users", {}).get("includeRoles") and "phishing" in strength(p).lower()
               for p in pols):
        add("ENT-CA-03", "high", "Admin roles not required to use phishing-resistant MFA", "Conditional Access", "",
            "CA policy: include directory roles (Global Admin, Privileged Role Admin, etc.), "
            "Grant = authentication strength 'Phishing-resistant MFA'.", "CISA SCuBA M365 baseline")
    for p in report_only:
        add("ENT-CA-04", "medium", "Conditional Access policy left in report-only mode", p.get("displayName"),
            "state=enabledForReportingButNotEnforced", "Review sign-in impact and switch to On.", "CSF 2.0 PR.AA-05")
    for p in pols:
        ex = p.get("conditions", {}).get("users", {}).get("excludeUsers") or []
        if len(ex) > cfg["ca_max_exclusions"]:
            add("ENT-CA-05", "medium", "Conditional Access policy with many user exclusions", p.get("displayName"),
                f"{len(ex)} excluded users", "Limit exclusions to break-glass accounts; review quarterly.", "CSF 2.0 PR.AA-05")
    return out


# =========================================================================== #
# Active Directory
# =========================================================================== #

def audit_ad(d: Path, today: date, cfg: dict) -> list[Finding]:
    F, out = "Active Directory", []

    def add(*a):
        out.append(Finding(F, *a))

    users = _load(d / "ad_users.json") or []
    priv_names = set()
    groups = _load(d / "ad_privileged_groups.json") or {}
    for g, members in groups.items():
        priv_names.update(m.lower() for m in members)
    da = groups.get("Domain Admins", [])
    if len(da) > cfg["da_max"]:
        add("AD-PRIV-01", "high", "Too many Domain Admins", "Domain Admins", f"{len(da)} members: {', '.join(da)}",
            "Reduce to 2-4 named admin accounts; delegate with least-privileged groups; adopt a tiered admin model.",
            "Microsoft AD tiering guidance; CIS Controls v8.1 5.4")

    for u in users:
        sam = u["SamAccountName"]
        enabled = u.get("Enabled")
        priv = sam.lower() in priv_names or u.get("AdminCount") == 1
        last = _d(u.get("LastLogonDate"))
        pls = _d(u.get("PasswordLastSet"))
        if sam.lower() == "krbtgt":
            if pls and (today - pls).days > cfg["krbtgt_max_days"]:
                add("AD-KRB-01", "high", "krbtgt password not rotated", "krbtgt", f"last set {pls} ({(today - pls).days} days)",
                    "Rotate krbtgt twice (allowing replication between resets) at least every 180 days and after any DA compromise.",
                    "MITRE T1558.001 (Golden Ticket)")
            continue
        if not enabled:
            continue
        if u.get("ServicePrincipalName"):
            add("AD-KRB-02", "critical" if priv else "high",
                "Kerberoastable privileged account" if priv else "Kerberoastable user account (SPN set)", sam,
                f"SPN={u['ServicePrincipalName'][0]}; pwd age {(today - pls).days if pls else '?'} days",
                "Use gMSA for services; otherwise 25+ char random password, AES-only encryption, and remove privileged rights.",
                "MITRE T1558.003 (Kerberoasting)")
        if u.get("DoesNotRequirePreAuth"):
            add("AD-KRB-03", "high", "Kerberos pre-authentication disabled (AS-REP roastable)", sam,
                "DoesNotRequirePreAuth=True", "Enable Kerberos pre-authentication.", "MITRE T1558.004 (AS-REP Roasting)")
        if u.get("TrustedForDelegation"):
            add("AD-KRB-04", "high", "Unconstrained delegation on user account", sam, "TrustedForDelegation=True",
                "Remove unconstrained delegation; use resource-based constrained delegation; mark admins 'sensitive and cannot be delegated'.",
                "MITRE T1558 / T1134")
        if u.get("PasswordNeverExpires") and priv:
            add("AD-PWD-01", "medium", "Privileged account with non-expiring, aged password", sam,
                f"PasswordNeverExpires; last set {pls}",
                "Privileged passwords should be managed (PAM/LAPS) or rotated on compromise; enforce 15+ chars + MFA.",
                "NIST SP 800-63B-4; CIS Controls v8.1 5.2")
        if (last and (today - last).days > cfg["ad_stale_days"]) or (not last and pls and (today - pls).days > cfg["ad_stale_days"]):
            add("AD-ACC-01", "high" if priv else "medium", "Stale enabled account", sam,
                f"last logon {last or 'never'}", "Disable after confirming with the manager; delete after 30 days.",
                "CIS Controls v8.1 5.3; MITRE T1078.002")
    return out


# =========================================================================== #
# Reporting
# =========================================================================== #

def write(findings: list[Finding], out: Path, today: date):
    out.mkdir(parents=True, exist_ok=True)
    (out / "identity_findings.json").write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    c = Counter(f.severity for f in findings)
    byp = Counter(f.platform for f in findings)
    md = ["# Cloud & Identity Security Audit", "",
          f"*As of:* {today} · *Findings:* {len(findings)} (critical {c['critical']}, high {c['high']}, "
          f"medium {c['medium']}, low {c['low']})  ",
          "*Platforms:* " + ", ".join(f"{k} ({v})" for k, v in byp.items()), ""]
    for plat in byp:
        md += [f"## {plat}", "", "| Sev | Check | Finding | Resource | Detail | Fix | Reference |", "|---|---|---|---|---|---|---|"]
        for f in findings:
            if f.platform == plat:
                md.append(f"| **{f.severity.upper()}** | {f.check} | {f.title} | `{f.resource}` | {f.detail} | {f.fix} | {f.references} |")
        md.append("")
    (out / "identity_findings.md").write_text("\n".join(md), encoding="utf-8")


DEFAULTS = {"key_max_age_days": 90, "stale_days": 45, "ad_stale_days": 90, "krbtgt_max_days": 180,
            "ga_min": 2, "ga_max": 4, "da_max": 4, "ca_max_exclusions": 3}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline cloud & identity posture audit")
    ap.add_argument("--aws", type=Path)
    ap.add_argument("--entra", type=Path)
    ap.add_argument("--ad", type=Path)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--as-of")
    ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    if not (a.aws or a.entra or a.ad):
        ap.error("provide at least one of --aws, --entra, --ad")
    cfg = dict(DEFAULTS)
    if a.config:
        cfg.update({k: v for k, v in json.loads(a.config.read_text()).items() if not k.startswith("_")})
    today = date.fromisoformat(a.as_of) if a.as_of else date.today()

    findings: list[Finding] = []
    if a.aws:
        findings += audit_aws(a.aws, today, cfg)
    if a.entra:
        findings += audit_entra(a.entra, today, cfg)
    if a.ad:
        findings += audit_ad(a.ad, today, cfg)
    findings.sort(key=lambda f: (SEV[f.severity], f.platform, f.check))
    write(findings, a.out, today)

    c = Counter(f.severity for f in findings)
    print(f"[+] {len(findings)} findings (critical {c['critical']}, high {c['high']}, medium {c['medium']}, low {c['low']})")
    for f in findings:
        print(f"    [{f.severity.upper():8}] {f.platform:<16} {f.check:<11} {f.title} :: {f.resource}")
    print(f"[+] Reports in {a.out}/")
    return 2 if c["critical"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
