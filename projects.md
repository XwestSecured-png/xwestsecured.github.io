# Projects

**Focus:** incident handling and DFIR, vulnerability analysis, and secure SQL practices.

| Focus area | Start here |
|---|---|
| Incident handling & DFIR | [09 Ransomware investigation](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/09-dfir-endpoint-triage-ransomware) · [08 Phishing investigation](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/08-phishing-investigation-forensics) · [01 Log triage](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/01-incident-response-log-triage) |
| Vulnerability analysis | [10 Web app vulnerability analysis](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/10-web-app-vulnerability-analysis) · [02 Risk-based remediation](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/02-vulnerability-management) |
| Secure SQL | [11 Secure PostgreSQL & breach forensics](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/11-secure-postgresql-db-forensics) · [03 Injection defense & SQL hunting](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/03-secure-sql-and-threat-hunting) |

Hands-on security projects with working code, sample data, generated reports, automated tests, and documentation mapped to current standards (NIST CSF 2.0, NIST SP 800-61r3, CIS Controls v8.1, OWASP Top 10:2025, MITRE ATT&CK).

---

## 01: Incident Response Log Triage Toolkit & Incident Handler's Journal
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/01-incident-response-log-triage)

A Python toolkit that correlates Linux and Windows authentication logs to detect brute force, password spraying, account compromise, persistence and log tampering, with each detection mapped to MITRE ATT&CK. Includes an IR playbook aligned to NIST SP 800-61r3, Sigma rules, and a structured **Incident Handler's Journal** covering two simulated compromises.

---

## 02: Vulnerability Assessment & Risk-Based Remediation
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/02-vulnerability-management)

Turns raw scanner output into a prioritized remediation plan using CVSS, the **CISA Known Exploited Vulnerabilities** catalog, **EPSS** exploit likelihood, and asset criticality. Includes read-only Linux and Windows hardening audits mapped to CIS Controls v8.1, plus a scanning SOP with rules of engagement.

---

## 03: Secure SQL, Injection Defense & SQL Threat Hunting
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/03-secure-sql-and-threat-hunting)

Side-by-side vulnerable and secure code showing five SQL injection attacks (OWASP Top 10:2025 A05) and the controls that stop them. Also includes ten documented SQL threat hunts (spray, impossible travel, compromise pivot, SQLi), a web-log SQLi detector, and a database hardening checklist.

---

## 04: Network Threat Detection & Firewall Policy Audit
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/04-network-threat-detection)

Zeek log analytics that detect port scans, C2 beaconing, data exfiltration and DNS tunneling (7/7 planted scenarios found, 0 false positives). Also includes a 10-check vendor-neutral firewall rule auditor, 11 validated Suricata rules, and a Zero Trust segmentation design.

---

## 05: NIST CSF 2.0 Gap Assessment, Risk Register & Policy Set
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/05-grc-csf2-risk-assessment)

A full security program assessment for a fictional multi-site nonprofit. It scores current vs. target maturity across all 22 NIST CSF 2.0 categories, keeps a risk register with inherent and residual heat maps and a risk-appetite check, and generates a board-ready report with a prioritized 90-day roadmap. Includes Information Security, Access Control and Vendor Risk policies.

---

## 06: Cloud & Identity Security Audit (AWS · Entra ID · Active Directory)
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/06-cloud-identity-security-audit)

Read-only collectors and an offline analyzer run 34 identity-security checks: root and IAM key hygiene, public S3 and exposed security groups, MFA strength and Conditional Access gaps, guest admins, Kerberoastable service accounts and krbtgt age. Includes a 30-day hardening plan and KQL/Athena detections.

---

## 07: Software Supply-Chain Security Toolkit
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/07-software-supply-chain-security)

Tools that address OWASP Top 10:2025 A03 Software Supply Chain Failures. A secrets scanner exports SARIF for GitHub code scanning, a CycloneDX SBOM generator inventories every build, and a dependency gate checks components against OSV, PyPI and npm advisories and turns 58 advisories into 6 upgrade actions. A hardened CI pipeline template enforces it all.

---

## 08: Phishing Investigation & Forensic Timeline
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/08-phishing-investigation-forensics)

Offline analysis of suspicious emails catches lookalike domains, deceptive links, HTML smuggling and business email compromise, then exports IOCs as STIX 2.1. A correlation tool combines mail, proxy, sign-in and EDR logs to find who clicked, who submitted credentials and who was compromised, and surfaces new attacker infrastructure along the way.

---

## 09: DFIR Endpoint Triage & Ransomware Investigation
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/09-dfir-endpoint-triage-ransomware)

A full DFIR case, from phishing email to encrypted file server. Read-only Windows and Linux live-response collectors gather evidence in order of volatility. A hash-verified analyzer decodes obfuscated PowerShell, detects credential dumping, lateral movement, C2 beaconing and mass encryption, and rebuilds the attack timeline across hosts. Includes a complete incident investigation report and chain-of-custody procedures.

---

## 10: Web Application Vulnerability Analysis (VulnLab)
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/10-web-app-vulnerability-analysis)

Vulnerable and secure builds of the same web app, with six findings (IDOR, stored XSS, SSRF, path traversal, forgeable sessions, information disclosure). Each one has a proof of concept, a CVSS v3.1 score, root-cause code and a fix. An automated harness proves every issue is exploitable before the fix, blocked after it, and that the feature still works.

---

## 11: Secure PostgreSQL & Database Breach Forensics
[View project](https://github.com/XwestSecured-png/xwestsecured.github.io/tree/main/projects/11-secure-postgresql-db-forensics)

A hardened PostgreSQL database using least-privilege roles, row-level security, column encryption, audited access functions and a tamper-evident hash-chained audit trail. It is tested against an insider data-theft scenario, and SQL-only forensics produce the exact breach scope for notification: 120 records exposed, and other sites protected.

---

## TryHackMe Journal
[My TryHackMe Profile](https://tryhackme.com/p/westwings85)

A collection of walkthroughs, notes, and analysis from hands-on cybersecurity labs.

---

[Home](index.md) | [About Me](about.md)
