# Vendor (Third-Party) Risk Management Policy

| Field | Value |
|---|---|
| Policy ID | POL-VRM-003 |
| Version | 1.0 (template) |
| Owner | Operations Manager (with IT Director) |
| Framework mapping | NIST CSF 2.0 GV.SC-01–10 · NIST SP 800-161r1 · CIS Controls v8.1 Control 15 |

## 1. Vendor tiering
| Tier | Criteria | Due diligence | Reassessment |
|---|---|---|---|
| **Critical** | Stores or processes Confidential/Restricted data (client PII, PHI, payment data) **or** an outage stops core services | Full questionnaire + SOC 2 Type II / ISO 27001 certificate review + contract security clauses | Annually |
| **High** | Has access to internal systems or network | Questionnaire + evidence of MFA/encryption | Annually |
| **Low** | No data access, no system access | Basic review at onboarding | At renewal |

## 2. Minimum contract clauses (Critical/High)
- Breach notification to the organization within **72 hours** of discovery.
- Data stays encrypted in transit (TLS 1.2+) and at rest.
- Data is returned or securely deleted at contract end, with certification.
- The organization has a right to request security evidence (audit reports, penetration test summaries).
- Subcontractors (fourth parties) are disclosed and held to equivalent terms.
- Cyber liability insurance minimums apply.

## 3. Security questionnaire (core 12)
1. Do you hold a current SOC 2 Type II or ISO/IEC 27001 certification? Please provide the report or certificate.
2. Is MFA enforced for all workforce and administrator access to systems holding our data?
3. Is our data encrypted at rest and in transit? Who manages the keys?
4. Where (countries/regions) is our data stored and processed?
5. How quickly are critical and actively exploited vulnerabilities patched?
6. Do you have an incident response plan, and when was it last tested?
7. What are your breach notification commitments to customers?
8. How are backups protected (immutability, offsite) and how often are restores tested?
9. Do you perform independent penetration testing at least annually?
10. How do you manage subcontractors who can access our data?
11. Do you provide SSO (SAML/OIDC) and audit logs to customers?
12. Do you provide an SBOM or vulnerability disclosure (VEX) for software you supply? (See Project 07.)

## 4. Monitoring
The IT Director keeps the vendor inventory (name, tier, data types, owner, contract end date, last review). Vendor breaches reported in the news or by the vendor trigger an immediate review under the Incident Response playbook.
