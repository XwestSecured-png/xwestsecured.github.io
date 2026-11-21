# Incident Severity & Escalation Matrix

Adapt the names, phone trees and times to your organization. Times are **maximums** from the moment an analyst confirms the incident.

## Severity levels

| Severity | Definition (any one is enough) | Examples |
|---|---|---|
| **SEV-1 Critical** | Business-wide outage or active encryption; confirmed exfiltration of regulated data (PII, PHI, payment); compromise of domain admin, cloud root or identity provider | Ransomware spreading; domain controller compromised; customer database dumped |
| **SEV-2 High** | Confirmed compromise of a server or privileged account, contained to one system or team; likely data exposure under investigation | Web server web shell; admin account takeover; BEC with wire-transfer attempt |
| **SEV-3 Medium** | Confirmed compromise of a single standard user or workstation, no evidence of spread | Malware on one laptop; one phished mailbox with no rule changes |
| **SEV-4 Low** | Policy violation or blocked attack with no compromise | Blocked phishing campaign; unapproved software; failed brute force |

## Who is notified, and how fast

| Role | SEV-1 | SEV-2 | SEV-3 | SEV-4 |
|---|---|---|---|---|
| SOC on-call analyst | Immediately | Immediately | Immediately | Next business day |
| Incident Commander (IR lead) | 15 min, phone | 30 min, phone | 4 h, ticket | — |
| CISO / Head of Security | 30 min, phone | 2 h, phone | Daily summary | Weekly report |
| IT Operations lead | 30 min | 2 h | As needed | — |
| Legal / Privacy counsel | 1 h | 4 h if data may be involved | — | — |
| Executive sponsor (CEO/COO) | 1 h | 24 h summary | — | — |
| Communications / PR | 2 h | If external impact | — | — |
| Cyber insurer / IR retainer | Within policy window (often 24–72 h) | Per policy | — | — |
| Board / audit committee | 24 h | Next scheduled meeting | — | — |

## RACI for the main decisions

R = Responsible, A = Accountable, C = Consulted, I = Informed

| Decision | IC | SOC | IT Ops | CISO | Legal | Comms | Exec |
|---|---|---|---|---|---|---|---|
| Declare incident and severity | A | R | I | C | I | I | I |
| Isolate hosts / disable accounts | A | R | R | I | — | — | — |
| Take a business system offline | R | C | R | C | I | I | **A** |
| Engage outside IR firm / insurer | R | — | — | **A** | C | — | I |
| Notify regulators, customers, law enforcement | C | — | — | C | **A/R** | C | I |
| External statement | C | — | — | C | C | R | **A** |
| Any ransom payment discussion (incl. OFAC sanctions check) | C | — | — | C | R | — | **A** |
| Declare recovery complete | A | R | R | C | I | I | I |

## Rules that are never skipped

1. **Preserve evidence before you fix.** Image or snapshot first when it won't let the attacker spread.
2. **Out-of-band communication** for SEV-1/2 (phone bridge or a separate chat tenant). Assume email may be read by the attacker.
3. **One incident commander** at a time; handoffs are announced on the bridge and logged.
4. **Log every decision** with time, who decided and why. This becomes the legal timeline.
5. **Regulatory clocks** start at *discovery*, not confirmation: for example, SEC 8-K Item 1.05 (4 business days after a materiality determination), HIPAA (60 days), GDPR (72 hours), state breach laws (vary), and CIRCIA reporting for covered critical-infrastructure entities once its final rule takes effect. Legal owns the determination.
