# Assessment Methodology

## 1. Scoping
1. Name the business mission, the critical services and the data types (GV.OC).
2. List applicable laws, regulations and contracts.
3. Agree on the assessment boundary: sites, cloud tenants and business units.

## 2. Evidence collection
For each of the **22 CSF 2.0 categories**, gather evidence through:
- **Interviews** with the people who own the process (IT, HR, Operations, Finance, Executive).
- **Document review**: policies, procedures, diagrams, contracts, training records.
- **Technical validation**: outputs from Projects 01–04 and 06–07 (hardening audits, vulnerability scans, firewall audits, identity audits).

Rule of thumb: **no evidence means no credit.** A process that exists only "in someone's head" scores no higher than 1 (Partial).

## 3. Scoring
| Score | Level | Meaning |
|---|---|---|
| 0 | Not implemented | Nothing in place |
| 1 | Partial | Ad hoc and reactive. Depends on individuals |
| 2 | Risk Informed | Practices approved by management but not organization-wide or consistent |
| 3 | Repeatable | Formal, documented, consistently applied and measured |
| 4 | Adaptive | Continuously improved based on lessons learned and threat intelligence |

The **Target** score for each category comes from risk appetite, regulatory requirements and budget. Not everything needs a 4. The **weight** (0.5 to 2.0) shows how much the category matters to this organization's top risks.

## 4. Prioritization
`priority = (target − current) × weight`. The top five items become the 90-day plan. Each roadmap item links to risks in the register, so leadership can see which risks each investment reduces.

## 5. Risk analysis
- **Inherent risk** is likelihood × impact with existing controls only.
- **Residual risk** is the same calculation after the planned controls are in place.
- Each risk gets one **treatment**: Mitigate, Transfer (insurance or contract), Avoid (stop the activity), or Accept (documented, owner-signed, with an expiry).
- Risks whose residual score exceeds the appetite go to the Executive Director for a decision.

## 6. Reporting cadence
| Audience | Content | Frequency |
|---|---|---|
| Board | KPI dashboard, top 5 risks, roadmap status | Quarterly |
| Executive team | Full report, risk acceptances | Quarterly |
| IT | Roadmap backlog (`roadmap.csv`) | Monthly |
| All | Re-assessment of the CSF profile | Annually |
