# Third-Party Risk Register (as of 2026-11-21)

Residual risk = inherent risk (data sensitivity × access × business criticality) reduced by verified controls, plus penalties for high-impact red flags.

| Vendor | Service | Inherent | Controls | Residual | Tier | Review cycle | Overdue |
|---|---|---|---|---|---|---|---|
| NetWatch MSP | Managed IT with remote admin access | 80 | 25% | **81** | Critical | 180 d | 551 d |
| AIScribe Notes | AI meeting transcription | 32 | 50% | **36** | High | 365 d | — |
| PayrollCloud Inc. | Payroll and HR SaaS | 60 | 95% | **20** | Moderate | 730 d | — |
| MarketMail Pro | Email marketing platform | 16 | 75% | **8** | Low | 1095 d | — |
| QuickPrint Supplies | Office supplies ordering | 1 | 10% | **1** | Low | 1095 d | — |

## NetWatch MSP (Critical)

- 🚩 **Privileged remote access without MFA: top supply-chain attack path**
- [ ] Request SOC 2 Type II report (or ISO 27001 certificate) and review exceptions
- [ ] Require MFA on every account with access to our data or systems
- [ ] Ask for SSO/SAML support so access is removed when staff leave
- [ ] Request latest third-party penetration test summary
- [ ] Add 72-hour breach notification clause to the contract
- [ ] Obtain list of sub-processors (fourth parties)
- [ ] Request evidence of tested business continuity / DR plan
- [ ] Confirm critical vulnerabilities are patched within a defined SLA

## AIScribe Notes (High)

- 🚩 **Vendor trains AI models on customer data: require opt-out in contract**
- [ ] Request SOC 2 Type II report (or ISO 27001 certificate) and review exceptions
- [ ] Request latest third-party penetration test summary
- [ ] Obtain list of sub-processors (fourth parties)
- [ ] Add certified data return/deletion at contract end
- [ ] Request evidence of tested business continuity / DR plan
- [ ] Confirm critical vulnerabilities are patched within a defined SLA
