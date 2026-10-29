# Phishing Analysis Report

| Email | Verdict | Score | Subject | From | ATT&CK |
|---|---|---|---|---|---|
| `01_credential_phish.eml` | **MALICIOUS** | 100 | Action Required: Payroll portal password expires today | `Corp IT Helpdesk <helpdesk@c0rp.example>` | T1027.006, T1566.001, T1566.002 |
| `02_bec_vendor_fraud.eml` | **MALICIOUS** | 85 | RE: Invoice INV-20931 overdue - updated banking details | `Dana Whitfield <dana.whitfield@payflow-billing.example>` | T1656 |
| `03_legit_newsletter.eml` | **LIKELY BENIGN** | 0 | Weekly update: volunteer day and new parking lot hours | `Corp Communications <news@corp.example>` | - |

## 01_credential_phish.eml: MALICIOUS (100/100)

- **Subject:** Action Required: Payroll portal password expires today
- **From:** `Corp IT Helpdesk <helpdesk@c0rp.example>` · **Reply-To:** `-` · **Return-Path:** `bounce@c0rp.example`
- **Date (UTC):** 2026-10-27T14:03:05Z · **Origin IP:** 203.0.113.45 · **Hops:** 2
- **SPF / DKIM / DMARC:** pass / none / none
- **File SHA-256:** `2d492110c76bc304552b9e7e5eb178d3ffea79dd334ee846673348f4e3565d71`

**Signals**

| Points | Category | Detail |
|---|---|---|
| +35 | sender | From domain 'c0rp.example' is a lookalike of protected domain 'corp.example' |
| +30 | attachments | Payroll_Update_Nov2026.pdf.html: JavaScript decoding/Blob pattern (HTML smuggling, T1027.006) |
| +30 | attachments | Payroll_Update_Nov2026.pdf.html: embedded login form posts to https://198.51.100.23/owa/auth.php |
| +25 | links | Link text shows 'portal.corp.example' but points to 'c0rp-portal.example' |
| +25 | attachments | Risky attachment type: Payroll_Update_Nov2026.pdf.html |
| +25 | attachments | Double extension: Payroll_Update_Nov2026.pdf.html |
| +20 | sender | Display name 'Corp IT Helpdesk' impersonates an internal/trusted brand from external domain |
| +20 | content | Urgency / pressure language: action required, password expires, verify your account, within 24 hours |
| +10 | links | External link with login/verify-style path |
| +8 | authentication | DMARC result missing |
| +5 | authentication | DKIM result missing |

**Links (not visited)**

| URL | Shown text | Notes |
|---|---|---|
| `https[:]//c0rp-portal.example/login/verify?u=staff` | https://portal.corp.example/payroll | text shows portal.corp.example, credential-harvest path |

**Attachments (not opened)**

| Name | Declared / true type | Size | SHA-256 | Notes |
|---|---|---|---|---|
| Payroll_Update_Nov2026.pdf.html | text/html / html | 391 | `17c11fcc55103e5a…` | risky type .html, double extension, HTML smuggling / obfuscated JS, form posts to 198.51.100.23 |

## 02_bec_vendor_fraud.eml: MALICIOUS (85/100)

- **Subject:** RE: Invoice INV-20931 overdue - updated banking details
- **From:** `Dana Whitfield <dana.whitfield@payflow-billing.example>` · **Reply-To:** `dana.payflow@mail.example.net` · **Return-Path:** `dana.whitfield@payflow-billing.example`
- **Date (UTC):** 2026-10-28T16:41:22Z · **Origin IP:** 198.51.100.77 · **Hops:** 1
- **SPF / DKIM / DMARC:** pass / pass / pass
- **File SHA-256:** `c57cf4bcfc2fcfe58dc95523dc1a80ef4fa93bdb8d32888762f4ce75e1aca99c`

**Signals**

| Points | Category | Detail |
|---|---|---|
| +35 | sender | From domain 'payflow-billing.example' is a lookalike of protected domain 'payflow.example' |
| +30 | content | BEC / payment-fraud language: keep this confidential, new account number, routing number, updated banking details, wire transfer |
| +20 | sender | Reply-To (dana.payflow@mail.example.net) differs from From (dana.whitfield@payflow-billing.example) |

## 03_legit_newsletter.eml: LIKELY BENIGN (0/100)

- **Subject:** Weekly update: volunteer day and new parking lot hours
- **From:** `Corp Communications <news@corp.example>` · **Reply-To:** `-` · **Return-Path:** `news@corp.example`
- **Date (UTC):** 2026-10-29T12:00:00Z · **Origin IP:** - · **Hops:** 1
- **SPF / DKIM / DMARC:** pass / pass / pass
- **File SHA-256:** `ee00017d6a67ac01ced7dcde066390f3b88fbe721775b12f4fbe385bfd798dcc`

**Signals**

| Points | Category | Detail |
|---|---|---|
| 0 | - | none |

**Links (not visited)**

| URL | Shown text | Notes |
|---|---|---|
| `https[:]//intranet.corp.example/news/2026-44` | intranet | - |
