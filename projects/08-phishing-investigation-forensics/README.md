# Project 08: Phishing Investigation & Forensic Timeline

**Skills shown:** email forensics (headers, SPF/DKIM/DMARC) · malicious URL & attachment triage · HTML smuggling · business email compromise · threat intel sharing (STIX 2.1) · log correlation & incident scoping · Python

Phishing is still the most common way attackers get in. This project covers a full phishing investigation, from the user's report to the incident commander's briefing:

1. **`phish_analyzer.py`**: safe, offline static analysis of `.eml` files. It scores authentication results, sender spoofing, lookalike domains, deceptive links, HTML smuggling attachments and BEC language, then exports IOCs as **CSV and a STIX 2.1 bundle**.
2. **`timeline.py`**: correlates those IOCs with **message trace, web proxy, Entra ID sign-in and EDR logs**. It answers *who received, clicked, opened, submitted credentials, and got compromised*, and builds a UTC super-timeline.
3. **[Phishing & BEC response playbook](docs/phishing-response-playbook.md)** aligned to NIST SP 800-61r3, with Microsoft 365 and Google Workspace actions.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![STIX](https://img.shields.io/badge/STIX-2.1-orange) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Results

### Email triage

```
[MALICIOUS    ] 100/100  01_credential_phish.eml   Action Required: Payroll portal password expires today
        +35  From domain 'c0rp.example' is a lookalike of protected domain 'corp.example'
        +30  Payroll_Update_Nov2026.pdf.html: JavaScript decoding/Blob pattern (HTML smuggling, T1027.006)
        +30  Payroll_Update_Nov2026.pdf.html: embedded login form posts to https://198.51.100.23/owa/auth.php
        +25  Link text shows 'portal.corp.example' but points to 'c0rp-portal.example'
[MALICIOUS    ]  85/100  02_bec_vendor_fraud.eml   RE: Invoice INV-20931 overdue - updated banking details
        +35  From domain 'payflow-billing.example' is a lookalike of protected domain 'payflow.example'
        +30  BEC / payment-fraud language: keep this confidential, new account number, routing number, ...
        +20  Reply-To (dana.payflow@mail.example.net) differs from From (dana.whitfield@payflow-billing.example)
[LIKELY BENIGN]   0/100  03_legit_newsletter.eml   Weekly update: volunteer day and new parking lot hours
```

The BEC email **passes SPF, DKIM and DMARC**, because the attacker registered their own lookalike domain. Authentication only proves who sent a message, not whether they're honest. The analyzer still catches it through the lookalike domain, the Reply-To redirect and the payment-change language.

The STIX bundle was validated with the OASIS `stix2` Python library (`stix2.parse`).

### Incident scope

```
[+] Exposure funnel: received 6 → clicked 2 → opened attachment 1 → submitted credentials 2 → compromised 1
    jdoe       compromised            Disable sign-in, revoke sessions/refresh tokens, reset password, re-register MFA, remove inbox rules ...
    tnguyen    submitted_credentials  Reset password, revoke sessions, confirm MFA blocked attacker, monitor sign-ins 30 days
[!] New attacker IOCs from sign-in pivot: 203.0.113.88
```

How the evidence lines up for the two users who matter:

- **jdoe** clicked the link at 14:09 and submitted credentials at 14:10. The attacker signed in from the Netherlands at 14:31 and created a hidden inbox rule at 14:34 that moves *payroll / invoice / bank* emails out of sight, a classic setup for a follow-on BEC.
- **tnguyen** opened the HTML-smuggling attachment (EDR shows Outlook → Edge) and submitted credentials through the embedded form. **The attacker's sign-ins were blocked by MFA**, so no compromise. That's the evidence that the MFA rollout worked.
- The attacker's **sign-in IP wasn't in the email at all**. It was found by pivoting from the confirmed victim's sign-ins, and becomes a new IOC to hunt for org-wide.

Full outputs: [`reports/phish_report.md`](reports/phish_report.md) · [`reports/incident_timeline.md`](reports/incident_timeline.md) · [`reports/iocs.stix.json`](reports/iocs.stix.json) · [`reports/iocs.csv`](reports/iocs.csv)

## Detection logic

| Area | Signals |
|---|---|
| Authentication | SPF/DKIM/DMARC fail or missing; Return-Path ≠ From; Reply-To to a different or free-mail domain |
| Sender | Lookalike domains by **homoglyph skeleton** (`c0rp`→`corp`, `rn`→`m`, punycode decoding), **Levenshtein distance ≤ 2**, and brand-in-domain (`payflow-billing`); display-name impersonation of internal brands |
| Links | Shown text vs. real destination, IP-literal URLs, shorteners, punycode, login/verify paths on external hosts, links to lookalikes. **Links are never fetched** |
| Attachments | SHA-256, magic-byte true type vs. extension, double extensions, risky types (HTML, SVG, ISO/IMG, LNK, OneNote, macro docs, scripts), **HTML smuggling** (`atob`, `Blob`, `fromCharCode`), embedded credential forms |
| Content | Urgency phrases; BEC phrases (bank change, wire, gift cards, confidentiality) |

## Standards alignment

| Standard | Coverage |
|---|---|
| **MITRE ATT&CK** | T1566.001/.002 Phishing, T1204.001/.002 User Execution, T1027.006 HTML Smuggling, T1056.003 Web Portal Capture, T1078.004 Cloud Accounts, T1564.008 Email Hiding Rules, T1656 Impersonation |
| **NIST SP 800-61r3 / CSF 2.0** | DE.AE-02/03 (analysis, correlation), RS.AN-03/06/07 (analysis, evidence), RS.MA, RS.MI |
| **STIX 2.1 (OASIS)** | Indicator objects with STIX patterns for URL, domain, IPv4, email address and file hash |
| **CIS Controls v8.1** | 9 (Email & Web Browser Protections), 14 (Security Awareness), 17 (Incident Response) |
| **DMARC (RFC 7489)**, **SPF (RFC 7208)**, **DKIM (RFC 6376)** | Header authentication interpretation |

## Quick start

```bash
python3 samples/generate_samples.py                       # (re)build the synthetic .eml files
python3 phish_analyzer.py samples/*.eml --config config.json --out reports/
python3 timeline.py --phish reports/phish_results.json --trace logs/message_trace.csv \
    --proxy logs/proxy.csv --signins logs/signins.csv --edr logs/edr_events.csv --out reports/
python3 -m unittest discover -s tests -v
```

## Adapting to your environment

| Input | Where to get it |
|---|---|
| `.eml` | Outlook: drag the message to a folder (.msg → convert with `msgconvert`) or *Download message* in OWA; Gmail: *Show original → Download*; report mailbox exports |
| Message trace | M365: `Get-MessageTraceV2` / Explorer export; Google: Email Log Search export |
| Proxy / DNS | Secure web gateway, firewall URL logs, Zscaler/Umbrella/Netskope CSV exports, Zeek `http.log` |
| Sign-ins | Entra ID sign-in logs export (or Okta System Log), with columns mapped to `ts_utc,user,ip,country,app,client,result` |
| EDR | Defender Advanced Hunting (`DeviceFileEvents`, `DeviceProcessEvents`), CrowdStrike, SentinelOne CSV exports |

Edit `config.json` with **your** domains, key vendors' domains (to catch vendor impersonation), brand names and egress IPs (`--known-ips`).

## Safety & ethics

- The analyzer never resolves, fetches or renders anything. URLs in the report are defanged (`https[:]//`).
- Sample emails are synthetic. Domains use the reserved `.example` TLD, IPs are RFC 5737 documentation addresses, and the "malicious" attachment is inert demo HTML.
- Real phishing samples and logs contain personal data. Handle them under your incident evidence procedures.

## Lessons learned

1. **DMARC pass ≠ safe.** Lookalike domains authenticate perfectly. Domain similarity and reply-path analysis catch what authentication can't.
2. **Scope by stage, not by recipient.** Five people received the phish but only one account was compromised. A funnel keeps the response proportionate.
3. **Pivot.** The attacker's sign-in IP was the most valuable IOC, and it wasn't in the email.
4. **MFA helped, but not every type of MFA.** Two users gave up passwords. MFA stopped the attacker for tnguyen, but jdoe's account was still taken over. That fits MFA not being enforced for that sign-in, or an adversary-in-the-middle relay, which is exactly what phishing-resistant MFA (FIDO2/passkeys) prevents (see Projects 05 and 06).
