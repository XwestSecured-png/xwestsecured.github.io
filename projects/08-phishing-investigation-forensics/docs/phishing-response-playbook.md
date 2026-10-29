# Playbook: Reported Phishing & Business Email Compromise

| Field | Value |
|---|---|
| Playbook ID | PB-IR-002 |
| Alignment | NIST SP 800-61r3 (CSF 2.0 Detect → Respond → Recover) · MITRE ATT&CK T1566, T1078.004, T1564.008, T1656 · CIS Controls v8.1 9, 14, 17 |
| Triggers | User report ("Report phishing" button), mail-gateway alert, `phish_analyzer.py` verdict ≥ SUSPICIOUS, finance team call-back on a bank change |

## 1. Triage: first 15 minutes

1. **Get the original.** Ask the reporter to use the Report button or forward the email *as an attachment* (.eml/.msg). A forwarded body loses the headers.
2. **Analyze safely.** Run `python3 phish_analyzer.py report.eml`. Don't click links or open attachments on a production workstation.
3. **Decide:**

| Verdict | Action |
|---|---|
| LIKELY BENIGN (< 35) | Thank the reporter, close with a note. Reports are good behavior, so always reply |
| SUSPICIOUS (35–69) | Analyst review. Treat as malicious if any credential-harvest link, smuggling or BEC payment language is present |
| MALICIOUS (≥ 70) | Open an incident and continue below |

## 2. Contain: first hour

| Action | Microsoft 365 example | Google Workspace example |
|---|---|---|
| Find every copy | Defender **Threat Explorer** / Content Search by Message-ID, sender or subject | Security investigation tool → Gmail log events |
| Purge from mailboxes | `New-ComplianceSearchAction -Purge -PurgeType SoftDelete` or Explorer "Soft delete" | "Delete message" action in the investigation tool |
| Block sender, domains, URLs, hashes | Tenant Allow/Block List (senders, URLs, files) | Blocked senders + content compliance rules |
| Block network IOCs | Import `reports/iocs.stix.json` / `iocs.csv` into the firewall, secure web gateway, DNS filter and EDR custom indicators | Same |

## 3. Scope: who is affected?

```bash
python3 timeline.py --phish reports/phish_results.json --trace message_trace.csv \
    --proxy proxy.csv --signins signins.csv --edr edr_events.csv
```

| Stage reached | Required response |
|---|---|
| Received only | Purge. No user action |
| Clicked | Confirm no form submission (proxy POST, EDR). Short awareness follow-up |
| Opened attachment | **Isolate endpoint**, collect triage, scan, check for persistence |
| Submitted credentials | **Reset password, revoke all sessions/refresh tokens**, verify MFA stopped the attacker |
| Compromised (successful attacker sign-in, inbox rule, MFA method added) | All of the above, plus: disable the account temporarily, remove malicious inbox rules and forwarding, review MailItemsAccessed for data exposure, search for onward phishing sent from the account, and check for new MFA methods or OAuth app consents |

**Pivot on what you learn.** Attacker IPs from sign-in logs (e.g., `203.0.113.88` in the sample) are new IOCs. Block them, then hunt for them across **all** users, not just the ones who received this email.

## 4. Business Email Compromise (payment fraud)

1. **Never** change payment details based on an email. Call the vendor back at a number already on file, not one from the email.
2. If money was sent: contact the bank's fraud department **immediately** to request a recall. File with the **FBI IC3** (ic3.gov). Speed matters most here.
3. Check whether the *vendor* is compromised (legitimate domain, DMARC pass) or *impersonated* (lookalike domain, mismatched Reply-To). Notify the vendor either way.
4. Add mandatory call-back verification for bank changes to the AP procedure.

## 5. Recover & improve

- Re-enable accounts after the credential reset, MFA re-registration and 30 days of heightened monitoring.
- Send a short, blameless awareness note to staff with a screenshot of the phish and how to spot it.
- **Tune controls:** DMARC `p=reject` for your own domains, lookalike-domain monitoring, external-sender banners, blocking HTML/ISO/LNK attachments at the gateway, and phishing-resistant MFA, which defeats credential relay.
- Track metrics: report rate, time-to-report, time-to-purge, click and submit rates.

## Evidence handling
Keep the original `.eml` (hashed by the analyzer), message trace exports, proxy and sign-in logs, and EDR triage packages under incident ID, in a restricted location, for the retention period your legal counsel sets.
