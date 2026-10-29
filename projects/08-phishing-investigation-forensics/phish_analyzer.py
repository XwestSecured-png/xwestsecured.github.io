#!/usr/bin/env python3
"""
Phishing Email Analyzer
=======================

Static, offline triage of suspicious emails (.eml). Nothing is opened, rendered,
executed or fetched: links are never visited and attachments are only hashed
and inspected as bytes, so it is safe to run on live phishing samples.

Checks
  Authentication   SPF / DKIM / DMARC results, Return-Path and Reply-To alignment
  Sender           display-name spoofing, lookalike / homoglyph / punycode domains
  Routing          Received chain, originating IP, hop count
  Links            text-vs-href mismatch, IP-literal URLs, shorteners, punycode,
                   credential-harvest paths, links to lookalike domains
  Attachments      SHA-256, true type vs extension, double extensions, risky types
                   (HTML smuggling, ISO/IMG/LNK/OneNote/macro docs), embedded forms
  Content          urgency, payment-change and credential-request language (BEC)

Outputs a scored verdict, Markdown report, IOC CSV and a STIX 2.1 bundle for
sharing with a SIEM, TIP or ISAC.

    python3 phish_analyzer.py samples/*.eml --config config.json --out reports/

Maps to: MITRE ATT&CK T1566.001/.002, T1656, T1027.006 · NIST CSF 2.0 DE.AE, RS.AN · CIS Control 9
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_CFG = {
    "protected_domains": ["corp.example"],
    "trusted_brands": ["Corp IT", "IT Helpdesk", "Payroll", "HR"],
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "shorteners": ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "ow.ly", "rebrand.ly"],
    "freemail": ["gmail.com", "outlook.com", "yahoo.com", "proton.me", "aol.com", "mail.example.net"],
}
RISKY_EXT = {".html": 25, ".htm": 25, ".shtml": 25, ".svg": 20, ".iso": 30, ".img": 30, ".vhd": 30, ".lnk": 35,
             ".js": 35, ".jse": 35, ".vbs": 35, ".wsf": 35, ".hta": 35, ".exe": 35, ".scr": 35, ".msi": 30,
             ".one": 30, ".docm": 25, ".xlsm": 25, ".pptm": 25, ".xll": 35, ".zip": 10, ".rar": 15, ".7z": 15}
MAGIC = [(b"%PDF", "pdf"), (b"PK\x03\x04", "zip/ooxml"), (b"MZ", "pe-executable"), (b"\xd0\xcf\x11\xe0", "ole/office97"),
         (b"CD001", "iso"), (b"<!DOCTYPE html", "html"), (b"<html", "html"), (b"<svg", "svg"), (b"\x89PNG", "png"),
         (b"\xff\xd8\xff", "jpeg"), (b"L\x00\x00\x00", "lnk")]
URGENCY = re.compile(r"(?i)\b(urgent|immediately|within 24 hours|account (?:will be )?(?:suspended|locked|disabled)|"
                     r"final notice|action required|verify your (?:account|identity)|unusual (?:sign-?in|activity)|"
                     r"password (?:expires|expired))\b")
BEC = re.compile(r"(?i)\b(wire transfer|updated? (?:bank|banking|payment) (?:details|information)|new account number|"
                 r"routing number|gift cards?|invoice (?:is )?(?:attached|overdue)|change (?:of|to) (?:bank|payment)|"
                 r"keep this confidential|are you available)\b")
CRED_PATH = re.compile(r"(?i)(log-?in|sign-?in|verify|validate|account|password|sso|auth|secure|update|wp-admin|owa)")
HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "@": "a", "$": "s"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(domain: str) -> str:
    d = domain.lower()
    if d.startswith("xn--") or ".xn--" in d:
        try:
            d = d.encode().decode("idna")
        except UnicodeError:
            pass
    return d.translate(HOMO).replace("rn", "m").replace("vv", "w").replace("-", "")


def lookalike(domain: str, protected: list[str]) -> str | None:
    d = domain.lower().strip(".")
    for p in protected:
        if d == p or d.endswith("." + p):
            return None
        if skeleton(d) == skeleton(p) or lev(d, p) <= 2 or (p.split(".")[0] in d and len(p.split(".")[0]) >= 4):
            return p
    return None


def reg_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []
        self.forms = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        if tag == "form":
            self.forms.append(a.get("action", ""))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def analyze(path: Path, cfg: dict) -> dict:
    msg = BytesParser(policy=policy.default).parse(path.open("rb"))
    raw = path.read_bytes()
    nets = [ipaddress.ip_network(n) for n in cfg["internal_networks"]]
    signals, iocs = [], []

    def sig(points, category, text):
        signals.append({"points": points, "category": category, "detail": text})

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    rp = parseaddr(str(msg.get("Return-Path", "")))[1]
    rt = [a for _, a in getaddresses([str(msg.get("Reply-To", ""))]) if a]
    subject = str(msg.get("Subject", ""))
    try:
        date = parsedate_to_datetime(str(msg.get("Date"))).astimezone(timezone.utc)
    except (TypeError, ValueError):
        date = None

    # ---- Authentication
    ar = " ".join(str(h) for h in msg.get_all("Authentication-Results", []) or []).lower()
    auth = {k: (re.search(rf"\b{k}=(\w+)", ar).group(1) if re.search(rf"\b{k}=(\w+)", ar) else "none")
            for k in ("spf", "dkim", "dmarc")}
    for k, pts in (("spf", 15), ("dkim", 15), ("dmarc", 25)):
        if auth[k] in ("fail", "softfail", "permerror"):
            sig(pts, "authentication", f"{k.upper()}={auth[k]}")
        elif auth[k] == "none":
            sig(pts // 3, "authentication", f"{k.upper()} result missing")
    if rp and rp.split("@")[-1].lower() != from_dom:
        sig(10, "sender", f"Return-Path domain ({rp.split('@')[-1]}) ≠ From domain ({from_dom})")
    for r in rt:
        rdom = r.split("@")[-1].lower()
        if rdom != from_dom:
            sig(20 if rdom in cfg["freemail"] else 15, "sender", f"Reply-To ({r}) differs from From ({from_addr})")
            iocs.append(("email-addr", r))

    # ---- Sender identity
    la = lookalike(from_dom, cfg["protected_domains"]) if from_dom else None
    if la:
        sig(35, "sender", f"From domain '{from_dom}' is a lookalike of protected domain '{la}'")
        iocs.append(("domain-name", from_dom))
    if from_name and any(b.lower() in from_name.lower() for b in cfg["trusted_brands"]) and \
            not any(from_dom == p or from_dom.endswith("." + p) for p in cfg["protected_domains"]):
        sig(20, "sender", f"Display name '{from_name}' impersonates an internal/trusted brand from external domain")
    if "@" in from_name and parseaddr(from_name)[1].lower() != from_addr.lower():
        sig(20, "sender", f"Display name contains a different address: '{from_name}'")
    if from_dom in cfg["freemail"]:
        sig(5, "sender", "Sent from a free-mail provider")

    # ---- Received chain
    hops = msg.get_all("Received", []) or []
    origin_ip = None
    for h in reversed(hops):  # oldest first
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(h)):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not any(a in n for n in nets) and not a.is_loopback:
                origin_ip = ip
                break
        if origin_ip:
            break
    if origin_ip:
        iocs.append(("ipv4-addr", origin_ip))

    # ---- Body & links
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        fname = part.get_filename()
        if disp == "attachment" or fname:
            data = part.get_payload(decode=True) or b""
            attachments.append((fname or "unnamed", part.get_content_type(), data))
        elif part.get_content_type() == "text/plain":
            text_parts.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html_parts.append(part.get_content())
    body_text = "\n".join(text_parts)
    links = []
    for h in html_parts:
        lp = LinkParser(); lp.feed(h)
        links += lp.links
        body_text += "\n" + re.sub(r"<[^>]+>", " ", html.unescape(h))
    links += [(u, "") for u in URL_RE.findall("\n".join(text_parts)) if u not in {l[0] for l in links}]

    url_findings = []
    for href, text in links:
        u = urlparse(href.strip())
        if u.scheme not in ("http", "https"):
            continue
        host = (u.hostname or "").lower()
        notes = []
        if is_ip(host):
            notes.append("IP-literal URL"); sig(20, "links", f"Link to raw IP address: {host}")
        if host in cfg["shorteners"]:
            notes.append("URL shortener"); sig(10, "links", f"Shortened URL hides destination: {href}")
        if "xn--" in host:
            notes.append("punycode"); sig(20, "links", f"Punycode (IDN) domain: {host}")
        lah = lookalike(host, cfg["protected_domains"])
        if lah:
            notes.append(f"lookalike of {lah}"); sig(30, "links", f"Link to lookalike domain {host} (imitates {lah})")
        shown = URL_RE.search(text or "")
        shown_host = urlparse(shown.group(0)).hostname if shown else (text if re.fullmatch(r"[\w.-]+\.[a-z]{2,}", text or "") else None)
        if shown_host and reg_domain(shown_host) != reg_domain(host):
            notes.append(f"text shows {shown_host}"); sig(25, "links", f"Link text shows '{shown_host}' but points to '{host}'")
        if CRED_PATH.search(u.path or "") and not any(host == p or host.endswith("." + p) for p in cfg["protected_domains"]):
            notes.append("credential-harvest path")
        if notes or not any(host.endswith(p) for p in cfg["protected_domains"]):
            iocs.append(("url", href)); iocs.append(("ipv4-addr" if is_ip(host) else "domain-name", host))
        url_findings.append({"url": href, "host": host, "text": text[:60], "notes": notes})
    if any("credential-harvest path" in f["notes"] for f in url_findings):
        sig(10, "links", "External link with login/verify-style path")

    # ---- Attachments
    att_findings = []
    for name, ctype, data in attachments:
        sha = hashlib.sha256(data).hexdigest()
        ext = Path(name.lower()).suffix
        true_type = next((t for m, t in MAGIC if data.lstrip()[:20].lower().startswith(m.lower())), "unknown")
        notes = []
        if ext in RISKY_EXT:
            notes.append(f"risky type {ext}"); sig(RISKY_EXT[ext], "attachments", f"Risky attachment type: {name}")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.[a-z0-9]{2,4}$", name.lower()):
            notes.append("double extension"); sig(25, "attachments", f"Double extension: {name}")
        if true_type == "html" and ext not in (".html", ".htm"):
            notes.append("HTML disguised"); sig(20, "attachments", f"{name} is actually HTML")
        if true_type in ("html", "svg"):
            body = data.decode("utf-8", "replace")
            if re.search(r"atob\(|fromCharCode|unescape\(|new Blob\(|msSaveOrOpenBlob|data:application/", body):
                notes.append("HTML smuggling / obfuscated JS"); sig(30, "attachments", f"{name}: JavaScript decoding/Blob pattern (HTML smuggling, T1027.006)")
            for act in re.findall(r"<form[^>]+action=[\"']([^\"']+)", body, re.I):
                notes.append(f"form posts to {urlparse(act).hostname}")
                sig(30, "attachments", f"{name}: embedded login form posts to {act}")
                ah = urlparse(act).hostname or ""
                iocs.append(("url", act)); iocs.append(("ipv4-addr" if is_ip(ah) else "domain-name", ah))
        if true_type == "pe-executable":
            notes.append("Windows executable"); sig(40, "attachments", f"{name} is a Windows executable")
        iocs.append(("file:sha256", sha))
        att_findings.append({"name": name, "content_type": ctype, "true_type": true_type, "size": len(data),
                             "sha256": sha, "notes": notes})

    # ---- Language
    urg = sorted({m.group(0).lower() for m in URGENCY.finditer(subject + " " + body_text)})
    bec = sorted({m.group(0).lower() for m in BEC.finditer(subject + " " + body_text)})
    if urg:
        sig(min(10 + 5 * len(urg), 20), "content", f"Urgency / pressure language: {', '.join(urg)}")
    if bec:
        sig(min(15 + 5 * len(bec), 30), "content", f"BEC / payment-fraud language: {', '.join(bec)}")

    score = min(sum(s["points"] for s in signals), 100)
    verdict = "MALICIOUS" if score >= 70 else "SUSPICIOUS" if score >= 35 else "LIKELY BENIGN"
    attack = set()
    if any(s["category"] == "links" for s in signals): attack.add("T1566.002")
    if any(s["category"] == "attachments" for s in signals): attack.add("T1566.001")
    if bec: attack.add("T1656")
    if any("smuggling" in n for a in att_findings for n in a["notes"]): attack.add("T1027.006")
    seen, uniq = set(), []
    for t, v in iocs:
        if v and (t, v) not in seen:
            seen.add((t, v)); uniq.append({"type": t, "value": v})
    return {"file": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "message_id": str(msg.get("Message-ID", "")),
            "date_utc": date.isoformat().replace("+00:00", "Z") if date else None, "subject": subject,
            "from": f"{from_name} <{from_addr}>", "reply_to": rt, "return_path": rp, "auth": auth, "origin_ip": origin_ip,
            "hops": len(hops), "links": url_findings, "attachments": att_findings, "score": score, "verdict": verdict,
            "attack": sorted(attack), "signals": sorted(signals, key=lambda s: -s["points"]), "iocs": uniq}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def stix_bundle(results: list[dict]) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'xwestsecured-phish-analyzer')}"
    objs = [{"type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now,
             "name": "phish_analyzer.py", "identity_class": "system"}]
    pattern = {"url": "[url:value = '{}']", "domain-name": "[domain-name:value = '{}']",
               "ipv4-addr": "[ipv4-addr:value = '{}']", "email-addr": "[email-addr:value = '{}']",
               "file:sha256": "[file:hashes.'SHA-256' = '{}']"}
    seen = set()
    for r in results:
        if r["verdict"] == "LIKELY BENIGN":
            continue
        for i in r["iocs"]:
            key = (i["type"], i["value"])
            if key in seen:
                continue
            seen.add(key)
            val = i["value"].replace("\\", "\\\\").replace("'", "\\'")
            objs.append({"type": "indicator", "spec_version": "2.1",
                         "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, i['type'] + i['value'])}",
                         "created": now, "modified": now, "created_by_ref": ident,
                         "name": f"Phishing {i['type']}: {i['value'][:80]}",
                         "description": f"From email '{r['subject']}' ({r['verdict']}, score {r['score']})",
                         "indicator_types": ["malicious-activity"], "pattern": pattern[i["type"]].format(val),
                         "pattern_type": "stix", "valid_from": now,
                         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def write_reports(results, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "phish_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out / "iocs.stix.json").write_text(json.dumps(stix_bundle(results), indent=2), encoding="utf-8")
    with (out / "iocs.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["type", "value", "source_email", "verdict"])
        for r in results:
            if r["verdict"] != "LIKELY BENIGN":
                for i in r["iocs"]:
                    w.writerow([i["type"], i["value"], r["file"], r["verdict"]])
    md = ["# Phishing Analysis Report", "", "| Email | Verdict | Score | Subject | From | ATT&CK |", "|---|---|---|---|---|---|"]
    for r in results:
        md.append(f"| `{r['file']}` | **{r['verdict']}** | {r['score']} | {r['subject']} | `{r['from']}` | {', '.join(r['attack']) or '-'} |")
    for r in results:
        md += ["", f"## {r['file']}: {r['verdict']} ({r['score']}/100)", "",
               f"- **Subject:** {r['subject']}", f"- **From:** `{r['from']}` · **Reply-To:** `{', '.join(r['reply_to']) or '-'}` · **Return-Path:** `{r['return_path'] or '-'}`",
               f"- **Date (UTC):** {r['date_utc']} · **Origin IP:** {r['origin_ip'] or '-'} · **Hops:** {r['hops']}",
               f"- **SPF / DKIM / DMARC:** {r['auth']['spf']} / {r['auth']['dkim']} / {r['auth']['dmarc']}",
               f"- **File SHA-256:** `{r['sha256']}`", "", "**Signals**", "", "| Points | Category | Detail |", "|---|---|---|"]
        md += [f"| +{s['points']} | {s['category']} | {s['detail']} |" for s in r["signals"]] or ["| 0 | - | none |"]
        if r["links"]:
            md += ["", "**Links (not visited)**", "", "| URL | Shown text | Notes |", "|---|---|---|"]
            md += [f"| `{l['url'].replace('://', '[:]//')}` | {l['text'] or '-'} | {', '.join(l['notes']) or '-'} |" for l in r["links"]]
        if r["attachments"]:
            md += ["", "**Attachments (not opened)**", "", "| Name | Declared / true type | Size | SHA-256 | Notes |", "|---|---|---|---|---|"]
            md += [f"| {a['name']} | {a['content_type']} / {a['true_type']} | {a['size']} | `{a['sha256'][:16]}…` | {', '.join(a['notes']) or '-'} |" for a in r["attachments"]]
    (out / "phish_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline phishing email analyzer")
    ap.add_argument("emails", nargs="+", type=Path)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    cfg = dict(DEFAULT_CFG)
    if a.config:
        cfg.update({k: v for k, v in json.loads(a.config.read_text()).items() if not k.startswith("_")})
    results = [analyze(p, cfg) for p in a.emails]
    write_reports(results, a.out)
    for r in results:
        print(f"[{r['verdict']:<13}] {r['score']:>3}/100  {r['file']:<28} {r['subject'][:55]}")
        for s in r["signals"][:4]:
            print(f"        +{s['points']:<3} {s['detail'][:100]}")
    print(f"[+] Reports, IOC CSV and STIX 2.1 bundle in {a.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
