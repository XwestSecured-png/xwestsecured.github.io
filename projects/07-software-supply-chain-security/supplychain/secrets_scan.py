#!/usr/bin/env python3
"""
Secrets scanner: finds hard-coded credentials in source trees before they ship.

  * Provider-specific patterns (AWS, GitHub, Slack, Stripe, Google, Azure, private keys, JWTs,
    connection strings) plus a generic "secret-looking assignment" rule gated by Shannon entropy
    to keep false positives down.
  * Skips binaries, vendored folders and lock files; honors inline `nosecret` and a
    .secretsignore file (glob per line).
  * Redacts matches in output and never prints full secret values.
  * Emits console, JSON and SARIF 2.1.0 (uploadable to GitHub code scanning).

    python3 supplychain/secrets_scan.py sample_app --sarif reports/secrets.sarif

Maps to: OWASP Top 10:2025 A04/A07, CWE-798, NIST SP 800-218 (SSDF) PS.1/PW.7, ATT&CK T1552.001
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

RULES = [
    # id, name, severity, regex
    ("SEC-AWS-AKID", "AWS access key ID", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("SEC-AWS-SECRET", "AWS secret access key", "critical",
     r"(?i)aws.{0,20}(?:secret|private).{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ("SEC-PRIVKEY", "Private key block", "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("SEC-GITHUB", "GitHub token", "critical", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("SEC-SLACK", "Slack token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("SEC-STRIPE", "Stripe live secret key", "critical", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    ("SEC-GOOGLE", "Google API key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("SEC-AZURE-CONN", "Azure storage connection string", "critical",
     r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("SEC-DB-URI", "Credentials in connection URI", "high",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/'\"]+:([^@\s'\"]{4,})@"),
    ("SEC-JWT", "JSON Web Token", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("SEC-GENERIC", "High-entropy secret assignment", "medium",
     r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?key|client[_-]?secret)[\w.-]*"
     r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
]
COMPILED = [(i, n, s, re.compile(p)) for i, n, s, p in RULES]
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox", "vendor"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum"}
PLACEHOLDERS = re.compile(r"(?i)^(?:changeme|change_me|example|your[_-]?.*|xxx+|\*+|<.*>|\$\{.*\}|%\(.*\)s|"
                          r"\{\{.*\}\}|os\.environ.*|env\(.*\)|none|null|password|secret|dummy|test|redacted)$")
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def redact(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "****"


def is_text(p: Path) -> bool:
    try:
        return b"\0" not in p.read_bytes()[:4096]
    except OSError:
        return False


def iter_files(root: Path, ignores: list[str]):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.parts) or p.name in SKIP_FILES:
            continue
        rel = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, g) for g in ignores):
            continue
        if p.stat().st_size > 2_000_000 or not is_text(p):
            continue
        yield p, rel


def scan(root: Path, min_entropy: float = 3.5) -> list[dict]:
    ign_file = root / ".secretsignore"
    ignores = [l.strip() for l in ign_file.read_text().splitlines() if l.strip() and not l.startswith("#")] \
        if ign_file.exists() else []
    findings = []
    for path, rel in iter_files(root, ignores):
        for ln, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "nosecret" in line:
                continue
            for rid, name, sev, rx in COMPILED:
                for m in rx.finditer(line):
                    value = m.group(1) if m.groups() and m.group(1) else m.group(0)
                    if rid == "SEC-GENERIC":
                        if PLACEHOLDERS.match(value) or entropy(value) < min_entropy:
                            continue
                        if any(f["file"] == rel and f["line"] == ln for f in findings):
                            continue  # a specific rule already caught this line
                    if rid == "SEC-DB-URI" and PLACEHOLDERS.match(value):
                        continue
                    findings.append({"rule_id": rid, "name": name, "severity": sev, "file": rel, "line": ln,
                                     "column": m.start() + 1, "match": redact(value),
                                     "entropy": round(entropy(value), 2)})
    findings.sort(key=lambda f: (SEV[f["severity"]], f["file"], f["line"]))
    return findings


def to_sarif(findings: list[dict]) -> dict:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    used = sorted({f["rule_id"] for f in findings})
    meta = {i: (n, s) for i, n, s, _ in RULES}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "secrets_scan", "informationUri": "https://github.com/XwestSecured-png/xwestsecured.github.io",
                                "rules": [{"id": r, "name": meta[r][0].replace(" ", ""),
                                           "shortDescription": {"text": meta[r][0]},
                                           "properties": {"security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}[meta[r][1]],
                                                          "tags": ["security", "CWE-798"]}} for r in used]}},
            "results": [{"ruleId": f["rule_id"], "level": lvl[f["severity"]],
                         "message": {"text": f"{f['name']} ({f['match']}). Remove from source, rotate the credential, "
                                             f"and load it from a secrets manager or environment variable."},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                             "region": {"startLine": f["line"], "startColumn": f["column"]}}}]}
                        for f in findings],
        }],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Hard-coded secrets scanner")
    ap.add_argument("path", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--min-entropy", type=float, default=3.5)
    a = ap.parse_args(argv)
    findings = scan(a.path, a.min_entropy)
    for out, data in ((a.json, findings), (a.sarif, to_sarif(findings) if a.sarif else None)):
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] {len(findings)} potential secrets")
    for f in findings:
        print(f"    [{f['severity'].upper():8}] {f['rule_id']:<15} {f['file']}:{f['line']}  {f['name']}  ({f['match']})")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
