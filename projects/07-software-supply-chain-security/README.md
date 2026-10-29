# Project 07: Software Supply-Chain Security Toolkit (Secrets · SBOM · Dependency Risk · CI Gate)

**Skills shown:** DevSecOps · application security · SBOM (CycloneDX) · vulnerability intelligence (OSV, GHSA, PyPI/npm advisories, CISA KEV) · SARIF / GitHub code scanning · CI/CD hardening · Python

**OWASP Top 10:2025** added **A03 Software Supply Chain Failures** as a category of its own, and incidents like SolarWinds, Log4Shell, 3CX, xz-utils and malicious npm packages show why. This project builds the three controls every software team needs, then wires them into a CI pipeline that blocks risky builds:

| Tool | Answers | Output |
|---|---|---|
| `supplychain/secrets_scan.py` | "Did someone commit a credential?" | Console, JSON, **SARIF 2.1.0** (shows inline in GitHub PRs) |
| `supplychain/sbom.py` | "What exactly is in this build?" | **CycloneDX 1.6** SBOM with Package URLs |
| `supplychain/vuln_check.py` | "Which components are vulnerable, and what's the minimum safe upgrade?" | Upgrade plan, full advisory list, pass/fail **build policy** |
| `ci/security-pipeline.yml` | "How do we enforce this on every change?" | Hardened GitHub Actions workflow template |

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%201.6-6c3fb5) ![SARIF](https://img.shields.io/badge/SARIF-2.1.0-555) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Results on the sample app

**Secrets:** 6 of 6 planted credentials found, 0 false positives. Environment variables, placeholders like `changeme`, and a justified `# nosecret` suppression were correctly ignored. Matches are redacted so the scanner never re-leaks what it finds.

```
[+] 6 potential secrets
    [CRITICAL] SEC-PRIVKEY     src/deploy_key.pem:1   Private key block
    [CRITICAL] SEC-AWS-SECRET  src/settings.py:9      AWS secret access key  (wJal…EY)
    [HIGH    ] SEC-AWS-AKID    src/settings.py:8      AWS access key ID      (AKIA…LE)
    [HIGH    ] SEC-DB-URI      src/settings.py:12     Credentials in connection URI
    [MEDIUM  ] SEC-JWT         src/app.js:6           JSON Web Token
    [MEDIUM  ] SEC-GENERIC     src/settings.py:15     High-entropy secret assignment
```

**SBOM + dependency risk.** The data is real: advisories were pulled live from the PyPI and npm advisory APIs on 2026-10-29 and saved as an offline snapshot.

```
[+] SBOM: 9 components {'npm': 3, 'pypi': 6}
[!] Unpinned: flask, gunicorn
[+] 7 pinned components checked, 58 known vulnerabilities, 2 unpinned
    component    installed  vulns  worst     upgrade to
    axios        0.21.0        25  HIGH      >= 0.33.0
    lodash       4.17.15        6  HIGH      latest (> 4.17.23)
    urllib3      1.24.1        13  UNKNOWN   >= 2.8.0
    jinja2       2.10           6  UNKNOWN   >= 3.1.6
    requests     2.19.1         5  UNKNOWN   >= 2.33.0
    pyyaml       5.3            3  UNKNOWN   >= 5.4
    [POLICY] flask is not pinned to an exact version
    [POLICY] gunicorn is not pinned to an exact version
[✗] Policy: FAIL (41 blocking advisories, 2 unpinned)
```

Instead of handing developers a list of 58 advisories, the tool collapses them into **six upgrade actions**: the minimum version per component that clears every known issue. `express@4.21.2` came back clean and stays off the list.

Reports: [`reports/vuln_report.md`](reports/vuln_report.md) · [`reports/sbom.cdx.json`](reports/sbom.cdx.json) · [`reports/secrets.sarif`](reports/secrets.sarif)

## Design decisions

- **Three lookup modes.** `--fetch` uses OSV.dev, the broadest source. `--registry` uses the PyPI JSON and npm bulk advisory APIs, which are often reachable through corporate proxies that block other sites. `--osv snapshot.json` works air-gapped. `--save-db` creates a snapshot from either live mode.
- **Unrated advisories fail closed.** PyPI advisories often have no severity, so any unrated advisory with a fix available is treated as **high until triaged**. A silent pass would be the worse failure.
- **`last_affected` handling.** npm ranges like `<=4.17.23` have no published fixed version. The plan says "latest (> 4.17.23)" rather than inventing a version.
- **Entropy gating.** The generic secret rule only fires above a Shannon entropy of 3.5, which keeps `password = "your_password_here"` out of the results.
- **Deterministic SBOMs.** Components are sorted and the serial number is a name-based UUID, so SBOMs diff cleanly in code review.

## Standards alignment

| Standard | Coverage |
|---|---|
| **OWASP Top 10:2025** | A03 Software Supply Chain Failures, A04 Cryptographic Failures / A07 (hard-coded credentials) |
| **NIST SP 800-218 (SSDF v1.1)** | PO.3, PO.4, PS.1–PS.3, PW.4, PW.7, RV.1, RV.2 ([mapping](docs/ssdf-and-slsa-mapping.md)) |
| **SLSA v1.0** | Build track L1–L2 path |
| **EO 14028 / NTIA SBOM minimum elements** | Supplier, name, version, unique ID (purl), dependency relationship, author, timestamp |
| **CISA KEV** | `--kev` flags actively exploited CVEs first and always fails the build |
| **CWE** | CWE-798 Hard-coded Credentials, CWE-1104 Unmaintained Third-Party Components, CWE-1357 |
| **MITRE ATT&CK** | T1195.001 (Compromise Software Dependencies), T1552.001 (Credentials in Files) |
| **CIS Controls v8.1** | 16.4 (inventory of third-party components), 16.5 (up-to-date components) |

## Quick start

```bash
python3 supplychain/secrets_scan.py sample_app --sarif reports/secrets.sarif
python3 supplychain/sbom.py sample_app --name sample-app --version 1.4.2 --out reports/sbom.cdx.json
python3 supplychain/vuln_check.py reports/sbom.cdx.json --osv sample_data/vuln_db_snapshot.json --strict --out reports/vuln_report.json
# live data instead of the snapshot:
python3 supplychain/vuln_check.py reports/sbom.cdx.json --fetch        # OSV.dev
python3 supplychain/vuln_check.py reports/sbom.cdx.json --registry     # PyPI + npm
python3 -m unittest discover -s tests -v
```

## Adapting to your environment

| Situation | How |
|---|---|
| **GitHub** | Copy `ci/security-pipeline.yml` to `.github/workflows/`. Pin actions to commit SHAs. SARIF shows up in the Security tab |
| **GitLab / Azure DevOps / Jenkins** | The tools are plain CLI commands with exit codes. Call the same three commands in any pipeline stage |
| **Pre-commit (developer laptop)** | Run `secrets_scan.py` as a pre-commit hook so secrets never reach the remote |
| **Other ecosystems** | Add a parser to `sbom.py` (Maven `pom.xml`, Go `go.sum`, `Cargo.lock`). OSV already supports those ecosystems through purls |
| **Vendor software you buy** | Ask vendors for a CycloneDX/SPDX SBOM (question 12 in the Project 05 vendor questionnaire) and run `vuln_check.py` on it |
| **Policy strictness** | Drop `--strict` for legacy apps while pinning is rolled out. Add `--kev` for exploited-first gating |

**When a secret is found:** removing it from code is **not enough**, because it stays in git history and may already be copied. Rotate the credential first, then purge history (`git filter-repo`), then move the value to a secrets manager.

## Lessons learned

1. **An SBOM is an inventory, not a scan.** Its value shows up the day the next Log4Shell drops and you can answer "are we affected?" with a single `grep`.
2. **Upgrade plans beat advisory lists.** Developers act on "bump urllib3 to 2.8.0", not on 13 separate CVE tickets.
3. **Fail closed on unknowns.** Missing severity data is common. Treating unrated as safe would have passed a build with 27 known-fixable vulnerabilities.
4. **Secret scanning has to be precise.** A noisy scanner gets disabled. Entropy thresholds, placeholder lists and auditable suppressions keep it trusted.
