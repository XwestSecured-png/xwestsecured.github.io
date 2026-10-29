# NIST SSDF & SLSA Mapping

How this toolkit maps to the **NIST Secure Software Development Framework (SP 800-218, v1.1)**, the practice set behind U.S. federal software attestation (EO 14028 / OMB M-22-18), and to **SLSA** supply-chain levels.

## NIST SP 800-218 (SSDF)

| Practice group | Practice | How this project addresses it |
|---|---|---|
| **PO** Prepare the Organization | PO.3 Implement supporting toolchains | `ci/security-pipeline.yml` automates checks on every PR, every push and weekly |
| | PO.4 Define criteria for software security checks | Build policy in `vuln_check.py`: fail on KEV, on high/critical/unrated advisories with a fix, and on unpinned dependencies |
| **PS** Protect the Software | PS.1 Protect all forms of code from unauthorized access and tampering | `secrets_scan.py` keeps credentials out of repos; workflow uses a read-only token and `persist-credentials: false` |
| | PS.2 Provide a mechanism for verifying software release integrity | npm `integrity` hashes recorded in the SBOM; guidance to pin actions by SHA |
| | PS.3 Archive and protect each software release | SBOM + vulnerability report stored as build artifacts per commit (PS.3.2: collect and share provenance data / SBOM) |
| **PW** Produce Well-Secured Software | PW.4 Reuse existing, well-secured software | Dependency inventory and vulnerability gating before third-party components are accepted |
| | PW.7 / PW.8 Review and test code | Secrets scanning in CI with SARIF results in code review |
| **RV** Respond to Vulnerabilities | RV.1 Identify and confirm vulnerabilities on an ongoing basis | Weekly scheduled re-scan against OSV + CISA KEV |
| | RV.2 Assess, prioritize and remediate | Upgrade plan with minimum safe version per component; KEV-first ordering |

## SLSA (Supply-chain Levels for Software Artifacts) v1.0, Build track

| Level | Requirement | Status with this pipeline |
|---|---|---|
| Build L1 | Provenance exists showing how the package was built | SBOM per build ✓ (add `actions/attest-build-provenance` for formal provenance) |
| Build L2 | Hosted build platform + signed provenance | GitHub-hosted runners ✓; signed provenance via GitHub artifact attestations (Sigstore) ➜ next step |
| Build L3 | Hardened build platform, non-falsifiable provenance | Use reusable workflows / isolated builders ➜ roadmap |

## OWASP Top 10:2025 A03: Software Supply Chain Failures

| Risk | Control here |
|---|---|
| Components with known vulnerabilities | SBOM → OSV / registry advisories → upgrade plan |
| Unpinned or floating dependencies (dependency confusion, malicious updates) | `--strict` unpinned-dependency policy |
| Compromised CI/CD (leaked secrets, over-privileged tokens) | Secrets scanning, least-privilege `permissions:`, OIDC instead of stored keys |
| Lack of inventory (can't answer "are we affected by X?") | CycloneDX SBOM per build, searchable by purl |

## Responding to the next "Log4Shell"

With an SBOM archived for every build, answering "are we affected?" takes minutes, not weeks:

```bash
grep -l '"pkg:maven/org.apache.logging.log4j/log4j-core@2.14' artifacts/*/sbom.cdx.json
```
