# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-21

### Added
- Single `westguard` CLI with 16 commands across incident response, detection, vulnerability management, audit and program reporting, consolidated from portfolio projects 01, 02, 04, 06, 07, 09, 13, 14 and 15.
- Stable exit-code contract (0 / 1 / 2 / 64 / 70) and structured logging (`--log-level`, `--log-file`, env vars).
- `demo` (post-install smoke test on bundled synthetic data), `doctor` (environment check) and `collectors` (exports read-only collection scripts).
- `file-triage`: directory recursion, size cap, symlink skipping, bundled YARA rules via `--yara default`, YARA timeout, exit codes by verdict.
- `cloud-detect`: loads CloudTrail S3 folders and `.json.gz` objects, JSON arrays and Microsoft Graph pages; exit codes by alert severity.
- Web dashboard with token auth, sessions, CSRF protection, strict CSP, upload limits, audit log, TLS or reverse-proxy enforcement for remote access.
- pip packaging (stdlib-only core; `yara`, `sigma`, `stix`, `all` extras), non-root Dockerfile, Caddy compose file, hardened systemd unit.
- CI: tests on Python 3.9-3.13, bandit, wheel install + demo smoke test, container build and non-root check.

### Fixed
- `secrets`: excluded-folder names (`build`, `dist`, `venv`, `vendor`, ...) were matched against the absolute path, so scanning a tree located under such a folder silently returned no findings. Now matched only inside the scan root; symlinks skipped.
- Python 3.9-3.11 compatibility: f-strings that used nested same-type quotes or backslashes (valid only on 3.12+) in the vulnerability prioritizer.
- Replaced `eval` in the Sigma condition evaluator with a dedicated boolean parser.
