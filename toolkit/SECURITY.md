# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's **Report a vulnerability** (Security tab) on this repository rather than in a public issue. Include the version (`westguard --version`), steps to reproduce and impact. Expect an acknowledgement within 5 business days.

## Design principles

| Principle | How it is enforced |
|---|---|
| Read-only | Engines read exported data only. No tool writes to, reconfigures or connects to the systems being assessed. Collectors use read/list/describe APIs only. |
| Never execute samples | `file-triage` reads bytes; YARA scans run with a 60 s timeout; symlinks and special files are skipped; per-file size cap (default 100 MB). |
| No network by default | Only `vuln --fetch` (CISA KEV, FIRST EPSS) and `deps --fetch/--registry` (OSV, PyPI, npm) make outbound HTTPS requests, and only when the flag is given. |
| Minimal dependencies | Core uses the Python standard library only, removing third-party supply-chain risk. Extras are optional. |
| No `eval` on data | Sigma conditions are parsed by a small boolean parser that accepts only selection names, `and`/`or`/`not` and parentheses. |
| Fail safely | Bad input returns exit 64 with a message, not a stack trace; internal errors return 70 and log details. |

## Dashboard (`westguard web`) controls

| Threat | Control |
|---|---|
| Exposure to the network | Binds to `127.0.0.1` by default. Non-loopback binding is refused unless `--allow-remote` **and** TLS (`--tls-cert/--tls-key`, TLS 1.2+) or `--behind-proxy` are given. |
| Weak or guessed credentials | Token from `WESTGUARD_TOKEN` (minimum 24 characters) or a random 192-bit token generated at start-up. Stored only as a SHA-256 digest; compared in constant time. 5 failures per IP per 5 minutes → HTTP 429. |
| Session theft | 256-bit random server-side session IDs, 8-hour idle expiry, cookie `HttpOnly; SameSite=Strict` and `Secure` under TLS. HSTS under TLS. |
| CSRF | Per-session token required on every POST (run, logout). |
| XSS / clickjacking | All output HTML-escaped; CSP `default-src 'none'` with no script; `frame-ancestors 'none'`; `X-Frame-Options: DENY`; `nosniff`. Reports are served as `text/plain`. The KPI dashboard HTML is served under a `sandbox` CSP (unique origin, no forms, no same-origin access). |
| Path traversal | Uploaded filenames are reduced to a safe basename; jobs use random 128-bit IDs validated by regex; served files must resolve inside their job folder. |
| Resource exhaustion | Upload cap (default 50 MB, `--max-upload-mb`); tool runs are serialised. |
| Accountability | Append-only JSON-lines audit log (`<data-dir>/audit.log`): logins, failures, rate limits, CSRF rejections, and every job with tool, exit code and SHA-256 of each input. |
| Data at rest | Data directory created with mode 700, uploads 600. Use disk encryption on the host and set a retention job (see docs/operations.md). |

**Known limitations:** single shared token (no per-user identities or roles) — front it with your SSO/identity-aware proxy for multi-user use; sessions are in memory (a restart signs everyone out); the built-in server is suited to a small team, not high-concurrency use.

## Verifying a release

CI builds the wheel and sdist and publishes them as workflow artifacts. Record the SHA-256 of the wheel you deploy (`sha256sum westguard-*.whl`) and install with `pip install --require-hashes` from a pinned requirements file in regulated environments.
