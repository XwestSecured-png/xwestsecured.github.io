# Evidence Handling, Order of Volatility & Chain of Custody

Aligned with **RFC 3227** (Guidelines for Evidence Collection and Archiving), **NIST SP 800-86** (Integrating Forensic Techniques into Incident Response), **NIST SP 800-61r3**, and **ISO/IEC 27037** (identification, collection, acquisition and preservation of digital evidence).

## 1. Before you touch the system

- [ ] Incident declared and a case ID assigned. Legal and HR informed if the case could involve employee misconduct or law enforcement.
- [ ] Decide: **live response or power off?** Default is to keep it running. Volatile data (memory, connections, running malware) is lost at shutdown. Exception: active destruction in progress (mass encryption, wiping). Then isolate the network first.
- [ ] Use **trusted tools from external media**. Don't install software on the suspect host, and don't browse or open files on it.
- [ ] Record every action you take, with time (UTC) and the reason. Your actions change the system, and you'll need to explain each change.

## 2. Order of volatility (collect most volatile first)

| Order | Data | Typical lifetime | How (Windows / Linux) |
|---|---|---|---|
| 1 | CPU registers, cache | Nanoseconds | Not practical in IR |
| 2 | **Memory (RAM)**: processes, injected code, keys, network state | Until reboot | WinPmem / Magnet RAM Capture · LiME / AVML |
| 3 | Network connections, ARP and routing tables, running processes | Seconds–minutes | `win_triage.ps1` / `linux_triage.sh` (steps 1–2) |
| 4 | Temporary file systems, swap/pagefile | Minutes–hours | Targeted copy |
| 5 | Disk: logs, persistence, user artifacts | Days–months | Triage collectors (steps 3–4); full disk image if scope requires |
| 6 | Remote logs (SIEM, cloud audit, proxy, EDR) | Retention policy | Export early, since retention windows can expire mid-investigation |
| 7 | Backups, archival media | Years | Preserve the last known-good backups and suspend rotation |

## 3. Integrity

- Hash every evidence file at collection (**SHA-256**). The collectors write `SHA256SUMS`, and `analyze_triage.py` re-verifies them before analysis and reports any mismatch.
- Analyze **copies**. Keep the original on write-protected or WORM storage.
- Record clock skew between hosts and the reference time source, so timelines across systems line up.

## 4. Chain-of-custody form

| Field | Entry |
|---|---|
| Case ID | IR-2026-1027 |
| Evidence ID | E1 |
| Description | Live-response triage package, host WS-0102 (8 JSON files + SHA256SUMS) |
| Source (make/model/serial or hostname/asset tag) | WS-0102.corp.example / Asset ECS-LT-0102 |
| Collected by / date-time (UTC) / location | X. West / 2026-10-27 20:10 / Site 1, remote via EDR live response |
| Collection method / tool & version | `win_triage.ps1` v1.0 from read-only share |
| SHA-256 of SHA256SUMS manifest | (recorded at collection) |
| Storage location | Evidence share `\\ir-vault\cases\IR-2026-1027\E1` (access: IR team only, WORM retention 7 years) |

**Transfer log**

| # | Date-time (UTC) | Released by | Received by | Purpose | Hash verified? |
|---|---|---|---|---|---|
| 1 | 2026-10-27 20:15 | X. West | Evidence vault (system) | Storage | ✅ |
| 2 | 2026-10-28 09:00 | Evidence vault | X. West | Analysis (working copy) | ✅ |
| 3 | | | | | |

## 5. Retention & disposal
Keep evidence for the longest of: legal hold, regulatory requirement, insurance claim, or organizational policy (commonly 3–7 years). Dispose of it securely (NIST SP 800-88 media sanitization) and record the disposal on the form.
