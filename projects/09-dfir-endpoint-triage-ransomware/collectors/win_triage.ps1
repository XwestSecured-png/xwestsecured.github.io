<#
.SYNOPSIS
  Read-only Windows live-response triage collector (analyze_triage.py input format).
.DESCRIPTION
  Collects volatile data first (order of volatility, RFC 3227), then persistence and logs:
    host.json, processes.json, network.json, scheduled_tasks.json, services.json, autoruns.json,
    events.json (Sysmon 1/3/10/11, Security 4624/4625/4672/4698/4720/4728/4732/1102, System 7045,
    PowerShell 4104), collection.log, SHA256SUMS
  Makes NO changes to the host. Run elevated from trusted media (USB/share), write output to
  external media or a network share, never to the suspect C:\ drive if avoidable.
.EXAMPLE
  .\win_triage.ps1 -OutRoot E:\IR-2026-1027 -Hours 72 -Examiner "X. West" -CaseId IR-2026-1027
.NOTES
  For full memory capture, run a dedicated tool (e.g. WinPmem / Magnet RAM Capture) BEFORE this script.
  Author: Xiome West | License: MIT
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutRoot,
    [int]$Hours = 72,
    [string]$Examiner = $env:USERNAME,
    [string]$CaseId = "UNSPECIFIED"
)
$ErrorActionPreference = 'SilentlyContinue'
$host_ = $env:COMPUTERNAME
$out = Join-Path $OutRoot $host_
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'collection.log'
function Log($m) { "$(Get-Date -Format o)  $m" | Tee-Object -FilePath $log -Append | Out-Null }
function Save($obj, $name) { $obj | ConvertTo-Json -Depth 6 | Out-File (Join-Path $out "$name.json") -Encoding utf8; Log "saved $name.json" }
function Iso($d) { if ($d) { $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } }

Log "Case $CaseId | examiner $Examiner | host $host_ | start"

# 1. Most volatile: network connections and processes
$procs = Get-CimInstance Win32_Process | ForEach-Object {
    $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
    $sha = if ($_.ExecutablePath) { (Get-FileHash -Algorithm SHA256 -Path $_.ExecutablePath).Hash }
    [ordered]@{ Name=$_.Name; ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Path=$_.ExecutablePath
                CommandLine=$_.CommandLine; User= if ($o.User) { "$($o.Domain)\$($o.User)" }; Created=(Iso $_.CreationDate); SHA256=$sha }
}
Save $procs 'processes'
Save (Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess) 'network'

# 2. System context
$os = Get-CimInstance Win32_OperatingSystem
Save ([ordered]@{ hostname=[System.Net.Dns]::GetHostEntry('').HostName; os="$($os.Caption) $($os.Version)"
                  ip=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1' | Select-Object -First 1).IPAddress
                  collected_utc=(Iso (Get-Date)); collected_by="$Examiner ($CaseId)"; timezone=(Get-TimeZone).Id
                  last_boot_utc=(Iso $os.LastBootUpTime) }) 'host'

# 3. Persistence
Save (Get-ScheduledTask | ForEach-Object { [ordered]@{ TaskName="$($_.TaskPath)$($_.TaskName)"; Author=$_.Author
        Action=(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ')
        Trigger=(($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task','' -replace 'Trigger','' }) -join ',')
        RunLevel="$($_.Principal.RunLevel)"; State="$($_.State)" } }) 'scheduled_tasks'
Save (Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName) 'services'
$runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
$auto = foreach ($k in $runKeys) { $p = Get-ItemProperty $k; if ($p) { $p.PSObject.Properties | Where-Object Name -notlike 'PS*' |
          ForEach-Object { [ordered]@{ Location=$k; Name=$_.Name; Value="$($_.Value)" } } } }
$auto += Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
          ForEach-Object { [ordered]@{ Location='WMI CommandLineEventConsumer'; Name=$_.Name; Value=$_.CommandLineTemplate } }
Save @($auto) 'autoruns'

# 4. Event logs (flattened EventData so the analyzer can match fields by name)
$since = (Get-Date).AddHours(-$Hours)
$queries = @(
  @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,10,11; StartTime=$since },
  @{ LogName='Security'; Id=4624,4625,4672,4698,4720,4728,4732,1102; StartTime=$since },
  @{ LogName='System'; Id=7045,104; StartTime=$since },
  @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$since }
)
$events = foreach ($q in $queries) {
  Get-WinEvent -FilterHashtable $q -MaxEvents 200000 | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = [ordered]@{ TimeCreated=(Iso $_.TimeCreated); Computer=$_.MachineName; Id=$_.Id; Provider=$_.ProviderName }
    foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
    $d } }
Save @($events) 'events'
Log "events collected: $(@($events).Count)"

# 5. Integrity manifest
Get-ChildItem $out -Filter *.json | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)" } | Out-File (Join-Path $out 'SHA256SUMS') -Encoding ascii
Log "SHA256SUMS written | end"
Write-Host "[+] Triage package: $out  (record the SHA256SUMS hash on the chain-of-custody form)"
