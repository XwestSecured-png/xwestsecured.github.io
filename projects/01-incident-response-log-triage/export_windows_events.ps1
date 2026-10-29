<#
.SYNOPSIS
  Read-only export of Windows Security events used by triage.py.
.DESCRIPTION
  Pulls the last N hours of authentication / account-management events and writes
  a CSV with the columns triage.py expects. Run from an elevated PowerShell session
  on the host (or use -ComputerName with appropriate rights). Nothing is modified.
.EXAMPLE
  .\export_windows_events.ps1 -Hours 24 -OutFile .\windows_security.csv
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$OutFile = ".\windows_security.csv"
)

$ids = 4624, 4625, 4672, 4720, 4728, 4732, 4756, 1102
$start = (Get-Date).AddHours(-$Hours)

$events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
    LogName = 'Security'; Id = $ids; StartTime = $start
} -ErrorAction SilentlyContinue

$rows = foreach ($e in $events) {
    $xml  = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [pscustomobject]@{
        TimeCreated    = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Computer       = $e.MachineName
        EventID        = $e.Id
        TargetUserName = if ($e.Id -in 4728,4732,4756) { $data['MemberName'] } else { $data['TargetUserName'] }
        IpAddress      = $data['IpAddress']
        LogonType      = $data['LogonType']
        GroupName      = if ($e.Id -in 4728,4732,4756) { $data['TargetUserName'] } else { '' }
    }
}

$rows | Sort-Object TimeCreated | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$hash = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash
Write-Host "[+] Exported $($rows.Count) events to $OutFile (SHA-256 $hash)"
