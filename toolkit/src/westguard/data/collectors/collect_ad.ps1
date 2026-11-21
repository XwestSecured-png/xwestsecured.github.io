<#
.SYNOPSIS
  Read-only Active Directory evidence collector for cloud_identity_audit.py
.DESCRIPTION
  Requires the ActiveDirectory module (RSAT). Any authenticated domain user can read these attributes;
  no changes are made. Run from a domain-joined admin workstation.
.EXAMPLE
  .\collect_ad.ps1 -OutDir .\ad_export
#>
param([string]$OutDir = ".\ad_export")
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Iso($d) { if ($d) { $d.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null } }

$props = 'LastLogonDate','PasswordLastSet','PasswordNeverExpires','ServicePrincipalName','DoesNotRequirePreAuth',
         'TrustedForDelegation','AdminCount','Enabled'
$users = Get-ADUser -Filter * -Properties $props | ForEach-Object {
    [ordered]@{
        SamAccountName        = $_.SamAccountName
        Enabled               = $_.Enabled
        LastLogonDate         = Iso $_.LastLogonDate
        PasswordLastSet       = Iso $_.PasswordLastSet
        PasswordNeverExpires  = $_.PasswordNeverExpires
        ServicePrincipalName  = @($_.ServicePrincipalName)
        DoesNotRequirePreAuth = $_.DoesNotRequirePreAuth
        TrustedForDelegation  = $_.TrustedForDelegation
        AdminCount            = $_.AdminCount
    }
}
$users | ConvertTo-Json -Depth 4 | Out-File "$OutDir\ad_users.json" -Encoding utf8

$groups = [ordered]@{}
foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
               'Backup Operators','Server Operators','Print Operators') {
    try { $groups[$g] = @(Get-ADGroupMember -Identity $g -Recursive | Select-Object -ExpandProperty SamAccountName) } catch {}
}
$groups | ConvertTo-Json -Depth 3 | Out-File "$OutDir\ad_privileged_groups.json" -Encoding utf8

Get-ChildItem $OutDir -File | Get-FileHash -Algorithm SHA256 | Format-Table Hash, Path -AutoSize | Out-File "$OutDir\SHA256SUMS.txt"
Write-Host "[+] Export complete: $OutDir (treat as CONFIDENTIAL; contains account names)"
