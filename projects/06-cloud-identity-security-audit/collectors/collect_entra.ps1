<#
.SYNOPSIS
  Read-only Microsoft Entra ID / Microsoft 365 evidence collector for cloud_identity_audit.py
.DESCRIPTION
  Uses the Microsoft Graph PowerShell SDK with read-only scopes. Nothing is changed in the tenant.
  Install once:  Install-Module Microsoft.Graph -Scope CurrentUser
  The user registration report requires an Entra ID P1/P2 license.
.EXAMPLE
  .\collect_entra.ps1 -OutDir .\entra_export
#>
param([string]$OutDir = ".\entra_export")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Connect-MgGraph -Scopes 'AuditLog.Read.All','Policy.Read.All','RoleManagement.Read.Directory','User.Read.All','Directory.Read.All' -NoWelcome

# 1. MFA / authentication method registration
$reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
    Select-Object UserPrincipalName, IsAdmin, IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable, MethodsRegistered
@{ value = @($reg | ForEach-Object {
    @{ userPrincipalName = $_.UserPrincipalName; isAdmin = $_.IsAdmin; isMfaRegistered = $_.IsMfaRegistered;
       methodsRegistered = @($_.MethodsRegistered) } }) } |
    ConvertTo-Json -Depth 5 | Out-File "$OutDir\user_registration_details.json" -Encoding utf8

# 2. Conditional Access policies (raw Graph JSON)
$ca = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$ca | ConvertTo-Json -Depth 20 | Out-File "$OutDir\conditional_access_policies.json" -Encoding utf8

# 3. Privileged directory role members
$roles = @('Global Administrator','Privileged Role Administrator','Exchange Administrator','SharePoint Administrator',
           'User Administrator','Security Administrator','Conditional Access Administrator','Application Administrator')
$result = @{}
foreach ($r in Get-MgDirectoryRole -All | Where-Object DisplayName -in $roles) {
    $result[$r.DisplayName] = @(Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All | ForEach-Object {
        $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,UserType,OnPremisesSyncEnabled -ErrorAction SilentlyContinue
        if ($u) { @{ userPrincipalName = $u.UserPrincipalName; userType = $u.UserType; onPremisesSyncEnabled = [bool]$u.OnPremisesSyncEnabled } }
    })
}
$result | ConvertTo-Json -Depth 5 | Out-File "$OutDir\privileged_role_members.json" -Encoding utf8

Get-ChildItem $OutDir -File | Get-FileHash -Algorithm SHA256 | Format-Table Hash, Path -AutoSize | Out-File "$OutDir\SHA256SUMS.txt"
Disconnect-MgGraph | Out-Null
Write-Host "[+] Export complete: $OutDir (treat as CONFIDENTIAL)"
