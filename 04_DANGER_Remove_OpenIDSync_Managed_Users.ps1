param(
    [string]$SearchBase,
    [switch]$Force,
    [switch]$WhatIf,
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '00_OpenIDSync_Config.json')
)

function Import-RequiredModule {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Please install RSAT Active Directory tools and try again." -ForegroundColor Yellow
        throw "Missing module: $Name"
    }
    Import-Module $Name -ErrorAction Stop
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','ACTION','RESULT')]
        [string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    $line | Out-File -FilePath $script:AuditLogPath -Encoding UTF8 -Append
    Write-Host $line
}

try { Import-RequiredModule -Name ActiveDirectory } catch { throw }

# Resolve SearchBase from JSON if not provided
if (-not $SearchBase -and (Test-Path -LiteralPath $ConfigPath)) {
    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        if ($cfg -and $cfg.UserSyncConfig -and $cfg.UserSyncConfig.DefaultOU) {
            $SearchBase = [string]$cfg.UserSyncConfig.DefaultOU
        }
    } catch {}
}

if (-not $SearchBase) {
    $SearchBase = Read-Host "Enter SearchBase distinguishedName to scan for users to delete (e.g. OU=Users,DC=example,DC=com)"
}
if ([string]::IsNullOrWhiteSpace($SearchBase)) { throw "SearchBase is required." }

# Logs
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:AuditLogPath = Join-Path -Path (Get-Location) -ChildPath "openidsync_danger_remove_$ts.log"
Write-Log -Level 'INFO' -Message "Audit log initialized: $AuditLogPath"
Write-Log -Level 'INFO' -Message "SearchBase: $SearchBase"

# DANGER ZONE banner
Write-Host "" 
Write-Host "###############################################################" -ForegroundColor Red
Write-Host "#                         DANGER ZONE                          #" -ForegroundColor Red
Write-Host "###############################################################" -ForegroundColor Red
Write-Host "THIS ACTION WILL PERMANENTLY DELETE ALL AD USER OBJECTS" -ForegroundColor Red
Write-Host "MANAGED BY THIS TOOL (Description contains [openidsync.org])" -ForegroundColor Red
Write-Host "UNDER: $SearchBase" -ForegroundColor Red
Write-Host "- This cannot be undone." -ForegroundColor Red
Write-Host "- All deleted users will receive NEW object IDs and NEW passwords upon re-import." -ForegroundColor Red
Write-Host "- Group memberships and any manual changes will be LOST." -ForegroundColor Red
Write-Host "Consider running with -WhatIf to preview before actual deletion." -ForegroundColor Red
Write-Host "###############################################################" -ForegroundColor Red
Write-Host ""

if (-not $Force) {
    $c1 = Read-Host "Type 'I UNDERSTAND' to continue or anything else to cancel"
    if ($c1 -ne 'I UNDERSTAND') {
        Write-Log -Level 'INFO' -Message "Aborted at first confirmation."
        return
    }
    $c2 = Read-Host "Type 'DELETE' to confirm permanent deletion"
    if ($c2 -ne 'DELETE') {
        Write-Log -Level 'INFO' -Message "Aborted at second confirmation."
        return
    }
}

# Discover candidates
Write-Log -Level 'ACTION' -Message "Scanning for users with [openidsync.org] in Description..."
$candidates = @()
try {
    $users = Get-ADUser -SearchBase $SearchBase -LDAPFilter "(objectClass=user)" -Properties description,displayName,samAccountName,userPrincipalName -ResultSetSize $null
    foreach ($u in $users) {
        if ($u.Description -and ($u.Description -match '\[openidsync\.org\]')) {
            $candidates += $u
        }
    }
} catch {
    Write-Log -Level 'ERROR' -Message "Failed to query AD users: $($_.Exception.Message)"
    throw
}

$found = $candidates.Count
Write-Log -Level 'INFO' -Message "Found $found user(s) eligible for deletion."
if ($found -eq 0) { return }

# Backup list before deletion
$backupPath = Join-Path -Path (Get-Location) -ChildPath "openidsync_danger_backup_$ts.csv"
try {
    $candidates | Select-Object SamAccountName, UserPrincipalName, DisplayName, DistinguishedName | Export-Csv -Path $backupPath -NoTypeInformation -Encoding UTF8
    Write-Log -Level 'INFO' -Message "Backup exported: $backupPath"
} catch {
    Write-Log -Level 'WARN' -Message "Failed to export backup list: $($_.Exception.Message)"
}

# Final heads-up before deletion if not forced
if (-not $Force) {
    $confirm = Read-Host "Last chance: proceed to delete $found users from $SearchBase? [Y/N]"
    if ($confirm.ToUpper() -ne 'Y' -and $confirm.ToUpper() -ne 'YES') {
        Write-Log -Level 'INFO' -Message "Aborted at final confirmation."
        return
    }
}

# Deletion loop
$removed = 0
$failed = 0
foreach ($u in $candidates) {
    $ident = $u.DistinguishedName
    try {
        if ($WhatIf) {
            Write-Log -Level 'ACTION' -Message "WhatIf: Remove-ADUser -Identity '$ident'"
        } else {
            Remove-ADUser -Identity $ident -Confirm:$false -ErrorAction Stop
            Write-Log -Level 'RESULT' -Message "Deleted: $($u.SamAccountName) ($($u.UserPrincipalName))"
        }
        $removed++
    } catch {
        Write-Log -Level 'ERROR' -Message "Failed to delete $($u.UserPrincipalName): $($_.Exception.Message)"
        $failed++
    }
}

# Summary
Write-Host "" 
Write-Host "==================== DANGER ZONE SUMMARY ====================" -ForegroundColor Red
Write-Host ("Found:   {0}" -f $found) -ForegroundColor Red
Write-Host ("Removed: {0}" -f $removed) -ForegroundColor Red
Write-Host ("Failed:  {0}" -f $failed) -ForegroundColor Red
Write-Host "=============================================================" -ForegroundColor Red
Write-Host "" 

Write-Log -Level 'INFO' -Message ("Summary -> Found: {0}, Removed: {1}, Failed: {2}" -f $found, $removed, $failed)
