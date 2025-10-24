param(
    [string]$CsvPath,
    [string]$DefaultOU,
    [ValidateSet('CSV','Online')]
    [string]$Source,
    # Future: support multiple targets (e.g., WindowsAD, Keycloak, OtherDirectory)
    [string]$Target = 'WindowsAD',
    [Alias('Batch','NoPrompt')]
    [switch]$NonInteractive,
    [Alias('All','ProcessAll')]
    [switch]$AllUsers,
    [switch]$NoSuggestRemovals,
    # Graph/App Registration overrides (optional)
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$ClientSecretEnvVar = 'OPENIDSYNC_CLIENT_SECRET',
    [switch]$AutoCreateGraphApp,
    [switch]$AutoInstallGraphModules,
    [switch]$AssignDirectoryReaderToApp,
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '00_OpenIDSync_Config.json'),
    # New: keep OnlineSyncConfig in a separate file to avoid modifying user's main config
    [string]$OnlineSyncConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '00_OpenIDSync_OnlineSyncConfig.json')
)

# Make config paths available script-wide
$script:ConfigPath = $ConfigPath
$script:OnlineSyncConfigPath = $OnlineSyncConfigPath
$script:NonInteractive = $false
$script:ProcessAll = $false
$script:SourceFromConfig = $false
$script:ModeUsers = 'All'
$script:ModeGroups = 'All'
$script:ModeMemberships = 'All'
$script:Target = $Target
$script:GroupsProcessAll = $false
$script:MembershipsProcessAll = $false

# Load OpenIDSync modules (modularized by domain) with per-file error handling
try {
    $modulesRoot = Join-Path -Path $PSScriptRoot -ChildPath 'modules'
    if (Test-Path -LiteralPath $modulesRoot) {
        $moduleFiles = @(
            (Join-Path (Join-Path $modulesRoot 'logging') 'Write-Log.ps1'),
            (Join-Path (Join-Path $modulesRoot 'common') 'Config.ps1'),
            (Join-Path (Join-Path $modulesRoot 'common') 'Contracts.ps1'),
            (Join-Path (Join-Path $modulesRoot 'common') 'Orchestrator.ps1'),
            (Join-Path (Join-Path $modulesRoot 'common') 'Summary.ps1'),
            (Join-Path (Join-Path $modulesRoot 'common') 'Dashboard.ps1'),
            (Join-Path (Join-Path $modulesRoot 'ad') 'ActiveDirectory.ps1'),
            (Join-Path (Join-Path $modulesRoot 'transform') 'Users.ps1'),
            (Join-Path (Join-Path $modulesRoot 'sync-sources') 'CSV.ps1'),
            (Join-Path (Join-Path $modulesRoot 'sync-sources') 'Providers.ps1'),
            (Join-Path (Join-Path $modulesRoot 'microsoft-graph') 'Graph.ps1'),
            (Join-Path (Join-Path $modulesRoot 'sync-targets') 'WindowsAD.ps1'),
            (Join-Path (Join-Path $modulesRoot 'sync-targets') 'WindowsAD.Groups.ps1')
        )
        foreach ($mf in $moduleFiles) {
            if (Test-Path -LiteralPath $mf) {
                try { . $mf } catch {
                    $msg = "Failed to load module file: $mf -> $($_.Exception.Message)"
                    try { Write-Log -Level 'WARN' -Message $msg } catch { Write-Host $msg -ForegroundColor Yellow }
                }
            } else {
                $msg = "Module file not found: $mf"
                try { Write-Log -Level 'WARN' -Message $msg } catch { Write-Host $msg -ForegroundColor Yellow }
            }
        }
    }
} catch { try { Write-Log -Level 'WARN' -Message ("Unhandled error while loading modules: {0}" -f $_.Exception.Message) } catch { Write-Host "Unhandled error while loading modules: $($_.Exception.Message)" -ForegroundColor Yellow } }

# Compatibility shims to support older function names if modules are not yet updated on disk
if (-not (Get-Command -Name Import-RequiredModule -ErrorAction SilentlyContinue)) {
    function Import-RequiredModule { param([string]$Name)
        if (Get-Command -Name Ensure-Module -ErrorAction SilentlyContinue) { Ensure-Module -Name $Name }
        else { Import-Module $Name -ErrorAction Stop }
    }
}
if (-not (Get-Command -Name Import-GraphModules -ErrorAction SilentlyContinue)) {
    function Import-GraphModules { if (Get-Command -Name Ensure-GraphModule -ErrorAction SilentlyContinue) { Ensure-GraphModule } }
}
if (-not (Get-Command -Name Test-GraphCommands -ErrorAction SilentlyContinue)) {
    function Test-GraphCommands { if (Get-Command -Name Verify-GraphCommands -ErrorAction SilentlyContinue) { Verify-GraphCommands } }
}
if (-not (Get-Command -Name Show-SecuritySummary -ErrorAction SilentlyContinue)) {
    function Show-SecuritySummary { param([switch]$AppOnly,[switch]$CreatingApp)
        if (Get-Command -Name Print-SecuritySummary -ErrorAction SilentlyContinue) { Print-SecuritySummary @PSBoundParameters }
    }
}
if (-not (Get-Command -Name Show-AuthContextSummary -ErrorAction SilentlyContinue)) {
    function Show-AuthContextSummary { param([switch]$AppOnly,[string]$TenantId,[string]$ClientId)
        if (Get-Command -Name Print-AuthContextSummary -ErrorAction SilentlyContinue) { Print-AuthContextSummary @PSBoundParameters }
    }
}
if (-not (Get-Command -Name Grant-DirectoryReadersToServicePrincipal -ErrorAction SilentlyContinue)) {
    function Grant-DirectoryReadersToServicePrincipal { param([string]$SpObjectId)
        if (Get-Command -Name Ensure-DirectoryReadersRoleForSp -ErrorAction SilentlyContinue) { Ensure-DirectoryReadersRoleForSp -SpObjectId $SpObjectId }
    }
}
if (-not (Get-Command -Name Invoke-UserSync -ErrorAction SilentlyContinue)) {
    function Invoke-UserSync { param($Row,[string]$DefaultOU,[switch]$ProcessAll)
        if (Get-Command -Name Process-User -ErrorAction SilentlyContinue) { Process-User -Row $Row -DefaultOU $DefaultOU -ProcessAll:$ProcessAll }
        else { throw 'Invoke-UserSync not available. Ensure modules/sync-targets/WindowsAD.ps1 is present.' }
    }
}
if (-not (Get-Command -Name Show-RemovalSuggestions -ErrorAction SilentlyContinue)) {
    function Show-RemovalSuggestions { param([string]$DefaultOU,[string[]]$CsvEmails)
        if (Get-Command -Name Suggest-Removals -ErrorAction SilentlyContinue) { Suggest-Removals -DefaultOU $DefaultOU -CsvEmails $CsvEmails }
        else { Write-Log -Level 'WARN' -Message 'Removal suggestion function not available (module not loaded).' }
    }
}
if (-not (Get-Command -Name Get-UsersFromCsv -ErrorAction SilentlyContinue)) {
    function Get-UsersFromCsv { param([string]$CsvPath) Import-Csv -LiteralPath $CsvPath }
}
if (-not (Get-Command -Name ConvertTo-BooleanFriendly -ErrorAction SilentlyContinue)) {
    function ConvertTo-BooleanFriendly { param($Value)
        if ($Value -is [bool]) { return [bool]$Value }
        if ($null -eq $Value) { return $false }
        $s = $Value.ToString().Trim()
        return @('true','1','yes','y') -contains $s.ToLower()
    }
}
if (-not (Get-Command -Name Show-Welcome -ErrorAction SilentlyContinue)) {
    function Show-Welcome { param([string]$Source)
        Write-Host ""
        Write-Host "==== OpenIDSync ====" -ForegroundColor Cyan
        $src = if ([string]::IsNullOrWhiteSpace($Source)) { '(unknown)' } else { $Source }
        Write-Host ("Source: {0}" -f $src)
        Write-Host "For Online mode, ensure Microsoft Graph modules are available."
        Write-Host ('{0}' -f ('=' * 22)) -ForegroundColor Cyan
    }
}
if (-not (Get-Command -Name Get-TenantLicenseInfo -ErrorAction SilentlyContinue)) {
    function Get-TenantLicenseInfo { return [pscustomobject]@{ HasPremium = $false; Plan = 'Unknown' } }
}

# Try to load logging module
try {
    $logModulePath = Join-Path -Path $PSScriptRoot -ChildPath '50_OpenIDSync_Logging.ps1'
    if (Test-Path -LiteralPath $logModulePath) { . $logModulePath }
} catch {}

## Graph module configuration and function cap moved to modules/microsoft-graph/Graph.ps1

# ==================== Main ====================

# Note: ActiveDirectory module import is deferred until just before syncing to Windows AD

# Initialize security group exception set from config (populated later)
$script:GroupSecurityExceptionSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

$continueLoop = $true
$showDashboardNext = -not $script:NonInteractive

while ($continueLoop) {

# Resolve inputs (optionally from JSON)
if (Test-Path -LiteralPath $ConfigPath) {
    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        if ($cfg -and $cfg.UserSyncConfig) {
            $usc = $cfg.UserSyncConfig
            if (-not $PSBoundParameters.ContainsKey('CsvPath') -and $usc.CsvPath) { $CsvPath = [string]$usc.CsvPath }
            if (-not $PSBoundParameters.ContainsKey('DefaultOU') -and $usc.DefaultOU) { $DefaultOU = [string]$usc.DefaultOU }
            if (-not $PSBoundParameters.ContainsKey('NoSuggestRemovals') -and $null -ne $usc.SuggestRemovals) {
                if (-not [bool]$usc.SuggestRemovals) { $NoSuggestRemovals = $true }
            }
            # Load display name skip tokens
            if ($usc.SkipUserBasedOnDisplayName -and $usc.SkipUserBasedOnDisplayName.Count -gt 0) {
                $script:SkipDisplayNameTokens = @($usc.SkipUserBasedOnDisplayName | ForEach-Object { [string]$_ })
            }
            # Load UPN skip tokens
            if ($usc.SkipUserBasedOnUserPrincipalName -and $usc.SkipUserBasedOnUserPrincipalName.Count -gt 0) {
                ${script:SkipUpnTokens} = @($usc.SkipUserBasedOnUserPrincipalName | ForEach-Object { [string]$_ })
            }
            # Always include base UPN skip substrings regardless of config
            $baseUpnSkips = @('archiv','temp')
            if (-not $script:SkipUpnTokens) { $script:SkipUpnTokens = @() }
            foreach ($b in $baseUpnSkips) {
                $exists = $false
                foreach ($t in $script:SkipUpnTokens) { if (([string]$t).ToLower() -eq $b) { $exists = $true; break } }
                if (-not $exists) { $script:SkipUpnTokens += $b }
            }

            if ($script:GroupSecurityExceptionSet) { $script:GroupSecurityExceptionSet.Clear() }
            $exceptionList = @()
            if ($usc.PSObject.Properties['GroupSecurityExceptions']) {
                $exceptionList = @($usc.GroupSecurityExceptions)
            }
            if ($exceptionList.Count -gt 0) {
                foreach ($exceptionName in $exceptionList) {
                    if (-not [string]::IsNullOrWhiteSpace($exceptionName)) {
                        [void]$script:GroupSecurityExceptionSet.Add(([string]$exceptionName).Trim())
                    }
                }
            }

            # Online sync config: prefer separate file, fallback to legacy section for backward compatibility
            $osc = $null
            try {
                if (Test-Path -LiteralPath $script:OnlineSyncConfigPath) {
                    $oscFile = Get-Content -LiteralPath $script:OnlineSyncConfigPath -Raw | ConvertFrom-Json
                    if ($oscFile -and $oscFile.OnlineSyncConfig) { $osc = $oscFile.OnlineSyncConfig }
                }
            } catch {}
            if (-not $osc -and $cfg.OnlineSyncConfig) { $osc = $cfg.OnlineSyncConfig }

            if ($osc) {
                $oscTenantId = $null; $oscClientId = $null; $oscEnvVar = $null
                try { $oscTenantId = $osc.TenantId } catch {}
                try { $oscClientId = $osc.ClientId } catch {}
                try { $oscEnvVar = $osc.ClientSecretEnvVar } catch {}
                if (-not $PSBoundParameters.ContainsKey('TenantId') -and $oscTenantId) { $TenantId = [string]$oscTenantId }
                if (-not $PSBoundParameters.ContainsKey('ClientId') -and $oscClientId) { $ClientId = [string]$oscClientId }
                # Never read client secrets from JSON; prefer env var name from config if present
                if (-not $PSBoundParameters.ContainsKey('ClientSecretEnvVar') -and $oscEnvVar) { $ClientSecretEnvVar = [string]$oscEnvVar }
            }
            # Preferred source now lives in main config under UserSyncConfig.PreferredSource
            try {
                if (-not $PSBoundParameters.ContainsKey('Source') -and $cfg.UserSyncConfig -and $cfg.UserSyncConfig.PreferredSource) {
                    $Source = [string]$cfg.UserSyncConfig.PreferredSource
                    $script:SourceFromConfig = $true
                }
            } catch {}
            # Logging config (if present)
            if ($cfg.LoggingConfig) {
                $lgc = $cfg.LoggingConfig
                try { $script:LogMode = [string]$lgc.Mode } catch {}
                try { $script:LogFilePath = [string]$lgc.FilePath } catch {}
                try { $script:LogSyslogServer = [string]$lgc.SyslogServer } catch {}
                try { $script:LogSyslogPort = [int]$lgc.SyslogPort } catch {}
            }

            # Background mode run-modes from JSON (if provided)
            if ($script:NonInteractive) {
                try {
                    $modesObj = $null
                    if ($cfg.SyncModes) { $modesObj = $cfg.SyncModes }
                    elseif ($usc.SyncModes) { $modesObj = $usc.SyncModes }
                    # Also accept flat properties for backward compatibility
                    $mu = $null; $mg = $null; $mm = $null
                    if ($modesObj) {
                        try { $mu = [string]$modesObj.Users } catch {}
                        try { $mg = [string]$modesObj.Groups } catch {}
                        try { $mm = [string]$modesObj.Memberships } catch {}
                    } else {
                        try { $mu = [string]$usc.UsersMode } catch {}
                        try { $mg = [string]$usc.GroupsMode } catch {}
                        try { $mm = [string]$usc.MembershipsMode } catch {}
                    }
                    function _normMode([string]$v){
                        if ([string]::IsNullOrWhiteSpace($v)) { return $null }
                        $t = $v.Trim().ToUpper()
                        switch ($t) { 'A' { 'All' } 'ALL' { 'All' } 'P' { 'Prompt' } 'PROMPT' { 'Prompt' } 'S' { 'Skip' } 'SKIP' { 'Skip' } default { $null } }
                    }
                    $nmu = _normMode $mu; if ($nmu) { $script:ModeUsers = $nmu }
                    $nmg = _normMode $mg; if ($nmg) { $script:ModeGroups = $nmg }
                    $nmm = _normMode $mm; if ($nmm) { $script:ModeMemberships = $nmm }
                } catch {}
            }
        }
    } catch {}
}
if ($AutoInstallGraphModules) { $script:AutoInstallGraphModules = $true } else { $script:AutoInstallGraphModules = $false }
if ($NonInteractive) { $script:NonInteractive = $true; $script:ProcessAll = $true }
if ($AllUsers) { $script:ProcessAll = $true }
if (-not $DefaultOU) {
    if ($script:NonInteractive) {
        throw "Default OU is required in -NonInteractive mode. Provide -DefaultOU or set it in 00_OpenIDSync_Config.json."
    } else {
        $DefaultOU = Read-Host "Enter default OU distinguishedName for new/managed users (e.g. OU=Users,DC=example,DC=com)"
    }
}
if ([string]::IsNullOrWhiteSpace($DefaultOU)) {
    throw "Default OU is required."
}

# Interactive dashboard (UI overhaul) for managing prerequisites and modes
$dashboardResult = $null
if (-not $script:NonInteractive -and $showDashboardNext) {
    $dashboardResult = Invoke-OpenIdSyncDashboard -ConfigPath $script:ConfigPath -OnlineConfigPath $script:OnlineSyncConfigPath -PasswordFilePath $script:CredLogPath -InitialSource $Source -InitialTarget $Target -DefaultOU $DefaultOU
    if ($dashboardResult.ExitRequested -and -not $dashboardResult.StartSync) {
        try { Write-Log -Level 'INFO' -Message 'User exited from OpenIDSync dashboard before synchronization.' } catch {}
        return
    }
    if ($dashboardResult.StartSync) {
        if ($dashboardResult.Source) { $Source = $dashboardResult.Source }
        if ($dashboardResult.Target) { $Target = $dashboardResult.Target }
        if ($dashboardResult.UsersMode) { $script:ModeUsers = $dashboardResult.UsersMode }
        if ($dashboardResult.GroupsMode) { $script:ModeGroups = $dashboardResult.GroupsMode }
        if ($dashboardResult.MembershipsMode) { $script:ModeMemberships = $dashboardResult.MembershipsMode }
    }
    $showDashboardNext = $false
}
if (-not $script:NonInteractive) {
    $script:ProcessAll = ($script:ModeUsers -eq 'All')
    $script:GroupsProcessAll = ($script:ModeGroups -eq 'All')
    $script:MembershipsProcessAll = ($script:ModeMemberships -eq 'All')
}

if (Test-Path -LiteralPath $ConfigPath) {
    try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch {}
}

# Choose source if not specified explicitly or via config
if ([string]::IsNullOrWhiteSpace($Source) -and $script:NonInteractive) {
    $cfgPathMsg = if ($script:ConfigPath) { $script:ConfigPath } else { '00_OpenIDSync_Config.json' }
    $msg = "-NonInteractive: Missing input source. Set UserSyncConfig.PreferredSource to 'Online' (recommended) or 'CSV' in $cfgPathMsg, or pass -Source Online/CSV on the command line."
    throw $msg
}

# Compute friendly labels for source & target
$sourceFriendly = switch ($Source) { 'Online' { 'Microsoft Entra ID' } 'CSV' { 'CSV File' } default { $Source } }
$targetFriendly = switch (($Target + '').ToUpper()) { 'WINDOWSAD' { 'Windows Active Directory' } default { $Target } }
$script:SourceFriendly = $sourceFriendly
$script:TargetFriendly = $targetFriendly



# Guard: NonInteractive cannot create app interactively
if ($script:NonInteractive -and $AutoCreateGraphApp) {
    throw "-AutoCreateGraphApp requires interactive sign-in and cannot be used with -NonInteractive. Pre-create the app or run once interactively to bootstrap."
}

if ($Source -eq 'CSV') {
    if (-not $CsvPath) {
        if ($script:NonInteractive) { throw "CSV path is required in -NonInteractive mode. Provide -CsvPath." }
        $CsvPath = Read-Host "Enter path to Microsoft 365 users CSV export"
    }
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }
}

# Default SkipDisplayNameTokens if none provided in JSON
if (-not $script:SkipDisplayNameTokens -or $script:SkipDisplayNameTokens.Count -eq 0) {
    $script:SkipDisplayNameTokens = @('(Archive)', '(Temp)')
}

# Default SkipUpnTokens if none provided in JSON
if (-not $script:SkipUpnTokens -or $script:SkipUpnTokens.Count -eq 0) {
    $script:SkipUpnTokens = @('#EXT#', 'Temporary', 'archiv', 'temp')
} else {
    # Ensure base UPN skip substrings are present
    $baseUpnSkips = @('archiv','temp')
    foreach ($b in $baseUpnSkips) {
        $exists = $false
        foreach ($t in $script:SkipUpnTokens) { if (([string]$t).ToLower() -eq $b) { $exists = $true; break } }
        if (-not $exists) { $script:SkipUpnTokens += $b }
    }
}

# Logs (default to file-only, Linux-like filenames) — always under ./log relative to the script
if (-not $script:LogMode) { $script:LogMode = 'File' }
if (-not $script:LogSyslogPort) { $script:LogSyslogPort = 514 }
$script:BaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:LogDir = Join-Path -Path $script:BaseDir -ChildPath 'log'
try { if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null } } catch {}
# Respect configured FilePath name but place it inside ./log
$logFileName = if ($script:LogFilePath) { Split-Path -Path $script:LogFilePath -Leaf } else { 'openidsync.log' }
$script:AuditLogPath = Join-Path -Path $script:LogDir -ChildPath $logFileName
$script:CredLogPath  = Join-Path -Path $script:LogDir -ChildPath 'openidsync-credentials.csv'

try { Initialize-Logger -Mode $script:LogMode -FilePath $script:AuditLogPath -SyslogServer $script:LogSyslogServer -SyslogPort $script:LogSyslogPort | Out-Null } catch {}

if (-not (Test-Path -LiteralPath $script:CredLogPath)) {
    "Email,UserPrincipalName,SamAccountName,GeneratedPassword" | Out-File -FilePath $script:CredLogPath -Encoding UTF8 -Force
}
$syslogHostForMsg = if ($script:LogSyslogServer) { $script:LogSyslogServer } else { '-' }
Write-Log -Level 'INFO' -Message ("Logging initialized: Mode={0}, File={1}, Syslog={2}:{3}" -f $script:LogMode, $script:AuditLogPath, $syslogHostForMsg, $script:LogSyslogPort)
$funcCapMsg = "MaximumFunctionCount in use: $MaximumFunctionCount"
Write-Log -Level 'INFO' -Message $funcCapMsg
if ($Source -eq 'Online') {
    Show-Welcome -Source $Source
    Write-Log -Level 'INFO' -Message ("Source: {0} (Online)" -f $sourceFriendly)
    $script:SourceLabel = 'Online'
} else {
    Write-Log -Level 'INFO' -Message ("Source: {0} ($CsvPath)" -f $sourceFriendly)
    $script:SourceLabel = $Source
}
Write-Log -Level 'INFO' -Message ("Target: {0}" -f $targetFriendly)
Write-Log -Level 'INFO' -Message "Default OU: $DefaultOU"

if ($Source -eq 'Online') {
    # Try to use configured app credentials; optionally auto-create if requested
    if ((-not $TenantId -or -not $ClientId) -and $AutoCreateGraphApp) {
        try {
            Import-GraphModules
            Test-GraphCommands
            Show-SecuritySummary -CreatingApp
            # Create app registration (do not persist secret to disk)
            $appDisplayName = 'OpenIDSync_org__Entra_Sync_Windows_AD'
            try {
                if ($cfg -and $cfg.OnlineSyncConfig -and $cfg.OnlineSyncConfig.AppRegistrationName) { $appDisplayName = [string]$cfg.OnlineSyncConfig.AppRegistrationName }
                elseif ($osc -and $osc.AppRegistrationName) { $appDisplayName = [string]$osc.AppRegistrationName }
            } catch {}
            $appInfo = New-OpenIdSyncGraphApp -DisplayName $appDisplayName
            $TenantId = $appInfo.TenantId; $ClientId = $appInfo.ClientId; $ClientSecret = $appInfo.ClientSecret
            Write-Log -Level 'INFO' -Message 'New App Registration created successfully for Online mode.'
            # Save identifiers to config to avoid re-creating
            Save-OnlineSyncConfig -OnlineConfigPath $script:OnlineSyncConfigPath -TenantId $TenantId -ClientId $ClientId -SpObjectId $appInfo.SpObjectId -ClientSecretEnvVar $ClientSecretEnvVar -AppRegistrationName $appDisplayName
            # Show secret ONCE and instruct to set environment variable
            Write-Host ""; Write-Host "==== IMPORTANT: CLIENT SECRET (copy and store securely) ==== " -ForegroundColor Yellow
            Write-Host ($appInfo.ClientSecret) -ForegroundColor Yellow
            Write-Host "Set environment variable before running next time (example):" -ForegroundColor Yellow
            Write-Host ('setx {0} "YOUR_SECRET_HERE"' -f $ClientSecretEnvVar) -ForegroundColor Yellow
            Write-Host "Secret will NOT be stored in any file." -ForegroundColor Yellow
            if ($AssignDirectoryReaderToApp) {
                Grant-DirectoryReadersToServicePrincipal -SpObjectId $appInfo.SpObjectId
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Auto app registration failed: $($_.Exception.Message). Falling back to delegated sign-in."
        }
    }
    # If requested and credentials provided for an existing app, assign Directory Readers to its SP
    if ($AssignDirectoryReaderToApp -and $ClientId) {
        try {
            Import-GraphModules
            Test-GraphCommands
            $ok = Connect-GraphDelegated -Scopes @('RoleManagement.ReadWrite.Directory')
            if ($ok) {
                $spIdToUse = $null
                # Prefer SP object id from separate online config file if available
                try {
                    if (Test-Path -LiteralPath $script:OnlineSyncConfigPath) {
                        $cfgTmp = Get-Content -LiteralPath $script:OnlineSyncConfigPath -Raw | ConvertFrom-Json
                        if ($cfgTmp -and $cfgTmp.OnlineSyncConfig -and $cfgTmp.OnlineSyncConfig.SpObjectId) { $spIdToUse = [string]$cfgTmp.OnlineSyncConfig.SpObjectId }
                    }
                } catch {}
                if (-not $spIdToUse) {
                    $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction Stop | Select-Object -First 1
                    if ($sp) { $spIdToUse = $sp.Id }
                }
                if ($spIdToUse) { Grant-DirectoryReadersToServicePrincipal -SpObjectId $spIdToUse }
                else { Write-Log -Level 'WARN' -Message "Service principal not found for appId: $ClientId" }
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Failed to assign Directory Readers to existing app: $($_.Exception.Message)"
        }
    }
    try {
    Import-GraphModules
    Test-GraphCommands
        # Resolve client secret from env var if not provided via param
        if (-not $ClientSecret) {
            $envSecret = $null
            if ($ClientSecretEnvVar) {
                $envSecret = [Environment]::GetEnvironmentVariable($ClientSecretEnvVar, 'Process')
                if (-not $envSecret) { $envSecret = [Environment]::GetEnvironmentVariable($ClientSecretEnvVar, 'User') }
                if (-not $envSecret) { $envSecret = [Environment]::GetEnvironmentVariable($ClientSecretEnvVar, 'Machine') }
            }
            if ($envSecret) { $ClientSecret = $envSecret }
        }
        if (-not $ClientSecret -and $TenantId -and $ClientId) {
            if ($script:NonInteractive) {
                $msg = "Client secret not found in env var '$ClientSecretEnvVar' in -NonInteractive mode. Set it via: setx $ClientSecretEnvVar `"YOUR_SECRET_HERE`" (open a new PowerShell window)."
                throw $msg
            } else {
                Write-Host "Client secret not found in environment variable '$ClientSecretEnvVar'." -ForegroundColor Yellow
                $ClientSecret = Read-Host -AsSecureString "Enter Client Secret (will not be stored)" | ForEach-Object { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }
                if (-not $ClientSecret) { Write-Host ("Tip: setx $ClientSecretEnvVar `"YOUR_SECRET_HERE`"  (persists for new sessions)") -ForegroundColor Yellow }
            }
        }
    if ($TenantId -and $ClientId -and $ClientSecret) { Show-SecuritySummary -AppOnly }
    else { Show-SecuritySummary }
        # Detect tenant license plan (for guidance only)
        $lic = Get-TenantLicenseInfo
        if ($lic) {
            Write-Log -Level 'INFO' -Message ("Tenant license plan detected: {0} (Premium features: {1})" -f $lic.Plan, $(if($lic.HasPremium){'Yes'}else{'No'}))
        }
        if ($script:ModeUsers -ne 'Skip') {
            $rows = Get-EntraUsersViaGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        } else { $rows = @() }
    } catch {
        Write-Log -Level 'ERROR' -Message "Online fetch failed: $($_.Exception.Message)"
        throw
    }
} else {
    # Import CSV via provider (new M365 Admin export format)
    if ($script:ModeUsers -ne 'Skip') { $rows = Get-UsersFromCsv -CsvPath $CsvPath } else { $rows = @() }
}

# --- Start-of-run summary (console + log) ---
try {
    $csvPathDisp = if ($CsvPath) { [string]$CsvPath } else { '-' }
    $cfgMainPath = if ($script:ConfigPath) { [string]$script:ConfigPath } else { '-' }
    $cfgOnlinePath = if ($script:OnlineSyncConfigPath) { [string]$script:OnlineSyncConfigPath } else { '-' }
    $syslogHost = if ($script:LogSyslogServer) { [string]$script:LogSyslogServer } else { '-' }
    $lgMode = if ($script:LogMode) { [string]$script:LogMode } else { 'File' }
    $lgFile = if ($script:AuditLogPath) { [string]$script:AuditLogPath } else { '-' }
    $lgPort = if ($script:LogSyslogPort) { [string]$script:LogSyslogPort } else { '514' }

    $summaryHeader = '==== Run Configuration Summary ===='
    Write-Host $summaryHeader -ForegroundColor Cyan
    $summaryLines = @(
        ('{0,-26}: {1}' -f 'Main Config', $cfgMainPath),
        ('{0,-26}: {1}' -f 'Online Config', $cfgOnlinePath),
    ('{0,-26}: {1}' -f 'Source', $sourceFriendly),
    ('{0,-26}: {1}' -f 'Target', $targetFriendly),
        ('{0,-26}: {1}' -f 'Default OU', $DefaultOU),
        ('{0,-26}: {1}' -f 'Users Mode', $script:ModeUsers),
        ('{0,-26}: {1}' -f 'Groups Mode', $script:ModeGroups),
        ('{0,-26}: {1}' -f 'Memberships Mode', $script:ModeMemberships),
        ('{0,-26}: {1}' -f 'CSV Path', $csvPathDisp),
        ('{0,-26}: {1}' -f 'Logging Mode', $lgMode),
        ('{0,-26}: {1}' -f 'Log File', $lgFile),
        ('{0,-26}: {1}' -f 'Syslog', ("{0}:{1}" -f $syslogHost, $lgPort))
    )
    foreach ($l in $summaryLines) { Write-Host $l }
    Write-Host ('{0}' -f ('=' * $summaryHeader.Length)) -ForegroundColor Cyan
    foreach ($l in $summaryLines) { Write-Log -Level 'INFO' -Message $l }

    # Also echo key values from JSON so the user understands current run
    if ($cfgMainPath -ne '-' -and (Test-Path -LiteralPath $cfgMainPath)) {
        try {
            $cfgPreview = Get-Content -LiteralPath $cfgMainPath -Raw | ConvertFrom-Json
            if ($cfgPreview.UserSyncConfig) {
                #Write-Host "-- UserSyncConfig --" -ForegroundColor DarkCyan
                $usc = $cfgPreview.UserSyncConfig
                $uscLines = @()
                $uscLines += ('{0,-26}: {1}' -f 'CsvPath', [string]$usc.CsvPath)
                $uscLines += ('{0,-26}: {1}' -f 'DefaultOU', [string]$usc.DefaultOU)
                $uscLines += ('{0,-26}: {1}' -f 'PreferredSource', [string]$usc.PreferredSource)
                $uscLines += ('{0,-26}: {1}' -f 'SuggestRemovals', [string]$usc.SuggestRemovals)
                $displaySkips = @($usc.SkipUserBasedOnDisplayName) | ForEach-Object { [string]$_ }
                $upnSkips = @($usc.SkipUserBasedOnUserPrincipalName) | ForEach-Object { [string]$_ }
                $securityExceptions = @()
                if ($usc.PSObject.Properties['GroupSecurityExceptions']) {
                    $securityExceptions = @($usc.GroupSecurityExceptions) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ }
                }
                $uscLines += ('{0,-26}: {1}' -f 'SkipDisplayNameTokens', ([string]::Join(', ', $displaySkips)))
                $uscLines += ('{0,-26}: {1}' -f 'SkipUpnTokens', ([string]::Join(', ', $upnSkips)))
                $uscLines += ('{0,-26}: {1}' -f 'GroupSecurityExceptions', ([string]::Join(', ', $securityExceptions)))
                foreach ($l in $uscLines) { Write-Log -Level 'INFO' -Message ("UserSyncConfig | {0}" -f $l) }
            }
            if ($cfgPreview.LoggingConfig) {
                #Write-Host "-- LoggingConfig --" -ForegroundColor DarkCyan
                $lgc = $cfgPreview.LoggingConfig
                $lgcLines = @()
                $lgcLines += ('{0,-26}: {1}' -f 'Mode', [string]$lgc.Mode)
                $lgcLines += ('{0,-26}: {1}' -f 'FilePath', [string]$lgc.FilePath)
                $lgcLines += ('{0,-26}: {1}' -f 'SyslogServer', [string]$lgc.SyslogServer)
                $lgcLines += ('{0,-26}: {1}' -f 'SyslogPort', [string]$lgc.SyslogPort)
                foreach ($l in $lgcLines) {  Write-Log -Level 'INFO' -Message ("LoggingConfig | {0}" -f $l) }
            }
        } catch {}
    }
    if ($cfgOnlinePath -ne '-' -and (Test-Path -LiteralPath $cfgOnlinePath)) {
        try {
            $oscPreview = Get-Content -LiteralPath $cfgOnlinePath -Raw | ConvertFrom-Json
            if ($oscPreview.OnlineSyncConfig) {
                #Write-Host "-- OnlineSyncConfig --" -ForegroundColor DarkCyan
                $oc = $oscPreview.OnlineSyncConfig
                $ocLines = @()
                $ocLines += ('{0,-26}: {1}' -f 'TenantId', [string]$oc.TenantId)
                $ocLines += ('{0,-26}: {1}' -f 'ClientId', [string]$oc.ClientId)
                $ocLines += ('{0,-26}: {1}' -f 'SpObjectId', [string]$oc.SpObjectId)
                $ocLines += ('{0,-26}: {1}' -f 'ClientSecretEnvVar', [string]$oc.ClientSecretEnvVar)
                foreach ($l in $ocLines) { Write-Log -Level 'INFO' -Message ("OnlineSyncConfig | {0}" -f $l) }
            }
        } catch {}
    }
} catch {}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Log -Level 'WARN' -Message "No user rows fetched from source."
    if ($Source -ne 'Online' -or $script:ModeUsers -ne 'Skip') {
        # For CSV or when users requested, no rows means abort
        return
    }
}

$script:ProcessAll = $false
$script:QuitRequested = $false

# Initialize summary counters
$script:Summary = [ordered]@{
    Created = 0
    Updated = 0
    SkippedByUPN = 0
    SkippedByDisplayName = 0
    SkippedPrompt = 0
    SkippedEmptyUPN = 0
    SkippedAdministrator = 0
    FailedCreate = 0
    FailedUpdate = 0
    GroupsCreated = 0
    GroupsExisting = 0
    GroupMembersAdded = 0
    GroupMembersRemoved = 0
    DomainAdminElevations = 0
}

# Ensure AD module present right before processing users
try {
    Import-RequiredModule -Name ActiveDirectory
}
catch {
    Write-Host "ActiveDirectory PowerShell module is not installed." -ForegroundColor Yellow
    Write-Host "Install on Windows Server (PowerShell 5.1):" -ForegroundColor Yellow
    Write-Host "  Install-WindowsFeature -Name RSAT-AD-PowerShell" -ForegroundColor Yellow
    Write-Host "Install on Windows 10/11 (1809+):" -ForegroundColor Yellow
    Write-Host "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Yellow
    throw
}

# Process users
if ($script:ModeUsers -ne 'Skip') {
    if ($script:ModeUsers -eq 'All') { $script:ProcessAll = $true }
    if ($script:ModeUsers -eq 'Prompt') { $script:ProcessAll = $false }
    foreach ($row in $rows) {
        Invoke-UserSync -Row $row -DefaultOU $DefaultOU
        if ($script:QuitRequested) { Write-Log -Level 'INFO' -Message 'Quit requested by user. Stopping user import.'; break }
    }

    # Privileged elevation: Global Administrators -> Domain Admins (only Online source scenario makes sense)
    if ($Source -eq 'Online' -and -not $script:QuitRequested) {
        try {
            if (Get-Command -Name Get-EntraGlobalAdministratorUpns -ErrorAction SilentlyContinue) {
                $globalAdmins = Get-EntraGlobalAdministratorUpns
                if ($globalAdmins -and $globalAdmins.Count -gt 0) {
                    Write-Log -Level 'ACTION' -Message ("Evaluating Global Administrators for Domain Admin elevation: {0}" -f $globalAdmins.Count)
                    foreach ($ga in $globalAdmins) {
                        try {
                            Invoke-OpenIdSyncExceptionElevation -Upn $ga -ExceptionTags @('GLOBAL_ADMIN')
                            # Count if membership now present
                            $adUser = Get-ADUser -Filter "userPrincipalName -eq '$ga'" -ErrorAction SilentlyContinue
                            if ($adUser) {
                                $isNow = (Get-ADGroupMember -Identity 'Domain Admins' -Recursive:$false -ErrorAction SilentlyContinue | Where-Object { $_.DistinguishedName -eq $adUser.DistinguishedName } | Select-Object -First 1)
                                if ($isNow) { $script:Summary['DomainAdminElevations']++ }
                            }
                        } catch { Write-Log -Level 'ERROR' -Message ("Elevation attempt failed for ${ga}: $($_.Exception.Message)") }
                    }
                } else { Write-Log -Level 'INFO' -Message 'No Global Administrators detected (or retrieval failed).' }
            } else { Write-Log -Level 'WARN' -Message 'Get-EntraGlobalAdministratorUpns not available (module not loaded?)' }
        } catch { Write-Log -Level 'ERROR' -Message ("Global Admin elevation phase failed: $($_.Exception.Message)") }
    }
}

# Groups and memberships (Online source only)
if ($Source -eq 'Online' -and -not $script:QuitRequested -and $script:ModeGroups -ne 'Skip') {
    try {
        Write-Log -Level 'ACTION' -Message 'Reconciling groups from Entra to AD...'
        $groups = Get-EntraGroupsViaGraph
        Write-Log -Level 'INFO' -Message ("Groups to reconcile: {0}" -f $groups.Count)
        $groupMap = @{}
        $securityDuplicateMap = @{}
        $securityExceptionSet = $script:GroupSecurityExceptionSet
        foreach ($g in $groups) {
            $proceedGroup = $true
            if ($script:ModeGroups -eq 'Prompt' -and -not $script:GroupsProcessAll) {
                $q = "Process group '$($g.DisplayName)' (Kind=$($g.Kind))? [Y]es/[N]o/[A]ll/[Q]uit"
                $ans = Read-Host $q; Write-Log -Level 'PROMPT' -Message ($q + " -> [" + $ans + "]")
                switch (($ans + '').Trim().ToUpper()) { 'A' { $script:GroupsProcessAll=$true } 'Q' { $script:QuitRequested=$true; $proceedGroup=$false } 'N' { $proceedGroup=$false } default { $proceedGroup=$true } }
            }
            if ($script:QuitRequested) { break }
            if (-not $proceedGroup) { continue }
            $res = New-ADGroupIfMissing -DisplayName $g.DisplayName -Kind $g.Kind -TargetOU $DefaultOU
            if ($res -and $res.Group) {
                $groupMap[$g.Id] = $res.Group
                if ($res.Created) { $script:Summary['GroupsCreated']++ } else { $script:Summary['GroupsExisting']++ }
                $shouldDuplicate = $false
                if ($securityExceptionSet -and $securityExceptionSet.Count -gt 0) {
                    $shouldDuplicate = $securityExceptionSet.Contains(([string]$g.DisplayName).Trim())
                }
                if ($shouldDuplicate -and $g.Kind -ne 'Security') {
                    Write-Log -Level 'DEBUG' -Message ("Group '{0}' matched security duplication exception (Kind={1})." -f $g.DisplayName, $g.Kind)
                    $secRes = New-ADGroupIfMissing -DisplayName $g.DisplayName -Kind 'Security' -TargetOU $DefaultOU
                    if ($secRes -and $secRes.Group) {
                        $securityDuplicateMap[$g.Id] = $secRes.Group
                        if ($secRes.Created) { $script:Summary['GroupsCreated']++ } else { $script:Summary['GroupsExisting']++ }
                        Write-Log -Level 'DEBUG' -Message ("Security clone available for '{0}' -> {1}" -f $g.DisplayName, $secRes.Group.SamAccountName)
                    } else {
                        Write-Log -Level 'WARN' -Message ("Failed to ensure security clone for exception group '{0}'." -f $g.DisplayName)
                    }
                } elseif ($shouldDuplicate -and $g.Kind -eq 'Security') {
                    Write-Log -Level 'DEBUG' -Message ("Group '{0}' already Security; skipping clone despite exception." -f $g.DisplayName)
                }
            }
        }
        if ($script:ModeMemberships -ne 'Skip' -and -not $script:QuitRequested) {
            Write-Log -Level 'ACTION' -Message 'Reconciling group memberships...'
            foreach ($g in $groups) {
                if (-not $groupMap.ContainsKey($g.Id)) { continue }
                $targetG = $groupMap[$g.Id]
                $securityClone = $null
                if ($securityDuplicateMap.ContainsKey($g.Id)) { $securityClone = $securityDuplicateMap[$g.Id] }
                if ($script:ModeMemberships -eq 'Prompt' -and -not $script:MembershipsProcessAll) {
                    # Dry compute current vs desired to present counts
                    # We reuse Set-AdGroupMemberships logic by precomputing differences here would duplicate code; prompt with counts from API calls
                    $apply = $true
                    $msg = "Apply membership changes to group '$($targetG.SamAccountName)'? [Y]es/[N]o/[A]ll/[Q]uit"
                    $ans2 = Read-Host $msg; Write-Log -Level 'PROMPT' -Message ($msg + " -> [" + $ans2 + "]")
                    switch (($ans2 + '').Trim().ToUpper()) { 'A' { $script:MembershipsProcessAll=$true } 'Q' { $script:QuitRequested=$true; $apply=$false } 'N' { $apply=$false } default { $apply=$true } }
                    if (-not $apply) { continue }
                }
                $memberUpns = @(Get-EntraGroupMembersViaGraph -GroupId $g.Id)
                if ($null -eq $memberUpns) { $memberUpns = @() }
                $mres = Set-AdGroupMemberships -Group $targetG -MemberUpns $memberUpns
                if ($mres) {
                    Write-Log -Level 'INFO' -Message ("Memberships set for {0}: +{1}/-{2}" -f $targetG.SamAccountName, $mres.Added, $mres.Removed)
                    $script:Summary['GroupMembersAdded'] += [int]$mres.Added
                    $script:Summary['GroupMembersRemoved'] += [int]$mres.Removed
                }
                if ($securityClone) {
                    Write-Log -Level 'DEBUG' -Message ("Applying membership parity to security clone {0} for source group '{1}'." -f $securityClone.SamAccountName, $g.DisplayName)
                    $secRes = Set-AdGroupMemberships -Group $securityClone -MemberUpns $memberUpns
                    if ($secRes) {
                        Write-Log -Level 'INFO' -Message ("Memberships set for {0} (security clone of {1}): +{2}/-{3}" -f $securityClone.SamAccountName, $targetG.SamAccountName, $secRes.Added, $secRes.Removed)
                        $script:Summary['GroupMembersAdded'] += [int]$secRes.Added
                        $script:Summary['GroupMembersRemoved'] += [int]$secRes.Removed
                    }
                }
            }
        }
    } catch { Write-Log -Level 'ERROR' -Message ("Group sync failed: {0}" -f $_.Exception.Message) }
}

# Suggest removals (not deleting, only suggesting)
if (-not $NoSuggestRemovals -and -not $script:QuitRequested) {
    $csvEmails = $rows | ForEach-Object {
        $p = Get-PrimarySmtpFromProxyAddresses -ProxyString $_.'Proxy addresses'
        if ($p) { $p } else { $_.'User principal name' }
    }
    Show-RemovalSuggestions -DefaultOU $DefaultOU -CsvEmails $csvEmails
} elseif ($script:QuitRequested) {
    Write-Log -Level 'INFO' -Message 'Skip removal suggestions due to quit request.'
}

# Print summary table
try {
    Write-Host ""
    Write-Host "==================== SUMMARY ====================" -ForegroundColor Cyan
    $summaryRows = @()
    foreach ($k in $script:Summary.Keys) {
        $summaryRows += [pscustomobject]@{ Action = $k; Count = [int]$script:Summary[$k] }
    }
    $summaryRows = $summaryRows | Where-Object { $_.Count -gt 0 } | Sort-Object -Property Action
    if ($summaryRows.Count -gt 0) {
        $table = ($summaryRows | Format-Table -AutoSize | Out-String)
        Write-Host $table
        foreach ($row in $summaryRows) {
            Write-Log -Level 'INFO' -Message ("Summary -> {0}: {1}" -f $row.Action, $row.Count)
        }
    } else {
        Write-Host "No actions recorded."
        Write-Log -Level 'INFO' -Message 'Summary -> No actions recorded.'
    }
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Log -Level 'ERROR' -Message "Failed to print summary: $($_.Exception.Message)"
}

Write-Log -Level 'INFO' -Message "Finished."

    if ($script:NonInteractive) {
        $continueLoop = $false
        break
    }

    $postAction = $null
    while (-not $postAction) {
        $choice = (Read-Host "Next steps? 1) Rerun Sync  2) Back to main menu  3) Quit").Trim()
        Write-Log -Level 'PROMPT' -Message ("Next steps menu -> [{0}]" -f $choice)
        switch ($choice) {
            '1' { $postAction = 'Rerun' }
            '2' { $postAction = 'Dashboard' }
            '3' { $postAction = 'Quit' }
            default {
                Write-Host 'Please choose 1, 2, or 3.' -ForegroundColor Yellow
            }
        }
    }

    $rerunRequested = $false
    $dashboardRequested = $false
    switch ($postAction) {
        'Rerun' {
            $rerunRequested = $true
            Write-Log -Level 'INFO' -Message 'Post-sync menu: rerun selected.'
        }
        'Dashboard' {
            $dashboardRequested = $true
            Write-Log -Level 'INFO' -Message 'Post-sync menu: return to dashboard selected.'
        }
        'Quit' {
            $continueLoop = $false
            Write-Log -Level 'INFO' -Message 'Post-sync menu: quit selected.'
        }
    }

    if (-not $continueLoop) { break }

    if ($rerunRequested) {
        $showDashboardNext = $false
        continue
    }

    if ($dashboardRequested) {
        $showDashboardNext = $true
        continue
    }
}

