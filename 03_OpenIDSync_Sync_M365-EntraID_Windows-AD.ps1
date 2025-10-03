param(
    [string]$CsvPath,
    [string]$DefaultOU,
    [ValidateSet('CSV','Online')]
    [string]$Source,
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

# Choose source if not specified explicitly or via config
if ([string]::IsNullOrWhiteSpace($Source)) {
    if ($script:NonInteractive) {
        $cfgPathMsg = if ($script:ConfigPath) { $script:ConfigPath } else { '00_OpenIDSync_Config.json' }
        $msg = "-NonInteractive: Missing input source. Set UserSyncConfig.PreferredSource to 'Online' (recommended) or 'CSV' in $cfgPathMsg, or pass -Source Online/CSV on the command line."
        throw $msg
    } else {
        Write-Host "Select input source:" -ForegroundColor Cyan
        Write-Host "  1 - Online (Microsoft Graph / Entra ID)" -ForegroundColor Cyan
        Write-Host "  2 - CSV (offline Microsoft 365 export)" -ForegroundColor Cyan
        $ans = Read-Host "Enter 1 or 2 (default: 1)"
        switch (($ans + '').Trim().ToUpper()) {
            '' { $Source = 'Online' }
            '1' { $Source = 'Online' }
            '2' { $Source = 'CSV' }
            'O' { $Source = 'Online' } # backward compatible
            'C' { $Source = 'CSV' }    # backward compatible
            default { $Source = 'Online' }
        }
    }
}

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
    Write-Log -Level 'INFO' -Message "Source: Online (Microsoft Graph)"
    $script:SourceLabel = 'Online'
} else {
    Write-Log -Level 'INFO' -Message "Source: CSV ($CsvPath)"
    $script:SourceLabel = 'CSV'
}
Write-Log -Level 'INFO' -Message "Default OU: $DefaultOU"

if ($Source -eq 'Online') {
    # Try to use configured app credentials; optionally auto-create if requested
    if ((-not $TenantId -or -not $ClientId) -and $AutoCreateGraphApp) {
        try {
            Import-GraphModules
            Test-GraphCommands
            Show-SecuritySummary -CreatingApp
            # Create app registration (do not persist secret to disk)
            $appInfo = New-OpenIdSyncGraphApp
            $TenantId = $appInfo.TenantId; $ClientId = $appInfo.ClientId; $ClientSecret = $appInfo.ClientSecret
            Write-Log -Level 'INFO' -Message 'New App Registration created successfully for Online mode.'
            # Save identifiers to config to avoid re-creating
            Save-OnlineSyncConfig -OnlineConfigPath $script:OnlineSyncConfigPath -TenantId $TenantId -ClientId $ClientId -SpObjectId $appInfo.SpObjectId -ClientSecretEnvVar $ClientSecretEnvVar
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
    $rows = Get-EntraUsersViaGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    } catch {
        Write-Log -Level 'ERROR' -Message "Online fetch failed: $($_.Exception.Message)"
        throw
    }
} else {
    # Import CSV via provider (new M365 Admin export format)
    $rows = Get-UsersFromCsv -CsvPath $CsvPath
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
        ('{0,-26}: {1}' -f 'Source', $Source),
        ('{0,-26}: {1}' -f 'Default OU', $DefaultOU),
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
                Write-Host "-- UserSyncConfig --" -ForegroundColor DarkCyan
                $usc = $cfgPreview.UserSyncConfig
                $uscLines = @()
                $uscLines += ('{0,-26}: {1}' -f 'CsvPath', [string]$usc.CsvPath)
                $uscLines += ('{0,-26}: {1}' -f 'DefaultOU', [string]$usc.DefaultOU)
                $uscLines += ('{0,-26}: {1}' -f 'PreferredSource', [string]$usc.PreferredSource)
                $uscLines += ('{0,-26}: {1}' -f 'SuggestRemovals', [string]$usc.SuggestRemovals)
                $uscLines += ('{0,-26}: {1}' -f 'SkipDisplayNameTokens', ([string]::Join(', ', [string[]]$usc.SkipUserBasedOnDisplayName)))
                $uscLines += ('{0,-26}: {1}' -f 'SkipUpnTokens', ([string]::Join(', ', [string[]]$usc.SkipUserBasedOnUserPrincipalName)))
                foreach ($l in $uscLines) { Write-Host $l; Write-Log -Level 'INFO' -Message ("UserSyncConfig | {0}" -f $l) }
            }
            if ($cfgPreview.LoggingConfig) {
                Write-Host "-- LoggingConfig --" -ForegroundColor DarkCyan
                $lgc = $cfgPreview.LoggingConfig
                $lgcLines = @()
                $lgcLines += ('{0,-26}: {1}' -f 'Mode', [string]$lgc.Mode)
                $lgcLines += ('{0,-26}: {1}' -f 'FilePath', [string]$lgc.FilePath)
                $lgcLines += ('{0,-26}: {1}' -f 'SyslogServer', [string]$lgc.SyslogServer)
                $lgcLines += ('{0,-26}: {1}' -f 'SyslogPort', [string]$lgc.SyslogPort)
                foreach ($l in $lgcLines) { Write-Host $l; Write-Log -Level 'INFO' -Message ("LoggingConfig | {0}" -f $l) }
            }
        } catch {}
    }
    if ($cfgOnlinePath -ne '-' -and (Test-Path -LiteralPath $cfgOnlinePath)) {
        try {
            $oscPreview = Get-Content -LiteralPath $cfgOnlinePath -Raw | ConvertFrom-Json
            if ($oscPreview.OnlineSyncConfig) {
                Write-Host "-- OnlineSyncConfig --" -ForegroundColor DarkCyan
                $oc = $oscPreview.OnlineSyncConfig
                $ocLines = @()
                $ocLines += ('{0,-26}: {1}' -f 'TenantId', [string]$oc.TenantId)
                $ocLines += ('{0,-26}: {1}' -f 'ClientId', [string]$oc.ClientId)
                $ocLines += ('{0,-26}: {1}' -f 'SpObjectId', [string]$oc.SpObjectId)
                $ocLines += ('{0,-26}: {1}' -f 'ClientSecretEnvVar', [string]$oc.ClientSecretEnvVar)
                foreach ($l in $ocLines) { Write-Host $l; Write-Log -Level 'INFO' -Message ("OnlineSyncConfig | {0}" -f $l) }
            }
        } catch {}
    }
} catch {}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Log -Level 'WARN' -Message "No rows found from input source."
    return
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
foreach ($row in $rows) {
    Invoke-UserSync -Row $row -DefaultOU $DefaultOU

    if ($script:QuitRequested) {
        Write-Log -Level 'INFO' -Message 'Quit requested by user. Stopping import.'
        break
    }
}

# Groups and memberships (Online source only)
if ($Source -eq 'Online' -and -not $script:QuitRequested) {
    try {
        Write-Log -Level 'ACTION' -Message 'Reconciling groups from Entra to AD...'
        $groups = Get-EntraGroupsViaGraph
        Write-Log -Level 'INFO' -Message ("Groups to reconcile: {0}" -f $groups.Count)
        $groupMap = @{}
        foreach ($g in $groups) {
            $res = New-ADGroupIfMissing -DisplayName $g.DisplayName -Kind $g.Kind -TargetOU $DefaultOU
            if ($res -and $res.Group) {
                $groupMap[$g.Id] = $res.Group
                if ($res.Created) { $script:Summary['GroupsCreated']++ } else { $script:Summary['GroupsExisting']++ }
            }
        }
        Write-Log -Level 'ACTION' -Message 'Reconciling group memberships...'
        foreach ($g in $groups) {
            if (-not $groupMap.ContainsKey($g.Id)) { continue }
            $targetG = $groupMap[$g.Id]
            $memberUpns = Get-EntraGroupMembersViaGraph -GroupId $g.Id
            $mres = Set-AdGroupMemberships -Group $targetG -MemberUpns $memberUpns
            if ($mres) {
                Write-Log -Level 'INFO' -Message ("Memberships set for {0}: +{1}/-{2}" -f $targetG.SamAccountName, $mres.Added, $mres.Removed)
                $script:Summary['GroupMembersAdded'] += [int]$mres.Added
                $script:Summary['GroupMembersRemoved'] += [int]$mres.Removed
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

