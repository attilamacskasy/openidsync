[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [string]$ConfigPath,
    [string]$OnlineSyncConfigPath,
    [string]$ClientSecretEnvVar,
    [switch]$SkipEnvVar,
    [switch]$SkipAppRemoval,
    [switch]$SkipModuleRemoval,
    [switch]$SkipConfigUpdate,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    try {
        $scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    } catch {
        $scriptRoot = (Get-Location).Path
    }
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path -Path $scriptRoot -ChildPath '00_OpenIDSync_Config.json'
}
if (-not $OnlineSyncConfigPath) {
    $OnlineSyncConfigPath = Join-Path -Path $scriptRoot -ChildPath '00_OpenIDSync_OnlineSyncConfig.json'
}

Set-StrictMode -Version Latest

function Write-ConsoleLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','ACTION','RESULT')][string]$Level = 'INFO'
    )
    $color = switch ($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'ACTION' { 'Magenta' }
        'RESULT' { 'Green' }
        default { 'White' }
    }
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

$logScript = Join-Path -Path $scriptRoot -ChildPath '50_OpenIDSync_Logging.ps1'
if (Test-Path -LiteralPath $logScript) {
    try { . $logScript } catch { Write-ConsoleLog -Level 'WARN' -Message ("Failed to import logging script: {0}" -f $_.Exception.Message) }
}
$script:Logger = $null
if (-not (Get-Command -Name Write-Log -ErrorAction SilentlyContinue)) {
    function Write-Log {
        param([string]$Message,[ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT')][string]$Level='INFO')
        Write-ConsoleLog -Message $Message -Level $Level
    }
}

$modulesRoot = Join-Path -Path $scriptRoot -ChildPath 'modules'
$configScript = Join-Path -Path $modulesRoot -ChildPath 'common/Config.ps1'
if (Test-Path -LiteralPath $configScript) {
    try { . $configScript } catch { Write-Log -Level 'WARN' -Message ("Failed to import Config helpers: {0}" -f $_.Exception.Message) }
} else {
    Write-Log -Level 'WARN' -Message "Config helper script not found. Online config updates may be limited."
}

$graphScript = Join-Path -Path $modulesRoot -ChildPath 'microsoft-graph/Graph.ps1'
if (Test-Path -LiteralPath $graphScript) {
    try { . $graphScript } catch { Write-Log -Level 'WARN' -Message ("Failed to import Graph helpers: {0}" -f $_.Exception.Message) }
} else {
    Write-Log -Level 'WARN' -Message "Graph helper script not found. App registration removal may be skipped."
}

if ($NonInteractive) { $script:NonInteractive = $true }

Write-Log -Level 'INFO' -Message '==== OpenIDSync Uninstall ===='

$onlineConfig = $null
if (Get-Command -Name Load-OpenIdSyncConfig -ErrorAction SilentlyContinue) {
    try {
        $loadedConfig = Load-OpenIdSyncConfig -ConfigPath $ConfigPath -OnlineSyncConfigPath $OnlineSyncConfigPath
        if ($loadedConfig -and $loadedConfig.Online -and $loadedConfig.Online.OnlineSyncConfig) {
            $onlineConfig = $loadedConfig.Online.OnlineSyncConfig
        } elseif ($loadedConfig -and $loadedConfig.Main -and $loadedConfig.Main.OnlineSyncConfig) {
            $onlineConfig = $loadedConfig.Main.OnlineSyncConfig
        }
    } catch {
        Write-Log -Level 'WARN' -Message ("Failed to load OpenIDSync configuration: {0}" -f $_.Exception.Message)
    }
}
if (-not $onlineConfig) {
    try {
        if (Test-Path -LiteralPath $OnlineSyncConfigPath) {
            $onlineConfig = (Get-Content -LiteralPath $OnlineSyncConfigPath -Raw | ConvertFrom-Json).OnlineSyncConfig
        }
    } catch {
        Write-Log -Level 'WARN' -Message ("Fallback config parse failed: {0}" -f $_.Exception.Message)
    }
}
if (-not $ClientSecretEnvVar) {
    try { $ClientSecretEnvVar = [string]$onlineConfig.ClientSecretEnvVar } catch {}
}
if ([string]::IsNullOrWhiteSpace($ClientSecretEnvVar)) { $ClientSecretEnvVar = 'OPENIDSYNC_CLIENT_SECRET' }

$tenantId = $null; $clientId = $null; $appName = $null; $spObjectId = $null
try { $tenantId = [string]$onlineConfig.TenantId } catch {}
try { $clientId = [string]$onlineConfig.ClientId } catch {}
try { $appName = [string]$onlineConfig.AppRegistrationName } catch {}
try { $spObjectId = [string]$onlineConfig.SpObjectId } catch {}

# Step 1: Clear environment variable
if ($SkipEnvVar) {
    Write-Log -Level 'INFO' -Message 'Skipping environment variable removal (SkipEnvVar switch supplied).'
} else {
    Write-Log -Level 'ACTION' -Message ("Step 1/4: Clearing environment variable '{0}'" -f $ClientSecretEnvVar)
    $scopes = @('Process','User','Machine')
    foreach ($scope in $scopes) {
        try {
            $currentValue = [Environment]::GetEnvironmentVariable($ClientSecretEnvVar, $scope)
            if ([string]::IsNullOrEmpty($currentValue)) {
                Write-Log -Level 'INFO' -Message ("No value present for '{0}' in {1} scope." -f $ClientSecretEnvVar, $scope)
                continue
            }
            if ($PSCmdlet.ShouldProcess(("{0} ({1} scope)" -f $ClientSecretEnvVar, $scope), 'Clear environment variable')) {
                [Environment]::SetEnvironmentVariable($ClientSecretEnvVar, $null, $scope)
                if ($scope -eq 'Process') {
                    try { Remove-Item -Path ("Env:{0}" -f $ClientSecretEnvVar) -ErrorAction SilentlyContinue } catch {}
                }
                Write-Log -Level 'RESULT' -Message ("Cleared '{0}' from {1} scope." -f $ClientSecretEnvVar, $scope)
            }
        } catch {
            Write-Log -Level 'WARN' -Message ("Failed clearing '{0}' from {1} scope: {2}" -f $ClientSecretEnvVar, $scope, $_.Exception.Message)
        }
    }
}

# Step 2: Remove app registration & service principal
$appRemovalPossible = (Get-Command -Name Import-GraphModules -ErrorAction SilentlyContinue) -and (Get-Command -Name Connect-GraphDelegated -ErrorAction SilentlyContinue)
if ($SkipAppRemoval) {
    Write-Log -Level 'INFO' -Message 'Skipping app registration removal (SkipAppRemoval switch supplied).'
} elseif (-not $appRemovalPossible) {
    Write-Log -Level 'WARN' -Message 'Graph helper functions unavailable; cannot attempt app registration removal.'
} elseif (-not ($clientId -or $appName)) {
    Write-Log -Level 'WARN' -Message 'Missing ClientId/AppRegistrationName; cannot determine which app registration to remove.'
} else {
    Write-Log -Level 'ACTION' -Message 'Step 2/4: Removing Azure app registration and service principal.'
    try {
        Import-GraphModules
        $scopes = @('Application.ReadWrite.All','Directory.ReadWrite.All')
        $connected = Connect-GraphDelegated -Scopes $scopes
        if (-not $connected) { throw "Failed to connect to Microsoft Graph. Manual cleanup required." }

        $removedSp = $false
        $spId = $spObjectId
        if (-not $spId -and $clientId) {
            try {
                $sp = Get-MgServicePrincipal -Filter ("appId eq '{0}'" -f $clientId) -ErrorAction Stop | Select-Object -First 1
                if ($sp) { $spId = $sp.Id }
            } catch {
                Write-Log -Level 'WARN' -Message ("Lookup of service principal by ClientId failed: {0}" -f $_.Exception.Message)
            }
        }
        if (-not $spId -and $appName) {
            try {
                $sp = Get-MgServicePrincipal -Filter ("displayName eq '{0}'" -f $appName.Replace("'","''")) -ErrorAction Stop | Select-Object -First 1
                if ($sp) { $spId = $sp.Id }
            } catch {
                Write-Log -Level 'WARN' -Message ("Lookup of service principal by display name failed: {0}" -f $_.Exception.Message)
            }
        }
        if ($spId) {
            if ($PSCmdlet.ShouldProcess(($spId), 'Remove service principal')) {
                try {
                    Remove-MgServicePrincipal -ServicePrincipalId $spId -ErrorAction Stop
                    Write-Log -Level 'RESULT' -Message ("Removed service principal: {0}" -f $spId)
                    $removedSp = $true
                } catch {
                    Write-Log -Level 'WARN' -Message ("Failed to remove service principal {0}: {1}" -f $spId, $_.Exception.Message)
                }
            }
        } else {
            Write-Log -Level 'INFO' -Message 'No matching service principal found; skipping SP removal.'
        }

        $appObjId = $null
        if ($clientId) {
            try {
                $app = Get-MgApplication -Filter ("appId eq '{0}'" -f $clientId) -ErrorAction Stop | Select-Object -First 1
                if ($app) { $appObjId = $app.Id; if (-not $appName) { $appName = $app.DisplayName } }
            } catch {
                Write-Log -Level 'WARN' -Message ("Lookup of application by ClientId failed: {0}" -f $_.Exception.Message)
            }
        }
        if (-not $appObjId -and $appName) {
            try {
                $app = Get-MgApplication -Filter ("displayName eq '{0}'" -f $appName.Replace("'","''")) -ErrorAction Stop | Select-Object -First 1
                if ($app) { $appObjId = $app.Id; $clientId = $app.AppId }
            } catch {
                Write-Log -Level 'WARN' -Message ("Lookup of application by name failed: {0}" -f $_.Exception.Message)
            }
        }
        if ($appObjId) {
            if ($PSCmdlet.ShouldProcess(($appObjId), 'Remove application')) {
                try {
                    Remove-MgApplication -ApplicationId $appObjId -ErrorAction Stop
                    Write-Log -Level 'RESULT' -Message ("Removed Azure AD application: {0}" -f $appObjId)
                } catch {
                    Write-Log -Level 'WARN' -Message ("Failed to remove application {0}: {1}" -f $appObjId, $_.Exception.Message)
                }
            }
        } else {
            Write-Log -Level 'INFO' -Message 'No matching application found; skipping application removal.'
        }
    } catch {
        Write-Log -Level 'ERROR' -Message ("App registration removal failed: {0}" -f $_.Exception.Message)
    }
}

# Step 3: Uninstall Microsoft Graph PowerShell modules
if ($SkipModuleRemoval) {
    Write-Log -Level 'INFO' -Message 'Skipping module uninstall (SkipModuleRemoval switch supplied).'
} else {
    Write-Log -Level 'ACTION' -Message 'Step 3/4: Uninstalling Microsoft Graph PowerShell modules.'
    $moduleNames = @()
    if (Get-Command -Name Get-GraphModuleRequirementStatus -ErrorAction SilentlyContinue) {
        try {
            $status = Get-GraphModuleRequirementStatus
            if ($status -and $status.Required) {
                $moduleNames = @($status.Required | Sort-Object -Unique)
            }
        } catch {
            Write-Log -Level 'WARN' -Message ("Failed to query Graph module list: {0}" -f $_.Exception.Message)
        }
    }
    if (-not $moduleNames -or $moduleNames.Count -eq 0) {
        $moduleNames = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Applications',
            'Microsoft.Graph.Identity.DirectoryManagement',
            'Microsoft.Graph.Groups'
        )
    }
    $moduleNames = $moduleNames | Sort-Object -Unique
    foreach ($name in $moduleNames) {
        try {
            $installed = Get-Module -ListAvailable -Name $name
            if (-not $installed) {
                Write-Log -Level 'INFO' -Message ("Module '{0}' not found; skipping." -f $name)
                continue
            }
            if ($PSCmdlet.ShouldProcess($name, 'Uninstall-Module')) {
                try {
                    $versions = $installed | Select-Object -ExpandProperty Version -Unique
                    foreach ($version in $versions) {
                        Uninstall-Module -Name $name -RequiredVersion $version -Force -ErrorAction Stop
                    }
                    Write-Log -Level 'RESULT' -Message ("Uninstalled module '{0}' ({1} version(s))." -f $name, $versions.Count)
                } catch {
                    Write-Log -Level 'WARN' -Message ("Failed uninstalling module '{0}': {1}" -f $name, $_.Exception.Message)
                }
            }
        } catch {
            Write-Log -Level 'WARN' -Message ("Error checking module '{0}': {1}" -f $name, $_.Exception.Message)
        }
    }
}

# Step 4: Reset online config JSON
if ($SkipConfigUpdate) {
    Write-Log -Level 'INFO' -Message 'Skipping online config reset (SkipConfigUpdate switch supplied).'
} else {
    Write-Log -Level 'ACTION' -Message 'Step 4/4: Resetting online sync configuration values.'
    if (Get-Command -Name Save-OnlineSyncConfig -ErrorAction SilentlyContinue) {
        try {
            if ($PSCmdlet.ShouldProcess($OnlineSyncConfigPath, 'Reset OnlineSyncConfig values')) {
                Save-OnlineSyncConfig -OnlineConfigPath $OnlineSyncConfigPath -TenantId '' -ClientId '' -SpObjectId '' -ClientSecretEnvVar '' -AppRegistrationName ''
                Write-Log -Level 'RESULT' -Message ("Cleared OnlineSyncConfig values at {0}." -f $OnlineSyncConfigPath)
            }
        } catch {
            Write-Log -Level 'WARN' -Message ("Failed to reset online config via helper: {0}" -f $_.Exception.Message)
        }
    } else {
        try {
            if ($PSCmdlet.ShouldProcess($OnlineSyncConfigPath, 'Reset OnlineSyncConfig values (manual)')) {
                $empty = @{ OnlineSyncConfig = @{ AppRegistrationName=''; TenantId=''; ClientId=''; SpObjectId=''; ClientSecretEnvVar='' } } | ConvertTo-Json -Depth 4
                $empty | Out-File -FilePath $OnlineSyncConfigPath -Encoding UTF8 -Force
                Write-Log -Level 'RESULT' -Message ("Cleared OnlineSyncConfig values at {0} (manual)." -f $OnlineSyncConfigPath)
            }
        } catch {
            Write-Log -Level 'ERROR' -Message ("Failed to reset online config JSON: {0}" -f $_.Exception.Message)
        }
    }
}

Write-Log -Level 'INFO' -Message '==== Uninstall sequence complete ===='
