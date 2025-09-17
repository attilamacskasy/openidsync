<#
Purpose: Reset Azure/Entra/Graph login state for this machine/user so the next run prompts for credentials again.

What it does (safe by default):
- Tries to disconnect Microsoft Graph (Disconnect-MgGraph) if the module is available.
- Tries to disconnect Azure PowerShell (Disconnect-AzAccount / Clear-AzContext) if the module is available.
- Deletes common local token/cache files used by MSAL/Azure PowerShell.

Optional aggressive mode (-Aggressive):
- Also clears Windows AAD Broker Plugin cache folder which may affect other apps relying on WAM SSO on this machine.

Notes:
- This script avoids touching Windows Credential Manager by default.
- Run in an elevated prompt if some files are locked or access is denied.
- After running, you can reconnect interactively (delegated) via Connect-MgGraph or sign in again with Az cmdlets.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [switch]$Aggressive,
    [switch]$NoGraph,
    [switch]$NoAz,
    [switch]$ReconnectGraph,
    [string[]]$GraphScopes = @('User.Read.All','Directory.Read.All')
)

function Write-Info($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-ErrorLine($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Try-Import([string]$ModuleName) {
    try {
        if (Get-Module -ListAvailable -Name $ModuleName) {
            Import-Module $ModuleName -ErrorAction Stop
            return $true
        }
    } catch {}
    return $false
}

Write-Host ""; Write-Host "==== Reset Azure/Graph Login Session ====" -ForegroundColor Magenta

# 1) Disconnect sessions
if (-not $NoGraph) {
    $mgOk = Try-Import -ModuleName 'Microsoft.Graph.Authentication'
    if ($mgOk) {
        try {
            if ($PSCmdlet.ShouldProcess('Microsoft Graph', 'Disconnect-MgGraph')) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
            Write-Info 'Disconnected Microsoft Graph (if connected).'
        } catch { Write-Warn "Disconnect-MgGraph failed: $($_.Exception.Message)" }
    } else {
        Write-Warn 'Microsoft.Graph.Authentication module not found; skipping Disconnect-MgGraph.'
    }
}

if (-not $NoAz) {
    $azOk = Try-Import -ModuleName 'Az.Accounts'
    if ($azOk) {
        try {
            if ($PSCmdlet.ShouldProcess('Azure PowerShell', 'Disconnect-AzAccount / Clear-AzContext')) {
                Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
                Clear-AzContext -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Info 'Cleared Azure PowerShell context (if present).'
        } catch { Write-Warn "Clearing Az context failed: $($_.Exception.Message)" }
    } else {
        Write-Warn 'Az.Accounts module not found; skipping Az context clear.'
    }
}

# 2) Delete common token/cache files
$paths = @()
# MSAL caches commonly used by dev tools
$paths += Join-Path -Path $env:LOCALAPPDATA -ChildPath '.IdentityService\msalcache.bin3'
$paths += Join-Path -Path $env:LOCALAPPDATA -ChildPath '.IdentityService\msalcache.bin'
$paths += Join-Path -Path $env:LOCALAPPDATA -ChildPath '.IdentityService\aadcache.bin3'

# Azure PowerShell legacy caches
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.Azure\TokenCache.dat'
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.Azure\AzureRmContext.json'
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.Azure\AzureRmContext.default.json'
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.Azure\azureProfile.json'
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.Azure\msal_token_cache.bin'

# (Speculative) Graph SDK cache folders (harmless if not present)
$paths += Join-Path -Path $env:USERPROFILE -ChildPath '.graph'

if ($Aggressive) {
    # Windows AAD Broker Plugin cache (affects all apps using WAM on this machine)
    $paths += Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC'
}

$deleted = 0
foreach ($p in $paths) {
    try {
        if (Test-Path -LiteralPath $p) {
            $isDir = (Get-Item -LiteralPath $p).PSIsContainer
            $target = $p
            if ($PSCmdlet.ShouldProcess($target, ('Remove ' + ($(if($isDir){'Directory'}else{'File'}))))) {
                Remove-Item -LiteralPath $p -Force -Recurse -ErrorAction Stop
                $deleted++
                Write-Info ("Removed {0}: {1}" -f ($(if($isDir){'directory'}else{'file'}), $p))
            }
        }
    } catch {
        Write-Warn ("Failed to remove: {0} -> {1}" -f $p, $_.Exception.Message)
    }
}

Write-Host ""; Write-Host ("Removed items: {0}" -f $deleted) -ForegroundColor Magenta

# 3) Optional reconnect (delegated login)
if ($ReconnectGraph -and -not $NoGraph) {
    if (Try-Import -ModuleName 'Microsoft.Graph.Authentication') {
        try {
            Write-Info 'Starting interactive Microsoft Graph login...'
            Connect-MgGraph -Scopes $GraphScopes -NoWelcome -ErrorAction Stop | Out-Null
            $ctx = $null; try { $ctx = Get-MgContext } catch {}
            if ($ctx) {
                Write-Info ("Connected as: {0}" -f $ctx.Account)
            } else {
                Write-Info 'Connected to Microsoft Graph.'
            }
        } catch {
            Write-ErrorLine "Connect-MgGraph failed: $($_.Exception.Message)"
        }
    } else {
        Write-Warn 'Microsoft.Graph.Authentication module not available for reconnect.'
    }
}

Write-Host ""; Write-Host "Done. Next run of your scripts should prompt for credentials again (if using delegated auth)." -ForegroundColor Magenta
