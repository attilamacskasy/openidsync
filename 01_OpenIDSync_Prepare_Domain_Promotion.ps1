<#
.SYNOPSIS
    Pre-install all prerequisites on a fresh Windows Server 2025 so DomainPromotion DSC can run without issues.

.DESCRIPTION
    This script prepares a fresh server for running Domain Controller promotion using the DSC configuration in DomainPromotionConfig.ps1.
    It performs the following steps (values can come from 00_OpenIDSync_Config.json):
      - Verifies administrative privileges and sets execution policy (Process scope)
      - Ensures TLS 1.2 is enabled for PowerShell Gallery operations
      - Installs NuGet package provider and trusts the PowerShell Gallery
      - Installs required PowerShell modules: PSDscResources and ActiveDirectoryDsc
      - Installs Windows Features: AD-Domain-Services and (optionally) DNS, including management tools
      - Verifies module availability and feature installation

.PARAMETER InstallDNS
    When specified (default or from JSON), the script also installs the DNS Server role required when the DC will host DNS.

.PARAMETER MinActiveDirectoryDsc
    Minimum version for the ActiveDirectoryDsc module (default: 6.2.0)

.PARAMETER MinPSDscResources
    Minimum version for the PSDscResources module (default: 2.12.0.0)

.PARAMETER ConfigPath
    Optional path to 00_OpenIDSync_Config.json (default: next to this script). Reads PrepareConfig if present.

.EXAMPLE
    .\01_Prepare_Domain_Promotion.ps1

.EXAMPLE
    .\01_Prepare_Domain_Promotion.ps1 -InstallDNS:$false

.NOTES
    - Run as Administrator
    - Requires Internet access to install modules from the PowerShell Gallery unless already present
    - Safe to re-run; will skip already installed features/modules
#>
param(
    [bool]$InstallDNS = $true,
    [string]$MinActiveDirectoryDsc = '6.2.0',
    [string]$MinPSDscResources    = '2.12.0.0',
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '00_OpenIDSync_Config.json')
)

# Load optional JSON for defaults
$json = $null
if (Test-Path -LiteralPath $ConfigPath) {
    try { $json = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch {}
}

if ($json -and $json.PrepareConfig) {
    $prep = $json.PrepareConfig
    if (-not $PSBoundParameters.ContainsKey('InstallDNS') -and $null -ne $prep.InstallDNS) { $InstallDNS = [bool]$prep.InstallDNS }
    if (-not $PSBoundParameters.ContainsKey('MinActiveDirectoryDsc') -and $prep.MinActiveDirectoryDsc) { $MinActiveDirectoryDsc = [string]$prep.MinActiveDirectoryDsc }
    if (-not $PSBoundParameters.ContainsKey('MinPSDscResources') -and $prep.MinPSDscResources) { $MinPSDscResources = [string]$prep.MinPSDscResources }
}

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] $Message"
}

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw 'This script must be run in an elevated PowerShell session (Run as Administrator).'
}

# Set execution policy for this process only
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force -ErrorAction Stop
    Write-Log 'Execution policy set to RemoteSigned for this process.'
} catch {
    Write-Log "Warning: Failed to set execution policy: $($_.Exception.Message)"
}

# Ensure TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Log 'TLS 1.2 enabled for PowerShell operations.'
} catch {
    Write-Log "Warning: Failed to enforce TLS 1.2: $($_.Exception.Message)"
}

# Install NuGet provider
try {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Log 'Installing NuGet package provider...'
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    } else {
        Write-Log 'NuGet package provider already installed.'
    }
} catch {
    Write-Log "ERROR: Failed to install NuGet provider: $($_.Exception.Message)"
    throw
}

# Ensure PSGallery exists and is trusted
try {
    $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
    if (-not $repo) {
        Write-Log 'Registering default PowerShell Gallery repository...'
        Register-PSRepository -Default -ErrorAction Stop
    }
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
    Write-Log 'PowerShell Gallery is registered and trusted.'
} catch {
    Write-Log "Warning: Could not trust PowerShell Gallery automatically: $($_.Exception.Message)"
}

# Install required modules
$modules = @(
    @{ Name = 'PSDscResources';   MinimumVersion = $MinPSDscResources },
    @{ Name = 'ActiveDirectoryDsc'; MinimumVersion = $MinActiveDirectoryDsc }
)

foreach ($m in $modules) {
    try {
        $installed = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
        if ($installed -and ($installed.Version -ge [version]$m.MinimumVersion)) {
            Write-Log "Module present: $($m.Name) v$($installed.Version)"
        } else {
            Write-Log "Installing module: $($m.Name) (>= $($m.MinimumVersion))..."
            Install-Module -Name $m.Name -MinimumVersion $m.MinimumVersion -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            Write-Log "Installed module: $($m.Name)"
        }
        Import-Module $m.Name -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Failed to install/import module $($m.Name): $($_.Exception.Message)"
        throw
    }
}

# Install Windows Features needed for AD DS and DNS (optional)
$features = @('AD-Domain-Services')
if ($InstallDNS) { $features += 'DNS' }

foreach ($f in $features) {
    try {
        $feat = Get-WindowsFeature -Name $f
        if ($feat -and -not $feat.Installed) {
            Write-Log "Installing Windows Feature: $f (with management tools)..."
            Install-WindowsFeature -Name $f -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-Log "Installed Feature: $f"
        } else {
            Write-Log "Feature already installed: $f"
        }
    } catch {
        Write-Log ("ERROR: Failed to install feature {0}: {1}" -f $f, $_.Exception.Message)
        throw
    }
}

# Verify ADDomain resource is available with diagnostics and retries
function _List-ModuleFiles {
    param($ModuleName)
    try {
        $mod = Get-Module -ListAvailable -Name $ModuleName | Select-Object -First 1
        if ($mod) {
            Write-Log "Module path: $($mod.ModuleBase)"
            Get-ChildItem -Path $mod.ModuleBase -Recurse -ErrorAction SilentlyContinue | Select-Object FullName | ForEach-Object { Write-Log "  $_" }
        } else {
            Write-Log "Module $ModuleName not present in Get-Module -ListAvailable"
        }
    } catch {
        Write-Log ("Failed to list files for module {0}: {1}" -f $ModuleName, $_.Exception.Message)
    }
}

try {
    Write-Log 'Verifying ADDomain DSC resource availability...'
    $res = Get-DscResource -Name ADDomain -Module ActiveDirectoryDsc -ErrorAction SilentlyContinue
    if ($res) {
        Write-Log 'DSC resource ADDomain is available.'
    } else {
    Write-Log 'ADDomain resource not found. Attempting to import ActiveDirectoryDsc module and retry.'
        try {
            Import-Module ActiveDirectoryDsc -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $res = Get-DscResource -Name ADDomain -Module ActiveDirectoryDsc -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Import-Module ActiveDirectoryDsc failed: $($_.Exception.Message)"
        }

        if ($res) {
            Write-Log 'DSC resource ADDomain became available after import.'
        } else {
            Write-Log 'ADDomain still not found. Will attempt to reinstall ActiveDirectoryDsc from PSGallery and retry.'
            _List-ModuleFiles -ModuleName 'ActiveDirectoryDsc'
            try {
                Install-Module -Name ActiveDirectoryDsc -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Import-Module ActiveDirectoryDsc -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                $res = Get-DscResource -Name ADDomain -Module ActiveDirectoryDsc -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Reinstall attempt failed: $($_.Exception.Message)"
            }
        }

        if ($res) {
            Write-Log 'DSC resource ADDomain is available after reinstall.'
        } else {
            Write-Log 'ERROR: ActiveDirectoryDsc resource ADDomain still not available after retries.'
            Write-Log 'Diagnostic commands you can run manually:'
            Write-Log '  Get-Module -ListAvailable ActiveDirectoryDsc'
            Write-Log '  Get-DscResource | Where-Object Name -like "*ADDomain*"'
            Write-Log '  Get-ChildItem (Get-Module -ListAvailable ActiveDirectoryDsc).ModuleBase -Recurse'
            Write-Log 'If these do not show ADDomain resources, verify the module version and that you are running Windows PowerShell (not PowerShell Core).'
            throw 'ADDomain DSC resource not available; see logs for diagnostics.'
        }
    }
} catch {
    Write-Log "ERROR: ActiveDirectoryDsc resource ADDomain not available: $($_.Exception.Message)"
    throw
}

Write-Log 'Prerequisite installation completed successfully. You can now run .\02_Domain_Promotion.ps1.'
