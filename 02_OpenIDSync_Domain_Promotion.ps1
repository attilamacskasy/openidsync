<#
.SYNOPSIS
    Promote a fresh Windows Server (2022/2025) to the first Domain Controller of a new forest using PowerShell DSC.

.DESCRIPTION
    Reads settings from a JSON file (OpenIDSync_Config.json) and applies a DSC configuration
    named 'DomainPromotionConfig' to deploy a new AD DS forest using Microsoft ActiveDirectoryDsc (ADDomain resource).

    This script mirrors the logic from the referenced 03_Promote_First_Domain_Controller.ps1 but uses DSC and consumes DomainPromotionConfig
    from the provided JSON. It will:
      - Ensure required modules are available (xPSDesiredStateConfiguration / PSDscResources, ActiveDirectoryDsc)
      - Optionally install AD-Domain-Services and DNS roles
      - Prompt for DSRM password (SecureString)
    - Compile and apply DSC configuration that uses ADDomain to create a new forest

.PARAMETER ConfigPath
    Path to JSON (default: ./OpenIDSync_Config.json next to this script)

.EXAMPLE
    .\02_OpenIDSync_Domain_Promotion.ps1 -ConfigPath .\OpenIDSync_Config.json

.NOTES
    Run as Administrator. Server will reboot when promotion completes.
#>
param(
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'OpenIDSync_Config.json'),
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$SetupCredential
)

# ---- Helper: Write-Log ----
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] $Message"
}

# ---- Validate input JSON ----
if (!(Test-Path -LiteralPath $ConfigPath)) {
    throw "Configuration file not found: $ConfigPath"
}

$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (-not $cfg.DomainPromotionConfig) {
    throw 'DomainPromotionConfig section is missing in the configuration file.'
}

# Extract parameters
$dp = $cfg.DomainPromotionConfig
$DomainName       = $dp.DomainName
$NetBIOSName      = $dp.NetBIOSName
$DNSDelegation    = [bool]$dp.DNSDelegation
$InstallDNS       = [bool]$dp.InstallDNS
$DatabasePath     = if ($dp.DatabasePath) { $dp.DatabasePath } else { 'C:\\Windows\\NTDS' }
$LogPath          = if ($dp.LogPath) { $dp.LogPath } else { 'C:\\Windows\\NTDS' }
$SYSVOLPath       = if ($dp.SYSVOLPath) { $dp.SYSVOLPath } else { 'C:\\Windows\\SYSVOL' }
$InstallServerRoles = [bool]$dp.InstallServerRoles

if (-not $DomainName -or -not $NetBIOSName) {
    throw 'DomainName and NetBIOSName are required in DomainPromotionConfig.'
}

# Prompt for credentials
Write-Host 'Please enter the Safe Mode Administrator Password (DSRM):'
$SafeModeSecure = Read-Host -AsSecureString 'Safe Mode Administrator Password'
if (-not $SafeModeSecure) { throw 'DSRM password is required.' }

$defaultAdminUser = 'Administrator'
if ($dp.AdministratorUsername) { $defaultAdminUser = [string]$dp.AdministratorUsername }
$defaultUser = "$env:COMPUTERNAME\$defaultAdminUser"
if (-not $PSBoundParameters.ContainsKey('SetupCredential') -or -not $SetupCredential) {
    Write-Host "Enter credential for forest creation (use local Administrator). Default: $defaultUser"
    $SetupCredential = Get-Credential -UserName $defaultUser -Message 'Credential used during forest creation'
    if (-not $SetupCredential) {
        Write-Host 'No credential entered via the secure prompt; falling back to console password entry.'
        $pwd = Read-Host -AsSecureString "Password for $defaultUser"
        if (-not $pwd) { throw 'Setup credential is required.' }
        $SetupCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($defaultUser, $pwd)
    }
}

# Convert SafeMode to PSCredential (username is ignored by the resource, password is used)
$SafeModeCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @('SafeMode', $SafeModeSecure)

# ---- Ensure required Windows Features (optional) ----
if ($InstallServerRoles) {
    Write-Log 'Checking and installing required server roles (AD-Domain-Services, DNS)...'
    $features = @('AD-Domain-Services')
    if ($InstallDNS) { $features += 'DNS' }
    foreach ($f in $features) {
        $feature = Get-WindowsFeature -Name $f
        if ($feature -and -not $feature.Installed) {
            Write-Log "Installing Windows Feature: $f"
            Install-WindowsFeature -Name $f -IncludeManagementTools -ErrorAction Stop | Out-Null
        } else {
            Write-Log "Feature already installed: $f"
        }
    }
}

# ---- Ensure DSC modules are present ----
$requiredModules = @(
    @{ Name = 'ActiveDirectoryDsc'; MinimumVersion = '6.2.0' }
)

foreach ($m in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed) {
        Write-Log "Installing PowerShell module: $($m.Name) (requires Internet access to PSGallery)"
        try {
            Install-Module -Name $m.Name -MinimumVersion $m.MinimumVersion -Force -Scope AllUsers -ErrorAction Stop
        } catch {
            throw "Failed to install module $($m.Name): $($_.Exception.Message)"
        }
    } else {
        Write-Log "Found module $($m.Name) v$($installed.Version)"
    }
}

Import-Module ActiveDirectoryDsc -ErrorAction Stop

# ---- DSC Configuration ----
Configuration DomainPromotionConfig {
    param(
        [Parameter(Mandatory)] [string]$NodeName,
        [Parameter(Mandatory)] [string]$DomainName,
        [Parameter(Mandatory)] [string]$DomainNetbiosName,
        [Parameter(Mandatory)] [PSCredential]$SetupCredential,
        [Parameter(Mandatory)] [PSCredential]$SafeModeAdministratorPassword,
        [bool]$InstallDNS = $true,
        [string]$DatabasePath = 'C:\\Windows\\NTDS',
        [string]$LogPath = 'C:\\Windows\\NTDS',
        [string]$SysvolPath = 'C:\\Windows\\SYSVOL'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc

    Node $NodeName {
        WindowsFeature 'ADDS' {
            Name   = 'AD-Domain-Services'
            Ensure = 'Present'
        }

        if ($InstallDNS) {
            WindowsFeature 'DNS' {
                Name   = 'DNS'
                Ensure = 'Present'
            }
        }

        # Create new forest and domain
        ADDomain 'NewForestDomain' {
            DomainName                    = $DomainName
            DomainNetBiosName             = $DomainNetbiosName
            Credential                    = $SetupCredential
            SafeModeAdministratorPassword = $SafeModeAdministratorPassword
            DatabasePath                  = $DatabasePath
            LogPath                       = $LogPath
            SysvolPath                    = $SysvolPath
            ForestMode                    = 'WinThreshold'
            DomainMode                    = 'WinThreshold'
            DependsOn                     = @('[WindowsFeature]ADDS')
        }
    }
}

# ---- Compile & Apply ----
$nodeName = $env:COMPUTERNAME
$staging = Join-Path -Path $PSScriptRoot -ChildPath 'DSC_Compiled'
if (-not (Test-Path -LiteralPath $staging)) { New-Item -Path $staging -ItemType Directory | Out-Null }

Write-Log 'Compiling DSC configuration...'
# WARNING: Allowing plaintext credentials in MOF for local compile/apply.
# Consider configuring an encryption certificate for production. The compiled MOF is stored under $staging.
Write-Log 'Security note: compiling with PSDscAllowPlainTextPassword = $true (delete compiled MOF after use).'
$configData = @{ AllNodes = @(@{ NodeName = $nodeName; PSDscAllowPlainTextPassword = $true }) }
DomainPromotionConfig -NodeName $nodeName -DomainName $DomainName -DomainNetbiosName $NetBIOSName -SetupCredential $SetupCredential -SafeModeAdministratorPassword $SafeModeCredential -InstallDNS:$InstallDNS -DatabasePath $DatabasePath -LogPath $LogPath -SysvolPath $SYSVOLPath -ConfigurationData $configData -OutputPath $staging

# Set LCM to reboot as needed and apply automatically
Write-Log 'Configuring Local Configuration Manager (LCM)...'
[DSCLocalConfigurationManager()]
configuration LCMConfig {
    Node $nodeName {
        Settings {
            RebootNodeIfNeeded   = $true
            ConfigurationMode    = 'ApplyOnly'
            ActionAfterReboot    = 'ContinueConfiguration'
            RefreshMode          = 'Push'
        }
    }
}

$LCMPath = Join-Path $staging 'LCM'
LCMConfig -OutputPath $LCMPath
Set-DscLocalConfigurationManager -Path $LCMPath -Verbose -ErrorAction Stop

Write-Log 'Starting DSC Apply...'
Start-DscConfiguration -Path $staging -Force -Verbose -Wait

Write-Log 'If not already rebooted by DSC, a reboot may be required to finish domain promotion.'
