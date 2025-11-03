# Dashboard helpers and interactive UI for OpenIDSync

if (-not (Get-Variable -Name DashboardPermissionStatus -Scope Script -ErrorAction SilentlyContinue)) {
    $script:DashboardPermissionStatus = $null
}
if (-not (Get-Variable -Name DashboardOnlineVerification -Scope Script -ErrorAction SilentlyContinue)) {
    $script:DashboardOnlineVerification = $null
}

function Get-JsonFileOrNull {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Protect-SecretValue {
    param(
        [string]$Value,
        [int]$VisibleCharacters = 3
    )
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $len = $Value.Length
    if ($len -le 1) { return ("{0}***{0}" -f $Value) }
    if ($len -le ($VisibleCharacters * 2)) {
        $half = [int][Math]::Ceiling($len / 2)
        $prefix = $Value.Substring(0, $half)
        $suffixLength = $len - $half
        if ($suffixLength -le 0) { $suffixLength = 1 }
        $suffix = $Value.Substring($len - $suffixLength)
    } else {
        $prefix = $Value.Substring(0, $VisibleCharacters)
        $suffix = $Value.Substring($len - $VisibleCharacters)
    }
    if ([string]::IsNullOrEmpty($suffix)) { $suffix = $Value.Substring($len - 1) }
    return "$prefix***$suffix"
}

function Protect-PasswordValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value -match '\*\*\*') { return $Value }
    return Protect-SecretValue -Value $Value -VisibleCharacters 1
}

function Get-SecretEnvironmentInfo {
    param([string]$PreferredName)
    $name = if ([string]::IsNullOrWhiteSpace($PreferredName)) { 'OPENIDSYNC_CLIENT_SECRET' } else { $PreferredName }
    $value = $null
    foreach ($scope in @('Process','User','Machine')) {
        $candidate = $null
        try { $candidate = [Environment]::GetEnvironmentVariable($name, $scope) } catch { $candidate = $null }
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { $value = $candidate; break }
    }
    $isSet = -not [string]::IsNullOrWhiteSpace($value)
    return [pscustomobject]@{
        Name     = $name
        IsSet    = $isSet
        Masked   = if ($isSet) { Protect-SecretValue -Value $value -VisibleCharacters 3 } else { $null }
        RawValue = $value
    }
}

function Get-PasswordCredentialStatus {
    param([string]$Path)
    $result = [ordered]@{
        Path            = $Path
        Exists          = $false
        Count           = 0
        LastWriteTime   = $null
        PasswordsMasked = $false
        Error           = $null
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]$result }
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]$result }
    $result.Exists = $true
    try {
        $items = Import-Csv -LiteralPath $Path
        $result.Count = $items.Count
        $allMasked = $true
        foreach ($item in $items) {
            if ($item.PSObject.Properties['GeneratedPassword']) {
                $pwd = [string]$item.GeneratedPassword
                if (-not ($pwd -match '^.{1}\*{3}.{1}$')) { $allMasked = $false; break }
            } else {
                $allMasked = $false; break
            }
        }
        $result.PasswordsMasked = $allMasked
        $result.LastWriteTime = (Get-Item -LiteralPath $Path).LastWriteTime
    } catch {
        $result.Error = $_.Exception.Message
    }
    return [pscustomobject]$result
}

function Resolve-PasswordCredentialPath {
    param(
        [string]$ProvidedPath,
        [string]$ConfigPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ProvidedPath)) { return $ProvidedPath }

    $baseDir = $null
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        try { $baseDir = Split-Path -Path $ConfigPath -Parent } catch { $baseDir = $null }
    }
    if (-not $baseDir) {
        try { $baseDir = (Get-Location).ProviderPath } catch { $baseDir = $null }
    }
    if (-not $baseDir -and $PSScriptRoot) { $baseDir = $PSScriptRoot }
    if (-not $baseDir) { return $ProvidedPath }

    $logDir = Join-Path -Path $baseDir -ChildPath 'log'
    return Join-Path -Path $logDir -ChildPath 'openidsync-credentials.csv'
}

function Get-OnlineRegistrationStatus {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$SpObjectId,
        [psobject]$SecretInfo
    )

    $result = [ordered]@{
        Attempted      = $false
        Connected      = $false
        UsingMode      = $null
        AppChecked     = $false
        AppFound       = $false
        AppDisplayName = $null
        SpChecked      = $false
        SpFound        = $false
        SpDisplayName  = $null
        Message        = $null
        Warning        = $null
        Error          = $null
    }

    if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
        $result.Message = 'TenantId and ClientId required for online verification.'
        return [pscustomobject]$result
    }

    if (-not (Get-Command -Name Import-GraphModules -ErrorAction SilentlyContinue)) {
        $result.Error = 'Graph helpers unavailable. Install Microsoft Graph PowerShell modules (Requirement 1).' 
        return [pscustomobject]$result
    }

    try { Import-GraphModules } catch {
        $result.Error = "Unable to import Microsoft Graph modules: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $result.Attempted = $true

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    $connected = $false

    if ($ctx -and $ctx.TenantId) {
        $connected = $true
        $result.UsingMode = 'ExistingContext'
    }

    if (-not $connected -and $SecretInfo -and $SecretInfo.IsSet -and $SecretInfo.RawValue) {
        try {
            $connected = Connect-GraphAppOnly -TenantId $TenantId -ClientId $ClientId -ClientSecret $SecretInfo.RawValue
            if ($connected) { $result.UsingMode = 'AppOnly' }
        } catch {
            $result.Warning = "App-only verification failed: $($_.Exception.Message)"
        }
    }

    if (-not $connected) {
        if (-not $result.Warning) {
            $result.Warning = 'Connect to Microsoft Graph interactively or set the client secret environment variable to enable verification.'
        }
        return [pscustomobject]$result
    }

    $result.Connected = $true

    try {
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop | Select-Object -First 1
        $result.AppChecked = $true
        if ($app) {
            $result.AppFound = $true
            $result.AppDisplayName = $app.DisplayName
        }
    } catch {
        #$result.Warning = "Application lookup failed: $($_.Exception.Message)"
    }

    $result.SpChecked = $true
    if (-not [string]::IsNullOrWhiteSpace($SpObjectId)) {
        try {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $SpObjectId -ErrorAction Stop
            if ($sp) {
                $result.SpFound = $true
                $result.SpDisplayName = $sp.DisplayName
            }
        } catch {
            $result.SpFound = $false
        }
    } else {
        try {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sp) {
                $result.SpFound = $true
                $result.SpDisplayName = $sp.DisplayName
            }
        } catch {
            $result.SpFound = $false
        }
    }

    return [pscustomobject]$result
}

function Normalize-SyncModeValue {
    param([string]$Value,[string]$Default = 'All')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    switch ($Value.Trim().ToUpper()) {
        'A' { return 'All' }
        'ALL' { return 'All' }
        'P' { return 'Prompt' }
        'PROMPT' { return 'Prompt' }
        'S' { return 'Skip' }
        'SKIP' { return 'Skip' }
        default { return $Default }
    }
}

function New-DisplayLine {
    param(
        [string]$Text,
        [string]$ForegroundColor,
        [string]$BackgroundColor
    )
    [pscustomobject]@{
        Text            = $Text
        ForegroundColor = $ForegroundColor
        BackgroundColor = $BackgroundColor
    }
}

function Write-DisplayLine {
    param(
        [string]$Text,
        [string]$ForegroundColor,
        [string]$BackgroundColor,
        [string]$Prefix = ''
    )
    $outputText = "$Prefix$Text"
    $fg = if ([string]::IsNullOrWhiteSpace($ForegroundColor)) { $null } else { $ForegroundColor }
    $bg = if ([string]::IsNullOrWhiteSpace($BackgroundColor)) { $null } else { $BackgroundColor }
    if ($fg -and $bg) { Write-Host $outputText -ForegroundColor $fg -BackgroundColor $bg }
    elseif ($fg) { Write-Host $outputText -ForegroundColor $fg }
    elseif ($bg) { Write-Host $outputText -BackgroundColor $bg }
    else { Write-Host $outputText }
}

function Write-ValueSegmentsLine {
    param(
        [string]$Prefix,
        [array]$Segments,
        [string]$PrefixForeground,
        [string]$PrefixBackground,
        [string]$DefaultValueForeground = 'Black',
        [string]$DefaultValueBackground = 'White'
    )

    if ($Prefix) {
        if ($PrefixForeground -or $PrefixBackground) {
            Write-Host $Prefix -ForegroundColor $PrefixForeground -BackgroundColor $PrefixBackground -NoNewline
        } else {
            Write-Host $Prefix -NoNewline
        }
    }

    foreach ($segment in $Segments) {
        $prefixText = ''
        $valueText = ''
        $suffixText = ''
        if ($segment -is [hashtable]) {
            if ($segment.ContainsKey('Prefix') -and $segment.Prefix) { $prefixText = [string]$segment.Prefix }
            if ($segment.ContainsKey('Value') -and $null -ne $segment.Value) { $valueText = [string]$segment.Value }
            if ($segment.ContainsKey('Suffix') -and $segment.Suffix) { $suffixText = [string]$segment.Suffix }
        } elseif ($segment -is [pscustomobject]) {
            if ($segment.PSObject.Properties['Prefix'] -and $segment.Prefix) { $prefixText = [string]$segment.Prefix }
            if ($segment.PSObject.Properties['Value'] -and $null -ne $segment.Value) { $valueText = [string]$segment.Value }
            if ($segment.PSObject.Properties['Suffix'] -and $segment.Suffix) { $suffixText = [string]$segment.Suffix }
        } else {
            $valueText = [string]$segment
        }

        if (-not [string]::IsNullOrEmpty($prefixText)) {
            Write-Host $prefixText -NoNewline
        }

        $valueForeground = $DefaultValueForeground
        $valueBackground = $DefaultValueBackground
        if ($segment -is [hashtable]) {
            if ($segment.ContainsKey('ValueForeground') -and $segment.ValueForeground) { $valueForeground = $segment.ValueForeground }
            if ($segment.ContainsKey('ValueBackground') -and $segment.ValueBackground) { $valueBackground = $segment.ValueBackground }
        } elseif ($segment -is [pscustomobject]) {
            if ($segment.PSObject.Properties['ValueForeground'] -and $segment.ValueForeground) { $valueForeground = $segment.ValueForeground }
            if ($segment.PSObject.Properties['ValueBackground'] -and $segment.ValueBackground) { $valueBackground = $segment.ValueBackground }
        }

        if ($valueForeground -or $valueBackground) {
            Write-Host $valueText -ForegroundColor $valueForeground -BackgroundColor $valueBackground -NoNewline
        } else {
            Write-Host $valueText -NoNewline
        }

        if (-not [string]::IsNullOrEmpty($suffixText)) {
            Write-Host $suffixText -NoNewline
        }
    }

    Write-Host ''
}

function Write-DangerZoneBanner {
    param([string]$Message)

    Write-Host ''
    Write-Host '###############################################################' -ForegroundColor Red
    Write-Host '#                         DANGER ZONE                          #' -ForegroundColor Red
    Write-Host '###############################################################' -ForegroundColor Red
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        Write-Host $Message -ForegroundColor Red
        Write-Host '---------------------------------------------------------------' -ForegroundColor Red
    }
    Write-Host 'Proceed ONLY if you understand the consequences.' -ForegroundColor Red
    Write-Host 'This action may permanently remove data or configuration.' -ForegroundColor Red
    Write-Host 'Create backups and confirm scope before continuing.' -ForegroundColor Red
    Write-Host '###############################################################' -ForegroundColor Red
    Write-Host ''
}

function Get-DashboardBaseDirectory {
    param([string]$ConfigPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        try { return Split-Path -Path $ConfigPath -Parent } catch {}
    }
    if ($PSScriptRoot) { return $PSScriptRoot }
    try { return (Get-Location).ProviderPath } catch {}
    return (Get-Location).Path
}

function New-RequirementStatus {
    param(
        [int]$Id,
        [string]$Title,
        [bool]$IsMet,
        [array]$Lines
    )
    [pscustomobject]@{
        Id               = $Id
        Title            = $Title
        IsMet            = $IsMet
        TitleForeground  = if ($IsMet) { $null } else { 'White' }
        TitleBackground  = if ($IsMet) { $null } else { 'DarkRed' }
        Lines            = $Lines
    }
}

function Get-RequirementStatuses {
    param(
        [psobject]$BaseConfig,
        [psobject]$OnlineConfig,
        [psobject]$SecretInfo,
        [switch]$ForcePermissionRefresh,
        [switch]$ForceOnlineRefresh
    )

    if ($ForcePermissionRefresh) { $script:DashboardPermissionStatus = $null }
    if ($ForceOnlineRefresh) { $script:DashboardOnlineVerification = $null }

    # Requirement 1 - Graph modules
    $moduleStatus = $null
    if (Get-Command -Name Get-GraphModuleRequirementStatus -ErrorAction SilentlyContinue) {
        try { $moduleStatus = Get-GraphModuleRequirementStatus } catch { $moduleStatus = $null }
    }
    if (-not $moduleStatus) {
        $requiredList = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Applications',
            'Microsoft.Graph.Identity.DirectoryManagement',
            'Microsoft.Graph.Groups'
        )
        $installed = @()
        foreach ($m in $requiredList) {
            if (Get-Module -ListAvailable -Name $m) { $installed += $m }
        }
        $missing = $requiredList | Where-Object { $installed -notcontains $_ }
        $moduleStatus = [pscustomobject]@{
            Required     = $requiredList
            Installed    = $installed
            Missing      = $missing
            AllInstalled = ($missing.Count -eq 0)
        }
    }
    $req1Lines = @()
    if ($moduleStatus.AllInstalled) {
        $req1Lines += (New-DisplayLine -Text 'Installed modules:')
        foreach ($name in $moduleStatus.Required) {
            $req1Lines += (New-DisplayLine -Text ("- {0}" -f $name) -ForegroundColor 'Green')
        }
    } else {
        if ($moduleStatus.Installed.Count -gt 0) {
            $req1Lines += (New-DisplayLine -Text 'Installed modules:')
            foreach ($name in $moduleStatus.Installed) {
                $req1Lines += (New-DisplayLine -Text ("- {0}" -f $name) -ForegroundColor 'Yellow')
            }
        } else {
            $req1Lines += (New-DisplayLine -Text 'No modules installed yet.' -ForegroundColor 'White' -BackgroundColor 'DarkRed')
        }
        if ($moduleStatus.Missing.Count -gt 0) {
            $req1Lines += (New-DisplayLine -Text 'Missing modules:' -ForegroundColor 'White' -BackgroundColor 'DarkRed')
            foreach ($name in $moduleStatus.Missing) {
                $req1Lines += (New-DisplayLine -Text ("- {0}" -f $name) -ForegroundColor 'White' -BackgroundColor 'DarkRed')
            }
        }
    }
    $req1 = New-RequirementStatus -Id 1 -Title 'Requirement 1 - Installed PowerShell Graph API modules' -IsMet $moduleStatus.AllInstalled -Lines $req1Lines

    # Requirement 2 - App registration
    $online = $null
    if ($OnlineConfig -and $OnlineConfig.PSObject.Properties['OnlineSyncConfig']) {
        $online = $OnlineConfig.OnlineSyncConfig
    } elseif ($OnlineConfig) {
        $online = $OnlineConfig
    }
    $appName = if ($online -and $online.AppRegistrationName) { [string]$online.AppRegistrationName } else { 'None' }
    $tenantId = if ($online -and $online.TenantId) { [string]$online.TenantId } else { '' }
    $clientId = if ($online -and $online.ClientId) { [string]$online.ClientId } else { '' }
    $spObjectId = if ($online -and $online.SpObjectId) { [string]$online.SpObjectId } else { '' }
    $tenantDisplay = if ([string]::IsNullOrWhiteSpace($tenantId)) { 'None' } else { $tenantId }
    $clientDisplay = if ([string]::IsNullOrWhiteSpace($clientId)) { 'None' } else { $clientId }
    $spDisplay = if ([string]::IsNullOrWhiteSpace($spObjectId)) { 'None' } else { $spObjectId }
    $hasAppRegistration = (-not [string]::IsNullOrWhiteSpace($tenantId)) -and (-not [string]::IsNullOrWhiteSpace($clientId)) -and (-not [string]::IsNullOrWhiteSpace($spObjectId))
    $req2Met = $hasAppRegistration -and $SecretInfo.IsSet
    $onlineVerification = $null
    if ($script:DashboardOnlineVerification -and -not $ForceOnlineRefresh) {
        $onlineVerification = $script:DashboardOnlineVerification
    }
    $req2Lines = @()
    $req2Lines += New-DisplayLine -Text ("App registration name: {0}" -f $appName)
    $req2Lines += New-DisplayLine -Text ("TenantId: {0}" -f $tenantDisplay)
    $req2Lines += New-DisplayLine -Text ("ClientId: {0}" -f $clientDisplay)
    $req2Lines += New-DisplayLine -Text ("SpObjectId: {0}" -f $spDisplay)
    if ($SecretInfo.IsSet) {
        $req2Lines += New-DisplayLine -Text ("{0} set to {1}" -f $SecretInfo.Name, $SecretInfo.Masked) -ForegroundColor 'White' -BackgroundColor 'DarkGreen'
    } else {
        $req2Lines += New-DisplayLine -Text ("ClientSecretEnvVar: {0} not set." -f $SecretInfo.Name) -ForegroundColor 'White' -BackgroundColor 'DarkRed'
    }
    if (-not $hasAppRegistration) {
        $req2Lines += New-DisplayLine -Text 'No app registration / service principal configured yet in Entra ID. Using delegated user mode (prompt for user login to bootstrap).' -ForegroundColor 'White' -BackgroundColor 'DarkRed'
    }
    try {
        if (-not $onlineVerification) {
            $onlineVerification = Get-OnlineRegistrationStatus -TenantId $tenantId -ClientId $clientId -SpObjectId $spObjectId -SecretInfo $SecretInfo
            $script:DashboardOnlineVerification = $onlineVerification
        }
    } catch {
        $onlineVerification = [pscustomobject]@{ Error = $_.Exception.Message }
        $script:DashboardOnlineVerification = $onlineVerification
    }

    if ($onlineVerification) {
        if ($onlineVerification.Error) {
            $req2Lines += New-DisplayLine -Text ("Online verification: {0}" -f $onlineVerification.Error) -ForegroundColor 'Yellow'
        } elseif (-not $onlineVerification.Attempted) {
            if ($onlineVerification.Message) {
                $req2Lines += New-DisplayLine -Text $onlineVerification.Message -ForegroundColor 'Yellow'
            }
        } else {
            if ($onlineVerification.AppChecked) {
                if ($onlineVerification.AppFound) {
                    $req2Lines += New-DisplayLine -Text ("Verified application: {0}" -f $onlineVerification.AppDisplayName) -ForegroundColor 'Green'
                } else {
                    $req2Lines += New-DisplayLine -Text 'Verified application: NOT FOUND in Entra ID.' -ForegroundColor 'White' -BackgroundColor 'DarkRed'
                }
            }
            if ($onlineVerification.SpChecked) {
                if ($onlineVerification.SpFound) {
                    $req2Lines += New-DisplayLine -Text ("Verified service principal: {0}" -f $onlineVerification.SpDisplayName) -ForegroundColor 'Green'
                } else {
                    $req2Lines += New-DisplayLine -Text 'Verified service principal: NOT FOUND in tenant.' -ForegroundColor 'White' -BackgroundColor 'DarkRed'
                }
            }
            if ($onlineVerification.Warning) {
                $req2Lines += New-DisplayLine -Text $onlineVerification.Warning -ForegroundColor 'Yellow'
            }
        }
    }
    $req2 = New-RequirementStatus -Id 2 -Title 'Requirement 2 - Create app registration for credential-less use' -IsMet $req2Met -Lines $req2Lines

    # Requirement 3 - Permissions
    $req3Lines = @()
    $permissionDetail = $null
    $req3Met = $false
    if ($hasAppRegistration) {
        $shouldCheck = $true
        if (-not $SecretInfo.IsSet) {
            $req3Lines += New-DisplayLine -Text ("Set environment variable {0} to verify permissions via app-only authentication." -f $SecretInfo.Name) -ForegroundColor 'White' -BackgroundColor 'DarkRed'
            $shouldCheck = $false
        }
        if ($shouldCheck) {
            if ($ForcePermissionRefresh -or -not $script:DashboardPermissionStatus) {
                try {
                    $permissionDetail = Test-GraphReadOperations -TenantId $tenantId -ClientId $clientId -ClientSecret $SecretInfo.RawValue
                } catch {
                    $permissionDetail = [pscustomobject]@{ Success = $false; Error = $_.Exception.Message; Tests = @() }
                }
                $script:DashboardPermissionStatus = $permissionDetail
            } else {
                $permissionDetail = $script:DashboardPermissionStatus
            }

            if ($permissionDetail) {
                if ($permissionDetail.Error) {
                    $req3Lines += New-DisplayLine -Text ("Unable to verify permissions: {0}" -f $permissionDetail.Error) -ForegroundColor 'White' -BackgroundColor 'DarkRed'
                }
                if ($permissionDetail.Tests -and $permissionDetail.Tests.Count -gt 0) {
                    foreach ($test in $permissionDetail.Tests) {
                        $label = switch ($test.Name) {
                            'Users' { 'User directory read' }
                            'Groups' { 'Group directory read' }
                            'GroupMembers' { 'Group membership read' }
                            default { $test.Name }
                        }
                        $message = if ($test.Message) { $test.Message } else { "Completed check: $label" }
                        if ($test.Success -and -not $test.Skipped) {
                            $req3Lines += New-DisplayLine -Text ("{0}: {1}" -f $label, $message) -ForegroundColor 'Green'
                        } elseif ($test.Skipped) {
                            $req3Lines += New-DisplayLine -Text ("{0}: {1}" -f $label, $message) -ForegroundColor 'Yellow'
                        } else {
                            $errorText = if ($test.Error) { $test.Error } else { 'Unexpected failure.' }
                            $req3Lines += New-DisplayLine -Text ("{0}: {1}" -f $label, $errorText) -ForegroundColor 'White' -BackgroundColor 'DarkRed'
                        }
                    }
                    $req3Met = ($permissionDetail.Tests | Where-Object { -not $_.Success -and -not $_.Skipped }).Count -eq 0 -and -not $permissionDetail.Error
                } elseif (-not $permissionDetail.Error) {
                    $req3Lines += New-DisplayLine -Text 'Permission verification did not return any test results.' -ForegroundColor 'Yellow'
                }
            } else {
                $req3Lines += New-DisplayLine -Text 'Permission status not checked yet. Select option 3 to verify.'
            }
        }
    } else {
        $req3Lines += New-DisplayLine -Text 'App registration is required before permission checks can succeed.' -ForegroundColor 'White' -BackgroundColor 'DarkRed'
    }
    if ($req3Lines.Count -eq 0) {
        $req3Lines += New-DisplayLine -Text 'Permission status not checked yet. Select option 3 to verify.'
    }
    $req3 = New-RequirementStatus -Id 3 -Title 'Requirement 3 - Required API permissions granted' -IsMet $req3Met -Lines $req3Lines

    $requirements = @($req1,$req2,$req3)
    $allMet = ($requirements | Where-Object { -not $_.IsMet }).Count -eq 0
    return [pscustomobject]@{
        Items            = $requirements
        AllMet           = $allMet
        PermissionDetail = $permissionDetail
    }
}

function Get-OpenIdSyncDashboardState {
    param(
        [string]$ConfigPath,
        [string]$OnlineConfigPath,
        [string]$CredentialFilePath,
        [switch]$ForcePermissionRefresh,
        [switch]$ForceOnlineRefresh
    )

    $baseConfig = Get-JsonFileOrNull -Path $ConfigPath
    $onlineConfig = Get-JsonFileOrNull -Path $OnlineConfigPath
    $preferredSecretName = $null
    if ($onlineConfig -and $onlineConfig.PSObject.Properties['OnlineSyncConfig'] -and $onlineConfig.OnlineSyncConfig -and $onlineConfig.OnlineSyncConfig.PSObject.Properties['ClientSecretEnvVar']) {
        $preferredSecretName = [string]$onlineConfig.OnlineSyncConfig.ClientSecretEnvVar
    }
    $secretInfo = Get-SecretEnvironmentInfo -PreferredName $preferredSecretName
    $resolvedCredentialPath = Resolve-PasswordCredentialPath -ProvidedPath $CredentialFilePath -ConfigPath $ConfigPath
    $passwordStatus = Get-PasswordCredentialStatus -Path $resolvedCredentialPath
    $reqStatus = Get-RequirementStatuses -BaseConfig $baseConfig -OnlineConfig $onlineConfig -SecretInfo $secretInfo -ForcePermissionRefresh:$ForcePermissionRefresh -ForceOnlineRefresh:$ForceOnlineRefresh

    $usc = $null
    if ($baseConfig -and $baseConfig.PSObject.Properties['UserSyncConfig']) { $usc = $baseConfig.UserSyncConfig }

    $preferredSource = if ($usc -and $usc.PreferredSource) { [string]$usc.PreferredSource } else { 'Online' }
    $usersMode = 'All'
    $groupsMode = 'All'
    $membershipsMode = 'All'
    if ($usc) {
        if ($usc.SyncModes) {
            if ($usc.SyncModes.Users) { $usersMode = Normalize-SyncModeValue -Value $usc.SyncModes.Users }
            if ($usc.SyncModes.Groups) { $groupsMode = Normalize-SyncModeValue -Value $usc.SyncModes.Groups }
            if ($usc.SyncModes.Memberships) { $membershipsMode = Normalize-SyncModeValue -Value $usc.SyncModes.Memberships }
        }
        if ($usc.UsersMode) { $usersMode = Normalize-SyncModeValue -Value $usc.UsersMode -Default $usersMode }
        if ($usc.GroupsMode) { $groupsMode = Normalize-SyncModeValue -Value $usc.GroupsMode -Default $groupsMode }
        if ($usc.MembershipsMode) { $membershipsMode = Normalize-SyncModeValue -Value $usc.MembershipsMode -Default $membershipsMode }
    }

    $sourceDisplay = switch ($preferredSource.ToUpper()) {
        'ONLINE' { 'Azure Entra ID (Microsoft)' }
        'CSV' { 'CSV File (Microsoft 365 Admin Portal Export)' }
        default { $preferredSource }
    }

    $targetSelection = if ($script:Target) { $script:Target } else { 'WindowsAD' }
    $targetDisplay = switch (($targetSelection + '').ToUpper()) {
        'WINDOWSAD' { 'Windows Active Directory (Microsoft)' }
        default { $targetSelection }
    }

    return [pscustomobject]@{
        BaseConfig           = $baseConfig
        OnlineConfig         = $onlineConfig
        SecretInfo           = $secretInfo
        PasswordStatus       = $passwordStatus
        Requirements         = $reqStatus.Items
        AllRequirementsMet   = $reqStatus.AllMet
        PermissionDetail     = $reqStatus.PermissionDetail
        OnlineVerification   = $script:DashboardOnlineVerification
        PreferredSource      = $preferredSource
        PreferredSourceDisplay = $sourceDisplay
        UsersMode            = $usersMode
        GroupsMode           = $groupsMode
        MembershipsMode      = $membershipsMode
        Target               = $targetSelection
        TargetDisplay        = $targetDisplay
        ConfigPath           = $ConfigPath
        OnlineConfigPath     = $OnlineConfigPath
        CredentialFilePath   = $resolvedCredentialPath
    }
}

function Write-RequirementBlock {
    param($Requirement)
    Write-DisplayLine -Text $Requirement.Title -ForegroundColor $Requirement.TitleForeground -BackgroundColor $Requirement.TitleBackground
    foreach ($line in $Requirement.Lines) {
        Write-DisplayLine -Text $line.Text -ForegroundColor $line.ForegroundColor -BackgroundColor $line.BackgroundColor -Prefix "`t"
    }
}

function Show-ConfigurationDetails {
    param(
        [hashtable]$Details
    )

    if (-not $Details) {
        Write-Host ''
        Write-Host 'Configuration details are not available.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    Write-Host ''
    Write-Host '=== Configuration Details ===' -ForegroundColor Cyan
    Write-Host ''

    $sections = @('Base','Online','Secret','Password','Logging')
    foreach ($section in $sections) {
        if ($Details.ContainsKey($section) -and $Details[$section]) {
            foreach ($line in $Details[$section]) {
                if ($line -and $line.PSObject.Properties['Text']) {
                    Write-DisplayLine -Text $line.Text -ForegroundColor $line.ForegroundColor -BackgroundColor $line.BackgroundColor
                } elseif ($line) {
                    Write-Host $line
                }
            }
            Write-Host ''
        }
    }

    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Show-RequirementDetails {
    param(
        [psobject[]]$Requirements
    )

    if (-not $Requirements -or $Requirements.Count -eq 0) {
        Write-Host ''
        Write-Host 'Requirement details are not available.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    Write-Host ''
    Write-Host '=== Requirement Details ===' -ForegroundColor Cyan
    Write-Host ''

    foreach ($req in $Requirements) {
        Write-RequirementBlock -Requirement $req
        Write-Host ''
    }

    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Write-OpenIdSyncDashboard {
    param(
        [psobject]$State,
        [string[]]$AvailableOptions
    )

    try { Clear-Host } catch {}

    Write-Host '============================================='
    Write-Host '=== Open Identity Synchronization Utility ==='
    Write-Host '===            OpenIDSync.org             ==='
    Write-Host '============================================='
    #Write-Host ''
    #Write-Host 'Creative spark and spec-driven development by: Attila Macskasy'
    #Write-Host 'Code generated using: GPT-5 Codex (Preview) - Premium Model x1'
    #Write-Host ''
    Write-Host ("Source Directory: {0}" -f $State.PreferredSourceDisplay)
    Write-Host ("Target Directory: {0}" -f $State.TargetDisplay)
    Write-Host ''

    $configFileLeaf = if ($State.ConfigPath) { Split-Path -Path $State.ConfigPath -Leaf } else { '00_OpenIDSync_Config.json' }
    $onlineFileLeaf = if ($State.OnlineConfigPath) { Split-Path -Path $State.OnlineConfigPath -Leaf } else { '00_OpenIDSync_OnlineSyncConfig.json' }

    $domainNameValue = 'None'
    $netbiosValue = 'None'
    $defaultOuValue = 'None'
    $displayNameSkips = '(none)'
    $upnSkips = '(none)'
    $baseDetailLines = @()
    $baseDetailLines += (New-DisplayLine -Text ("Base configuration loaded from file: [{0}]" -f $configFileLeaf) -ForegroundColor 'Black' -BackgroundColor 'White')

    if ($State.BaseConfig) {
        $domainConfig = $State.BaseConfig.DomainPromotionConfig
        if ($domainConfig) {
            if ($domainConfig.PSObject.Properties['DomainName'] -and $domainConfig.DomainName) { $domainNameValue = [string]$domainConfig.DomainName }
            if ($domainConfig.PSObject.Properties['NetBIOSName'] -and $domainConfig.NetBIOSName) { $netbiosValue = [string]$domainConfig.NetBIOSName }
            $baseDetailLines += (New-DisplayLine -Text "`tDomainPromotionConfig:")
            $baseDetailLines += (New-DisplayLine -Text ("`t`tDomainName:`t{0}" -f $domainNameValue))
            $baseDetailLines += (New-DisplayLine -Text ("`t`tNetBIOSName:`t{0}" -f $netbiosValue))
        } else {
            $baseDetailLines += (New-DisplayLine -Text "`t(DomainPromotionConfig section not found.)" -ForegroundColor 'Yellow')
        }

        $usc = $State.BaseConfig.UserSyncConfig
        if ($usc) {
            if ($usc.PSObject.Properties['DefaultOU'] -and $usc.DefaultOU) { $defaultOuValue = [string]$usc.DefaultOU }
            $baseDetailLines += (New-DisplayLine -Text "")
            $baseDetailLines += (New-DisplayLine -Text "`tUserSyncConfig:")
            $baseDetailLines += (New-DisplayLine -Text ("`t`tDefaultOU:`t{0}" -f $defaultOuValue))

            if ($usc.SkipUserBasedOnDisplayName -and $usc.SkipUserBasedOnDisplayName.Count -gt 0) {
                $filteredDisplaySkips = @($usc.SkipUserBasedOnDisplayName | Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 })
                if ($filteredDisplaySkips.Count -gt 0) { $displayNameSkips = $filteredDisplaySkips -join ', ' }
            }
            if ($usc.SkipUserBasedOnUserPrincipalName -and $usc.SkipUserBasedOnUserPrincipalName.Count -gt 0) {
                $filteredUpnSkips = @($usc.SkipUserBasedOnUserPrincipalName | Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 })
                if ($filteredUpnSkips.Count -gt 0) { $upnSkips = $filteredUpnSkips -join ', ' }
            }
            $securityExceptions = '(none)'
            if ($usc.PSObject.Properties['GroupSecurityExceptions']) {
                $filteredSecurity = @($usc.GroupSecurityExceptions | Where-Object { $_ -and ([string]$_).Trim().Length -gt 0 } | ForEach-Object { ([string]$_).Trim() })
                if ($filteredSecurity.Count -gt 0) { $securityExceptions = $filteredSecurity -join ', ' }
            }
            $baseDetailLines += (New-DisplayLine -Text ("`t`tSkipUserBasedOnDisplayName:`t{0}" -f $displayNameSkips))
            $baseDetailLines += (New-DisplayLine -Text ("`t`tSkipUserBasedOnUserPrincipalName:`t{0}" -f $upnSkips))
            $baseDetailLines += (New-DisplayLine -Text ("`t`tGroupSecurityExceptions:`t{0}" -f $securityExceptions))
        } else {
            $baseDetailLines += (New-DisplayLine -Text "`t(UserSyncConfig section not found.)" -ForegroundColor 'Yellow')
        }
    } else {
        $baseDetailLines += (New-DisplayLine -Text "`t(Base configuration file not found.)" -ForegroundColor 'Yellow')
    }

    $baseSummarySegments = @(
        @{ Prefix = 'Domain='; Value = $domainNameValue; Suffix = '; ' },
        @{ Prefix = 'DefaultOU='; Value = $defaultOuValue }
    )

    $online = $null
    if ($State.OnlineConfig -and $State.OnlineConfig.PSObject.Properties['OnlineSyncConfig']) { $online = $State.OnlineConfig.OnlineSyncConfig }
    $appNameValue = 'None'
    $tenantValue = 'None'
    $clientValue = 'None'
    $spValue = 'None'
    $onlineDetailLines = @()
    $onlineDetailLines += (New-DisplayLine -Text ("Online configuration loaded from file: [{0}]" -f $onlineFileLeaf) -ForegroundColor 'Black' -BackgroundColor 'White')
    if ($online) {
        if ($online.PSObject.Properties['AppRegistrationName'] -and $online.AppRegistrationName) { $appNameValue = [string]$online.AppRegistrationName }
        if ($online.PSObject.Properties['TenantId'] -and $online.TenantId) { $tenantValue = [string]$online.TenantId }
        if ($online.PSObject.Properties['ClientId'] -and $online.ClientId) { $clientValue = [string]$online.ClientId }
        if ($online.PSObject.Properties['SpObjectId'] -and $online.SpObjectId) { $spValue = [string]$online.SpObjectId }
        $onlineDetailLines += (New-DisplayLine -Text ("`tApp registration name: {0}" -f $appNameValue))
        $onlineDetailLines += (New-DisplayLine -Text ("`tTenantId: {0}" -f $tenantValue))
        $onlineDetailLines += (New-DisplayLine -Text ("`tClientId: {0}" -f $clientValue))
        $onlineDetailLines += (New-DisplayLine -Text ("`tSpObjectId: {0}" -f $spValue))
    } else {
        $onlineDetailLines += (New-DisplayLine -Text "`t(No online configuration found.)" -ForegroundColor 'Yellow')
    }

    $secretStateValue = if ($State.SecretInfo.IsSet) { 'Set' } else { 'Not set' }
    $onlineSummarySegments = @(
        @{ Prefix = 'ClientId='; Value = $clientValue; Suffix = '; ' },
        @{ Prefix = 'Tenant='; Value = $tenantValue; Suffix = '; ' },
        @{ Prefix = 'Secret='; Value = $secretStateValue }
    )

    $secretDetailLines = @()
    if ($State.SecretInfo.IsSet) {
        $secretDetailLines += (New-DisplayLine -Text ("`t{0} set to {1}" -f $State.SecretInfo.Name, $State.SecretInfo.Masked) -ForegroundColor 'White' -BackgroundColor 'DarkGreen')
    } else {
        $secretDetailLines += (New-DisplayLine -Text ("`tClientSecretEnvVar: {0} not set." -f $State.SecretInfo.Name) -ForegroundColor 'White' -BackgroundColor 'DarkRed')
    }

    $passwordPathDisplay = if ($State.PasswordStatus.Path) { $State.PasswordStatus.Path } else { '.\log\openidsync-credentials.csv' }
    $passwordStatusLabel = if ($State.PasswordStatus.Exists) { 'ready' } else { 'missing' }
    $passwordSummarySegments = @(
        @{ Value = $passwordPathDisplay; Suffix = ' ' },
        @{ Prefix = '('; Value = $passwordStatusLabel; Suffix = ')' }
    )

    $passwordDetailLines = @()
    $passwordDetailLines += (New-DisplayLine -Text ("Password credentials file: {0}" -f $passwordPathDisplay) -ForegroundColor 'Black' -BackgroundColor 'White')
    $passwordDetailLines += (New-DisplayLine -Text "`tWhen a new user is created in the destination directory, the password is not synchronized because the API does not provide the password hash.")
    $passwordDetailLines += (New-DisplayLine -Text "`tAs a workaround, OpenIDSync creates a new password for users and stores it in this file. Back up the file in a secure location and use the remove-password option in the menu.")
    if (-not $State.PasswordStatus.Exists) {
        $passwordDetailLines += (New-DisplayLine -Text "`tPassword credentials file not yet created." -ForegroundColor 'White' -BackgroundColor 'DarkRed')
    } else {
        $passwordDetailLines += (New-DisplayLine -Text ("`tNumber of users in file:`t{0}" -f $State.PasswordStatus.Count))
        if ($State.PasswordStatus.LastWriteTime) {
            $passwordDetailLines += (New-DisplayLine -Text ("`tLast update timestamp:`t{0}" -f $State.PasswordStatus.LastWriteTime))
        }
        $passwordsRemovedDisplay = if ($State.PasswordStatus.PasswordsMasked) { 'YES' } else { 'NO' }
        $passwordDetailLines += (New-DisplayLine -Text ("`tPasswords removed:`t{0}" -f $passwordsRemovedDisplay))
    }

    $loggingPath = if ($State.BaseConfig -and $State.BaseConfig.LoggingConfig -and $State.BaseConfig.LoggingConfig.FilePath) { $State.BaseConfig.LoggingConfig.FilePath } else { './openidsync.log' }
    $loggingSummarySegments = @(
        @{ Value = $loggingPath }
    )
    $loggingDetailLines = @()
    $loggingDetailLines += (New-DisplayLine -Text ("Logging configuration file: {0}" -f $loggingPath) -ForegroundColor 'Black' -BackgroundColor 'White')

    $configDetails = @{
        Base     = $baseDetailLines
        Online   = $onlineDetailLines
        Secret   = $secretDetailLines
        Password = $passwordDetailLines
        Logging  = $loggingDetailLines
    }

    if ($State.PSObject.Properties['ConfigurationDetails']) {
        $State.ConfigurationDetails = $configDetails
    } else {
        $State | Add-Member -NotePropertyName 'ConfigurationDetails' -NotePropertyValue $configDetails
    }

    Write-ValueSegmentsLine -Prefix ("Base config [{0}]: " -f $configFileLeaf) -Segments $baseSummarySegments
    Write-ValueSegmentsLine -Prefix ("Online config [{0}]: " -f $onlineFileLeaf) -Segments $onlineSummarySegments
    Write-ValueSegmentsLine -Prefix 'Password file: ' -Segments $passwordSummarySegments
    Write-ValueSegmentsLine -Prefix 'Logging file: ' -Segments $loggingSummarySegments
    Write-Host ''

    if (-not $State.AllRequirementsMet) {
        foreach ($req in $State.Requirements) {
            Write-RequirementBlock -Requirement $req
            Write-Host ''
        }
    }

    Write-Host 'Menu:'
    Write-Host ''
    if ($AvailableOptions -contains '1') {
        Write-Host '  1) Fix Requirement 1 - Install PowerShell Graph API Modules [-AutoInstallGraphModules]'
    }
    if ($AvailableOptions -contains '2') {
        Write-Host '  2) Fix Requirement 2 - Create App Registration / Service Principal for credential-less use [-AutoCreateGraphApp]'
    }
    if ($AvailableOptions -contains '3') {
        Write-Host '  3) Fix Requirement 3 - Check if API permissions are granted for Service Principal'
        #Write-Host '     This is not automated for security reasons. Grant permissions on Azure Portal manually, and understand least privileged access for OpenIDSync.'
    }
    if ($State.AllRequirementsMet) {
        Write-Host ("  4) Set user sync mode [S]KIP | [A]LL | [P]ROMPT (current: {0})" -f $State.UsersMode.ToUpper())
        Write-Host ("  5) Set group sync mode [S]KIP | [A]LL | [P]ROMPT (current: {0})" -f $State.GroupsMode.ToUpper())
        Write-Host ("  6) Set group membership sync mode [S]KIP | [A]LL | [P]ROMPT (current: {0})" -f $State.MembershipsMode.ToUpper())
        Write-Host ''
        Write-Host '  7) Change Source Directory'
        Write-Host '  [M] Azure | [A] AWS | [G] GCP | [O] OCI | [W] Windows AD | [K] Keycloak | [C] CSV'
        # Write-Host '     [M] Azure Entra ID (Microsoft)'
        # Write-Host '     [A] AWS IAM Identity Center (Amazon)'
        # Write-Host '     [G] GCP Cloud Identity (Google)'
        # Write-Host '     [O] OCI IAM (Oracle)'
        # Write-Host '     [W] Windows Active Directory (Microsoft)'
        # Write-Host '     [K] Keycloak (Open Source)'
        # Write-Host '     [C] CSV File (Microsoft 365 Admin Portal Export)'
        Write-Host '     Currently only "Azure Entra ID (Microsoft)" and "CSV File" are supported.'
        Write-Host ''
        Write-Host '  8) Change Target Directory'
        Write-Host '  [M] Azure | [A] AWS | [G] GCP | [O] OCI | [W] Windows AD | [K] Keycloak | [C] CSV'
        # Write-Host '     [M] Azure Entra ID (Microsoft)'
        # Write-Host '     [A] AWS IAM Identity Center (Amazon)'
        # Write-Host '     [G] GCP Cloud Identity (Google)'
        # Write-Host '     [O] OCI IAM (Oracle)'
        # Write-Host '     [W] Windows Active Directory (Microsoft)'
        # Write-Host '     [K] Keycloak (Open Source)'
        Write-Host '     Currently only "[W] Windows Active Directory (Microsoft)" is supported.'
        Write-Host ''
        Write-Host '  9) Start Synchronization'
        Write-Host ''
        Write-Host ' 10) Remove passwords from Password credentials file (after you backed up initial/temporary passwords in secure location)'
        Write-Host '     This file can be used to feed OpenGWTools and create point to site road warrior VPN for users stored in this file.'
        Write-Host ''
        Write-Host ' !!! DANGER ZONE !!!' -ForegroundColor Red
    Write-Host ' 80) Remove OpenIDSync-managed users from Windows Active Directory' -ForegroundColor Red
    Write-Host ' 81) Remove OpenIDSync-managed groups (and memberships) from Windows Active Directory' -ForegroundColor Red
    Write-Host ' 82) Uninstall OpenIDSync components (environment cleanup)' -ForegroundColor Red
        Write-Host ''
    }
    Write-Host ' 11) View configuration details'
    if ($State.AllRequirementsMet) {
        Write-Host ' 12) View requirement details (all passed)'
        Write-Host ' 13) Export User List for OpenGWTools VPN-Roadwarriors module'
        Write-Host '     Generates firstName,lastName,comment CSV based on Entra Office location devices.'
        Write-Host ''
    }
    Write-Host ' 99) Exit'
    Write-Host ''
}

function Set-UserSyncMode {
    param(
        [string]$ConfigPath,
        [string]$ModeName,
        [string]$Value
    )
    $cfg = Get-JsonFileOrNull -Path $ConfigPath
    if (-not $cfg) { $cfg = [pscustomobject]@{} }
    if (-not $cfg.PSObject.Properties['UserSyncConfig']) {
        $cfg | Add-Member -NotePropertyName 'UserSyncConfig' -NotePropertyValue ([pscustomobject]@{})
    }
    $usc = [pscustomobject]$cfg.UserSyncConfig
    $usc | Add-Member -NotePropertyName ("{0}Mode" -f $ModeName) -NotePropertyValue $Value -Force
    if (-not $usc.PSObject.Properties['SyncModes']) {
        $usc | Add-Member -NotePropertyName 'SyncModes' -NotePropertyValue ([pscustomobject]@{})
    }
    $syncModes = [pscustomobject]$usc.SyncModes
    $syncModes | Add-Member -NotePropertyName $ModeName -NotePropertyValue $Value -Force
    $usc.SyncModes = $syncModes
    $cfg.UserSyncConfig = $usc
    Save-OpenIdSyncConfig -ConfigPath $ConfigPath -ConfigObject $cfg
}

function Set-PreferredSource {
    param(
        [string]$ConfigPath,
        [string]$PreferredSource
    )
    $cfg = Get-JsonFileOrNull -Path $ConfigPath
    if (-not $cfg) { $cfg = [pscustomobject]@{} }
    if (-not $cfg.PSObject.Properties['UserSyncConfig']) {
        $cfg | Add-Member -NotePropertyName 'UserSyncConfig' -NotePropertyValue ([pscustomobject]@{})
    }
    $usc = [pscustomobject]$cfg.UserSyncConfig
    $usc | Add-Member -NotePropertyName 'PreferredSource' -NotePropertyValue $PreferredSource -Force
    $cfg.UserSyncConfig = $usc
    Save-OpenIdSyncConfig -ConfigPath $ConfigPath -ConfigObject $cfg
}

function Invoke-Requirement1Remediation {
    try {
        $script:AutoInstallGraphModules = $true
        if (Get-Command -Name Install-GraphModules -ErrorAction SilentlyContinue) {
            $ok = Install-GraphModules
            if ($ok) { Write-Host 'Microsoft Graph modules installed successfully.' -ForegroundColor Green }
            else { Write-Host 'Microsoft Graph module installation failed. Review log for details.' -ForegroundColor Red }
        } else {
            Write-Host 'Install-GraphModules command not available. Ensure microsoft-graph module is loaded.' -ForegroundColor Red
        }
    } catch {
        Write-Host ("Failed to install Microsoft Graph modules: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
    [void](Read-Host 'Press Enter to continue...')
}

function Invoke-Requirement2Bootstrap {
    param(
        [string]$ConfigPath,
        [string]$OnlineConfigPath,
        [psobject]$State
    )

    try { Import-GraphModules } catch {}
    try { Test-GraphCommands } catch {}

    $currentName = $null
    if ($State.OnlineConfig -and $State.OnlineConfig.PSObject.Properties['OnlineSyncConfig'] -and $State.OnlineConfig.OnlineSyncConfig -and $State.OnlineConfig.OnlineSyncConfig.AppRegistrationName) {
        $currentName = [string]$State.OnlineConfig.OnlineSyncConfig.AppRegistrationName
    }
    if ([string]::IsNullOrWhiteSpace($currentName)) { $currentName = 'OpenIDSync_org__Entra_Sync_Windows_AD' }
    try { Show-SecuritySummary -CreatingApp } catch {}
    $appInfo = $null
    try {
        $appInfo = New-OpenIdSyncGraphApp -DisplayName $currentName
    } catch {
        Write-Host ("Failed to create app registration: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to continue...')
        return
    }
    if (-not $appInfo) {
        Write-Host 'App registration creation returned no data.' -ForegroundColor Red
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $secretEnvName = $State.SecretInfo.Name
    Save-OnlineSyncConfig -OnlineConfigPath $OnlineConfigPath -TenantId $appInfo.TenantId -ClientId $appInfo.ClientId -SpObjectId $appInfo.SpObjectId -ClientSecretEnvVar $secretEnvName -AppRegistrationName $currentName

    Write-Host ''
    Write-Host '==== IMPORTANT: CLIENT SECRET (copy and store securely) ====' -ForegroundColor Yellow
    Write-Host $appInfo.ClientSecret -ForegroundColor Yellow
    Write-Host ('Set environment variable before running next time (example): setx {0} "YOUR_SECRET_HERE"' -f $secretEnvName) -ForegroundColor Yellow
    Write-Host 'Secret will NOT be stored in any file.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "Tip: run .\97_Set_OPENIDSYNC_CLIENT_SECRET.ps1 to set the secret interactively." -ForegroundColor Yellow

    $script:DashboardPermissionStatus = $null
    $script:DashboardOnlineVerification = $null
    [void](Read-Host 'Press Enter to continue...')
}

function Invoke-PasswordCredentialRedaction {
    param(
        [string]$CredentialFilePath,
        [psobject]$DashboardState
    )

    $configPath = $null
    if ($DashboardState -and $DashboardState.PSObject.Properties['ConfigPath']) { $configPath = [string]$DashboardState.ConfigPath }
    $resolvedPath = Resolve-PasswordCredentialPath -ProvidedPath $CredentialFilePath -ConfigPath $configPath

    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        Write-Host 'Password credentials path is not configured. Run a synchronization first to generate the credentials file.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $hadExplicitPath = -not [string]::IsNullOrWhiteSpace($CredentialFilePath)
    if ($hadExplicitPath -and -not [string]::Equals($CredentialFilePath, $resolvedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host ("Using resolved password file path: {0}" -f $resolvedPath) -ForegroundColor DarkGray
    } elseif (-not $hadExplicitPath) {
        Write-Host ("Default password file path: {0}" -f $resolvedPath) -ForegroundColor DarkGray
    }

    $credentialPath = $resolvedPath

    if (-not (Test-Path -LiteralPath $credentialPath)) {
        Write-Host ("Password credentials file not found: {0}" -f $credentialPath) -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $backupPath = "$credentialPath.bak"
    try { Copy-Item -LiteralPath $credentialPath -Destination $backupPath -Force }
    catch {
        Write-Host ("Failed to create backup: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to continue...')
        return
    }
    try {
        $rows = Import-Csv -LiteralPath $credentialPath
        if ($rows.Count -eq 0) {
            Write-Host 'Password credentials file contains no records. Backup created, nothing to redact.' -ForegroundColor Yellow
        } else {
            foreach ($row in $rows) {
                if ($row.PSObject.Properties['GeneratedPassword']) {
                    $row.GeneratedPassword = Protect-PasswordValue -Value $row.GeneratedPassword
                }
            }
            $rows | Export-Csv -LiteralPath $credentialPath -Encoding UTF8 -NoTypeInformation -Force
            Write-Host ("Passwords redacted in {0}. Backup saved to {1}." -f $credentialPath, $backupPath) -ForegroundColor Green
            try { Write-Log -Level 'ACTION' -Message "Passwords redacted in credentials file." } catch {}
        }
    } catch {
        Write-Host ("Failed to redact passwords: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
    [void](Read-Host 'Press Enter to continue...')
}

function Invoke-DangerZoneRemoveManagedUsers {
    param([psobject]$State)

    Write-DangerZoneBanner -Message 'Remove all OpenIDSync-managed users from Windows Active Directory.'

    $usc = $null
    $defaultSearchBase = $null
    if ($State -and $State.BaseConfig -and $State.BaseConfig.PSObject.Properties['UserSyncConfig']) {
        $usc = $State.BaseConfig.UserSyncConfig
        if ($usc -and $usc.PSObject.Properties['DefaultOU'] -and -not [string]::IsNullOrWhiteSpace($usc.DefaultOU)) {
            $defaultSearchBase = [string]$usc.DefaultOU
        }
    }

    $searchBase = $defaultSearchBase
    if (-not [string]::IsNullOrWhiteSpace($defaultSearchBase)) {
        Write-Host ("Default SearchBase from config: {0}" -f $defaultSearchBase) -ForegroundColor Yellow
        $override = Read-Host 'Press Enter to accept or type an alternate SearchBase DN'
        if (-not [string]::IsNullOrWhiteSpace($override)) { $searchBase = $override }
    }
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        $searchBase = Read-Host 'Enter SearchBase distinguishedName to scan (e.g. OU=Users,DC=example,DC=com)'
    }
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        Write-Host 'SearchBase is required. Operation cancelled.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $skipUpnValues = @()
    $skipSamValues = @()
    if ($usc) {
        $dangerZoneSkip = $null
        if ($usc.PSObject.Properties['DangerZoneSkip']) { $dangerZoneSkip = $usc.DangerZoneSkip }
        if ($dangerZoneSkip) {
            $userSkipConfig = $null
            if ($dangerZoneSkip.PSObject.Properties['Users']) {
                $userSkipConfig = $dangerZoneSkip.Users
            } elseif ($dangerZoneSkip.PSObject.Properties['UserPrincipalNames'] -or $dangerZoneSkip.PSObject.Properties['SamAccountNames']) {
                $userSkipConfig = $dangerZoneSkip
            }
            if ($userSkipConfig) {
                if ($userSkipConfig.PSObject.Properties['UserPrincipalNames']) {
                    foreach ($value in @($userSkipConfig.UserPrincipalNames)) {
                        if (-not [string]::IsNullOrWhiteSpace($value)) { $skipUpnValues += ([string]$value).Trim() }
                    }
                }
                if ($userSkipConfig.PSObject.Properties['SamAccountNames']) {
                    foreach ($value in @($userSkipConfig.SamAccountNames)) {
                        if (-not [string]::IsNullOrWhiteSpace($value)) { $skipSamValues += ([string]$value).Trim() }
                    }
                }
            }
        }
        if ($usc.PSObject.Properties['DangerZoneSkipUserPrincipalNames']) {
            foreach ($value in @($usc.DangerZoneSkipUserPrincipalNames)) {
                if (-not [string]::IsNullOrWhiteSpace($value)) { $skipUpnValues += ([string]$value).Trim() }
            }
        }
        if ($usc.PSObject.Properties['DangerZoneSkipSamAccountNames']) {
            foreach ($value in @($usc.DangerZoneSkipSamAccountNames)) {
                if (-not [string]::IsNullOrWhiteSpace($value)) { $skipSamValues += ([string]$value).Trim() }
            }
        }
    }

    $skipUpnSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $skipUpnValues) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$skipUpnSet.Add($value) }
    }
    $skipSamSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $skipSamValues) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$skipSamSet.Add($value) }
    }

    $configPathForBase = $null
    if ($State -and $State.PSObject.Properties['ConfigPath']) {
        $configPathForBase = [string]$State.ConfigPath
    }
    $baseDir = Get-DashboardBaseDirectory -ConfigPath $configPathForBase
    if ([string]::IsNullOrWhiteSpace($baseDir)) {
        try { $baseDir = (Get-Location).ProviderPath } catch { $baseDir = (Get-Location).Path }
    }
    $logDir = Join-Path -Path $baseDir -ChildPath 'log'
    try {
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    } catch {
        Write-Host ("Failed to prepare log directory: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFile = Join-Path -Path $logDir -ChildPath ("openidsync_danger_remove_{0}.log" -f $timestamp)

    function Write-DangerLog {
        param(
            [string]$Message,
            [ValidateSet('INFO','WARN','ERROR','ACTION','RESULT')][string]$Level = 'INFO'
        )
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "[$ts] [$Level] $Message"
        try { $line | Out-File -FilePath $logFile -Encoding UTF8 -Append } catch {}
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARN'  { 'Yellow' }
            'ACTION' { 'Magenta' }
            'RESULT' { 'Green' }
            default { 'White' }
        }
        Write-Host $line -ForegroundColor $color
    }

    if ($skipUpnSet.Count -gt 0 -or $skipSamSet.Count -gt 0) {
        $skipUpnDisplay = if ($skipUpnSet.Count -gt 0) { (@($skipUpnSet) -join ', ') } else { 'none' }
        $skipSamDisplay = if ($skipSamSet.Count -gt 0) { (@($skipSamSet) -join ', ') } else { 'none' }
        Write-Host ("Configured to skip {0} user principal name(s) and {1} sAMAccountName(s)." -f $skipUpnSet.Count, $skipSamSet.Count) -ForegroundColor Yellow
        Write-DangerLog -Level 'INFO' -Message ("Configured skips -> UPNs: {0}; sAMAccountNames: {1}" -f $skipUpnDisplay, $skipSamDisplay)
    }

    Write-DangerLog -Level 'INFO' -Message ("Audit log initialized: {0}" -f $logFile)
    Write-DangerLog -Level 'INFO' -Message ("SearchBase: {0}" -f $searchBase)

    try {
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'Module ActiveDirectory not found. Install RSAT Active Directory tools and retry.'
            }
            Import-Module ActiveDirectory -ErrorAction Stop
        }
    } catch {
        Write-DangerLog -Level 'ERROR' -Message ("Failed to load ActiveDirectory module: {0}" -f $_.Exception.Message)
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $confirm1 = Read-Host "Type 'I UNDERSTAND' to continue or anything else to cancel"
    if ($confirm1 -ne 'I UNDERSTAND') {
        Write-DangerLog -Level 'INFO' -Message 'Aborted at first confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $confirm2 = Read-Host "Type 'DELETE' to confirm permanent deletion"
    if ($confirm2 -ne 'DELETE') {
        Write-DangerLog -Level 'INFO' -Message 'Aborted at second confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $previewChoice = (Read-Host 'Run in preview mode (WhatIf) without deleting users? [Y/N]').Trim()
    $whatIf = $false
    if ($previewChoice -match '^(Y|YES)$') { $whatIf = $true }

    Write-DangerLog -Level 'ACTION' -Message 'Scanning for OpenIDSync-managed users...'
    $candidates = @()
    $matchedTotal = 0
    $skipped = 0
    try {
        $users = Get-ADUser -SearchBase $searchBase -LDAPFilter '(objectClass=user)' -Properties description,displayName,samAccountName,userPrincipalName,distinguishedName -ResultSetSize $null
        foreach ($user in $users) {
            if ($user.Description -and ($user.Description -match '\[openidsync\.org\]')) {
                $matchedTotal++
                $upn = $null
                if ($user.PSObject.Properties['UserPrincipalName']) { $upn = [string]$user.UserPrincipalName }
                $sam = $null
                if ($user.PSObject.Properties['SamAccountName']) { $sam = [string]$user.SamAccountName }
                $skipByUpn = $false
                if ($upn -and $skipUpnSet.Contains($upn)) { $skipByUpn = $true }
                $skipBySam = $false
                if ($sam -and $skipSamSet.Contains($sam)) { $skipBySam = $true }
                if ($skipByUpn -or $skipBySam) {
                    $reasonParts = @()
                    if ($skipByUpn) { $reasonParts += 'UPN match' }
                    if ($skipBySam) { $reasonParts += 'sAMAccountName match' }
                    if ($reasonParts.Count -eq 0) { $reasonParts = @('Configured exclusion') }
                    $reasonText = $reasonParts -join ', '
                    $upnDisplay = if ($upn) { $upn } else { '(no UPN)' }
                    $samDisplay = if ($sam) { $sam } else { '(no sAMAccountName)' }
                    Write-DangerLog -Level 'INFO' -Message ("Skipping excluded user: {0} ({1}) - {2}" -f $samDisplay, $upnDisplay, $reasonText)
                    $skipped++
                    continue
                }
                $candidates += $user
            }
        }
    } catch {
        Write-DangerLog -Level 'ERROR' -Message ("Failed to query Active Directory: {0}" -f $_.Exception.Message)
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    Write-DangerLog -Level 'INFO' -Message ("Matched {0} managed user(s); skipped {1} due to configuration." -f $matchedTotal, $skipped)
    $found = $candidates.Count
    Write-DangerLog -Level 'INFO' -Message ("Found {0} user(s) eligible for deletion after exclusions." -f $found)
    if ($found -eq 0) {
        if ($matchedTotal -gt 0 -and $skipped -gt 0) {
            Write-Host 'All OpenIDSync-managed users matched the configured skip list. No deletion candidates remain.' -ForegroundColor Yellow
            Write-DangerLog -Level 'INFO' -Message 'All matched users were skipped due to configured exclusions.'
        } else {
            Write-Host 'No OpenIDSync-managed users found under the specified SearchBase.' -ForegroundColor Yellow
        }
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $backupPath = Join-Path -Path $logDir -ChildPath ("openidsync_danger_backup_{0}.csv" -f $timestamp)
    try {
        $candidates | Select-Object SamAccountName,UserPrincipalName,DisplayName,DistinguishedName | Export-Csv -Path $backupPath -NoTypeInformation -Encoding UTF8
        Write-DangerLog -Level 'INFO' -Message ("Backup exported to {0}" -f $backupPath)
    } catch {
        Write-DangerLog -Level 'WARN' -Message ("Failed to export backup list: {0}" -f $_.Exception.Message)
    }

    $actionWord = if ($whatIf) { 'preview removal of' } else { 'delete' }
    $finalConfirm = (Read-Host ("Last chance: proceed to {0} {1} user(s) under {2}? [Y/N]" -f $actionWord, $found, $searchBase)).Trim()
    if (-not ($finalConfirm -match '^(Y|YES)$')) {
        Write-DangerLog -Level 'INFO' -Message 'Aborted at final confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $removed = 0
    $failed = 0

    foreach ($candidate in $candidates) {
        $identity = $candidate.DistinguishedName
        if ($whatIf) {
            Write-DangerLog -Level 'ACTION' -Message ("WhatIf: Remove-ADUser -Identity '{0}'" -f $identity)
            continue
        }
        try {
            Remove-ADUser -Identity $identity -Confirm:$false -ErrorAction Stop
            Write-DangerLog -Level 'RESULT' -Message ("Deleted: {0} ({1})" -f $candidate.SamAccountName, $candidate.UserPrincipalName)
            $removed++
        } catch {
            Write-DangerLog -Level 'ERROR' -Message ("Failed to delete {0}: {1}" -f $candidate.UserPrincipalName, $_.Exception.Message)
            $failed++
        }
    }

    Write-Host ''
    Write-Host '==================== DANGER ZONE SUMMARY ====================' -ForegroundColor Red
    Write-Host ("Found:    {0}" -f $found) -ForegroundColor Red
    if ($whatIf) {
        Write-Host ("Previewed: {0}" -f $found) -ForegroundColor Yellow
        Write-Host 'Removed:   0 (preview mode)' -ForegroundColor Yellow
    } else {
        Write-Host ("Removed:  {0}" -f $removed) -ForegroundColor Red
    }
    Write-Host ("Skipped:  {0}" -f $skipped) -ForegroundColor Yellow
    Write-Host ("Failed:   {0}" -f $failed) -ForegroundColor Red
    Write-Host '=============================================================' -ForegroundColor Red
    Write-Host ''

    if ($whatIf) {
        Write-DangerLog -Level 'INFO' -Message ("Preview completed. {0} user(s) would be removed. Skipped: {1} user(s)." -f $found, $skipped)
    } else {
        Write-DangerLog -Level 'INFO' -Message ("Summary -> Found: {0}, Removed: {1}, Failed: {2}, Skipped: {3}" -f $found, $removed, $failed, $skipped)
    }

    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Invoke-DangerZoneRemoveManagedGroups {
    param([psobject]$State)

    Write-DangerZoneBanner -Message 'Remove all OpenIDSync-managed groups (and memberships) from Windows Active Directory.'

    $defaultSearchBase = $null
    if ($State -and $State.BaseConfig -and $State.BaseConfig.PSObject.Properties['UserSyncConfig']) {
        $usc = $State.BaseConfig.UserSyncConfig
        if ($usc) {
            $groupOuPropertyCandidates = @('GroupTargetOU','GroupsTargetOU','TargetGroupOU','GroupsDefaultOU','GroupDefaultOU','GroupsOU','GroupOU')
            foreach ($propName in $groupOuPropertyCandidates) {
                if ($usc.PSObject.Properties[$propName] -and -not [string]::IsNullOrWhiteSpace($usc.$propName)) {
                    $defaultSearchBase = [string]$usc.$propName
                    break
                }
            }
            if ([string]::IsNullOrWhiteSpace($defaultSearchBase) -and $usc.PSObject.Properties['DefaultOU'] -and -not [string]::IsNullOrWhiteSpace($usc.DefaultOU)) {
                $defaultSearchBase = [string]$usc.DefaultOU
            }
        }
    }

    $searchBase = $defaultSearchBase
    if (-not [string]::IsNullOrWhiteSpace($defaultSearchBase)) {
        Write-Host ("Default SearchBase from config: {0}" -f $defaultSearchBase) -ForegroundColor Yellow
        $override = Read-Host 'Press Enter to accept or type an alternate SearchBase DN for groups'
        if (-not [string]::IsNullOrWhiteSpace($override)) { $searchBase = $override }
    }
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        $searchBase = Read-Host 'Enter SearchBase distinguishedName to scan for managed groups (e.g. OU=Groups,DC=example,DC=com)'
    }
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        Write-Host 'SearchBase is required. Operation cancelled.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $configPathForBase = $null
    if ($State -and $State.PSObject.Properties['ConfigPath']) {
        $configPathForBase = [string]$State.ConfigPath
    }
    $baseDir = Get-DashboardBaseDirectory -ConfigPath $configPathForBase
    if ([string]::IsNullOrWhiteSpace($baseDir)) {
        try { $baseDir = (Get-Location).ProviderPath } catch { $baseDir = (Get-Location).Path }
    }
    $logDir = Join-Path -Path $baseDir -ChildPath 'log'
    try {
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    } catch {
        Write-Host ("Failed to prepare log directory: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFile = Join-Path -Path $logDir -ChildPath ("openidsync_danger_remove_groups_{0}.log" -f $timestamp)

    function Write-DangerGroupLog {
        param(
            [string]$Message,
            [ValidateSet('INFO','WARN','ERROR','ACTION','RESULT')][string]$Level = 'INFO'
        )
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "[$ts] [$Level] $Message"
        try { $line | Out-File -FilePath $logFile -Encoding UTF8 -Append } catch {}
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARN'  { 'Yellow' }
            'ACTION' { 'Magenta' }
            'RESULT' { 'Green' }
            default { 'White' }
        }
        Write-Host $line -ForegroundColor $color
    }

    Write-DangerGroupLog -Level 'INFO' -Message ("Audit log initialized: {0}" -f $logFile)
    Write-DangerGroupLog -Level 'INFO' -Message ("SearchBase: {0}" -f $searchBase)

    try {
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'Module ActiveDirectory not found. Install RSAT Active Directory tools and retry.'
            }
            Import-Module ActiveDirectory -ErrorAction Stop
        }
    } catch {
        Write-DangerGroupLog -Level 'ERROR' -Message ("Failed to load ActiveDirectory module: {0}" -f $_.Exception.Message)
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $confirm1 = Read-Host "Type 'I UNDERSTAND' to continue or anything else to cancel"
    if ($confirm1 -ne 'I UNDERSTAND') {
        Write-DangerGroupLog -Level 'INFO' -Message 'Aborted at first confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $confirm2 = Read-Host "Type 'DELETE GROUPS' to confirm permanent deletion"
    if ($confirm2 -ne 'DELETE GROUPS') {
        Write-DangerGroupLog -Level 'INFO' -Message 'Aborted at second confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $previewChoice = (Read-Host 'Run in preview mode (WhatIf) without deleting groups? [Y/N]').Trim()
    $whatIf = $false
    if ($previewChoice -match '^(Y|YES)$') { $whatIf = $true }

    Write-DangerGroupLog -Level 'ACTION' -Message 'Scanning for OpenIDSync-managed groups...'
    $groups = @()
    try {
        $groups = Get-ADGroup -SearchBase $searchBase -LDAPFilter '(objectClass=group)' -Properties Description,DisplayName,SamAccountName,DistinguishedName,GroupCategory,GroupScope -ResultSetSize $null
    } catch {
        Write-DangerGroupLog -Level 'ERROR' -Message ("Failed to query Active Directory: {0}" -f $_.Exception.Message)
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $candidates = @()
    foreach ($group in $groups) {
        if ($group.Description -and ($group.Description -match '\[openidsync\.org\]')) {
            $candidates += $group
        }
    }

    $found = $candidates.Count
    Write-DangerGroupLog -Level 'INFO' -Message ("Found {0} group(s) eligible for deletion." -f $found)
    if ($found -eq 0) {
        Write-Host 'No OpenIDSync-managed groups found under the specified SearchBase.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $groupBackup = @()
    $membershipBackup = @()

    foreach ($candidate in $candidates) {
        $members = @()
        try {
            $members = Get-ADGroupMember -Identity $candidate.DistinguishedName -Recursive:$false -ErrorAction Stop
        } catch {
            Write-DangerGroupLog -Level 'WARN' -Message ("Failed to enumerate members for {0}: {1}" -f $candidate.SamAccountName, $_.Exception.Message)
        }

        $parentGroups = @()
        try {
            $parentGroups = Get-ADPrincipalGroupMembership -Identity $candidate.DistinguishedName -ErrorAction SilentlyContinue
        } catch {
            Write-DangerGroupLog -Level 'WARN' -Message ("Failed to enumerate parent groups for {0}: {1}" -f $candidate.SamAccountName, $_.Exception.Message)
        }

        $memberCount = if ($members) { $members.Count } else { 0 }
        $parentCount = if ($parentGroups) { $parentGroups.Count } else { 0 }

        $groupBackup += [pscustomobject]@{
            SamAccountName       = $candidate.SamAccountName
            Name                 = $candidate.Name
            GroupCategory        = $candidate.GroupCategory
            GroupScope           = $candidate.GroupScope
            Description          = $candidate.Description
            MemberCount          = $memberCount
            ParentGroupCount     = $parentCount
            DistinguishedName    = $candidate.DistinguishedName
        }

        foreach ($member in $members) {
            $memberSam = $null
            if ($member.PSObject.Properties['SamAccountName']) { $memberSam = [string]$member.SamAccountName }
            $memberUpn = $null
            if ($member.PSObject.Properties['UserPrincipalName']) { $memberUpn = [string]$member.UserPrincipalName }
            $membershipBackup += [pscustomobject]@{
                GroupSamAccountName        = $candidate.SamAccountName
                Relation                   = 'Member'
                RelatedSamAccountName      = $memberSam
                RelatedDistinguishedName   = $member.DistinguishedName
                RelatedObjectClass         = $member.ObjectClass
                RelatedUserPrincipalName   = $memberUpn
            }
        }

        foreach ($parent in $parentGroups) {
            $parentSam = $null
            if ($parent.PSObject.Properties['SamAccountName']) { $parentSam = [string]$parent.SamAccountName }
            $membershipBackup += [pscustomobject]@{
                GroupSamAccountName        = $candidate.SamAccountName
                Relation                   = 'ParentGroup'
                RelatedSamAccountName      = $parentSam
                RelatedDistinguishedName   = $parent.DistinguishedName
                RelatedObjectClass         = $parent.ObjectClass
                RelatedUserPrincipalName   = $null
            }
        }
    }

    $groupBackupPath = Join-Path -Path $logDir -ChildPath ("openidsync_danger_groups_{0}.csv" -f $timestamp)
    try {
        $groupBackup | Export-Csv -Path $groupBackupPath -NoTypeInformation -Encoding UTF8
        Write-DangerGroupLog -Level 'INFO' -Message ("Group backup exported to {0}" -f $groupBackupPath)
    } catch {
        Write-DangerGroupLog -Level 'WARN' -Message ("Failed to export group backup: {0}" -f $_.Exception.Message)
    }

    if ($membershipBackup.Count -gt 0) {
        $membershipBackupPath = Join-Path -Path $logDir -ChildPath ("openidsync_danger_group_links_{0}.csv" -f $timestamp)
        try {
            $membershipBackup | Export-Csv -Path $membershipBackupPath -NoTypeInformation -Encoding UTF8
            Write-DangerGroupLog -Level 'INFO' -Message ("Membership backup exported to {0}" -f $membershipBackupPath)
        } catch {
            Write-DangerGroupLog -Level 'WARN' -Message ("Failed to export membership backup: {0}" -f $_.Exception.Message)
        }
    }

    $actionWord = if ($whatIf) { 'preview removal of' } else { 'delete' }
    $finalConfirm = (Read-Host ("Last chance: proceed to {0} {1} group(s) under {2}? [Y/N]" -f $actionWord, $found, $searchBase)).Trim()
    if (-not ($finalConfirm -match '^(Y|YES)$')) {
        Write-DangerGroupLog -Level 'INFO' -Message 'Aborted at final confirmation prompt.'
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $removed = 0
    $failed = 0
    $parentMembershipsRemoved = 0

    foreach ($candidate in $candidates) {
        if ($whatIf) {
            Write-DangerGroupLog -Level 'ACTION' -Message ("WhatIf: Remove-ADGroup -Identity '{0}'" -f $candidate.DistinguishedName)
            continue
        }

        $parentGroups = @()
        try {
            $parentGroups = Get-ADPrincipalGroupMembership -Identity $candidate.DistinguishedName -ErrorAction SilentlyContinue
        } catch {}

        foreach ($parent in $parentGroups) {
            try {
                Remove-ADGroupMember -Identity $parent.DistinguishedName -Members $candidate.DistinguishedName -Confirm:$false -ErrorAction Stop
                Write-DangerGroupLog -Level 'ACTION' -Message ("Removed group {0} from parent group {1}" -f $candidate.SamAccountName, $parent.SamAccountName)
                $parentMembershipsRemoved++
            } catch {
                Write-DangerGroupLog -Level 'WARN' -Message ("Failed to remove group {0} from parent group {1}: {2}" -f $candidate.SamAccountName, $parent.SamAccountName, $_.Exception.Message)
            }
        }

        try {
            Remove-ADGroup -Identity $candidate.DistinguishedName -Confirm:$false -ErrorAction Stop
            Write-DangerGroupLog -Level 'RESULT' -Message ("Deleted group: {0}" -f $candidate.SamAccountName)
            $removed++
        } catch {
            Write-DangerGroupLog -Level 'ERROR' -Message ("Failed to delete group {0}: {1}" -f $candidate.SamAccountName, $_.Exception.Message)
            $failed++
        }
    }

    Write-Host ''
    Write-Host '==================== DANGER ZONE SUMMARY ====================' -ForegroundColor Red
    Write-Host ("Found:    {0}" -f $found) -ForegroundColor Red
    if ($whatIf) {
        Write-Host ("Previewed: {0}" -f $found) -ForegroundColor Yellow
        Write-Host 'Removed:   0 (preview mode)' -ForegroundColor Yellow
        Write-Host 'Parent memberships removed: 0 (preview mode)' -ForegroundColor Yellow
        Write-Host 'Failed:   0 (preview mode)' -ForegroundColor Yellow
    } else {
        Write-Host ("Removed:  {0}" -f $removed) -ForegroundColor Red
        Write-Host ("Parent memberships removed: {0}" -f $parentMembershipsRemoved) -ForegroundColor Red
        Write-Host ("Failed:   {0}" -f $failed) -ForegroundColor Red
    }
    Write-Host '=============================================================' -ForegroundColor Red
    Write-Host ''

    if ($whatIf) {
        Write-DangerGroupLog -Level 'INFO' -Message ("Preview completed. {0} group(s) would be removed." -f $found)
    } else {
        Write-DangerGroupLog -Level 'INFO' -Message ("Summary -> Found: {0}, Removed: {1}, Failed: {2}, ParentMembershipsRemoved: {3}" -f $found, $removed, $failed, $parentMembershipsRemoved)
    }

    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Invoke-DangerZoneUninstallOpenIdSync {
    param([psobject]$State)

    Write-DangerZoneBanner -Message 'Uninstall OpenIDSync components and reset local configuration.'

    $configPath = $null
    if ($State -and $State.PSObject.Properties['ConfigPath']) { $configPath = [string]$State.ConfigPath }
    if ([string]::IsNullOrWhiteSpace($configPath)) {
        $configPath = Join-Path -Path (Get-DashboardBaseDirectory -ConfigPath $null) -ChildPath '00_OpenIDSync_Config.json'
    }

    $onlineConfigPath = $null
    if ($State -and $State.PSObject.Properties['OnlineConfigPath']) { $onlineConfigPath = [string]$State.OnlineConfigPath }
    if ([string]::IsNullOrWhiteSpace($onlineConfigPath)) {
        $onlineConfigPath = Join-Path -Path (Get-DashboardBaseDirectory -ConfigPath $configPath) -ChildPath '00_OpenIDSync_OnlineSyncConfig.json'
    }

    $secretEnvName = 'OPENIDSYNC_CLIENT_SECRET'
    if ($State -and $State.PSObject.Properties['SecretInfo'] -and $State.SecretInfo -and $State.SecretInfo.PSObject.Properties['Name']) {
        $candidateName = [string]$State.SecretInfo.Name
        if (-not [string]::IsNullOrWhiteSpace($candidateName)) { $secretEnvName = $candidateName }
    }

    Write-Host 'This operation will attempt to:' -ForegroundColor Yellow
    Write-Host '  - Clear the OpenIDSync client secret environment variable.' -ForegroundColor Yellow
    Write-Host '  - Remove the Azure app registration and service principal (if found).' -ForegroundColor Yellow
    Write-Host '  - Uninstall Microsoft Graph PowerShell modules used by OpenIDSync.' -ForegroundColor Yellow
    Write-Host '  - Reset the online sync configuration JSON file.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host ('Resolved config path: {0}' -f $configPath) -ForegroundColor DarkGray
    Write-Host ('Resolved online config path: {0}' -f $onlineConfigPath) -ForegroundColor DarkGray
    Write-Host ('Client secret environment variable: {0}' -f $secretEnvName) -ForegroundColor DarkGray
    Write-Host ''

    $skipEnv = $false
    $skipApp = $false
    $skipModules = $false
    $skipConfig = $false

    $choiceEnv = (Read-Host 'Skip environment variable cleanup? [y/N]').Trim()
    if ($choiceEnv -match '^(Y|YES)$') { $skipEnv = $true }

    $choiceApp = (Read-Host 'Skip Azure app registration removal? [y/N]').Trim()
    if ($choiceApp -match '^(Y|YES)$') { $skipApp = $true }

    $choiceModules = (Read-Host 'Skip Microsoft Graph module uninstall? [y/N]').Trim()
    if ($choiceModules -match '^(Y|YES)$') { $skipModules = $true }

    $choiceConfig = (Read-Host 'Skip online config reset? [y/N]').Trim()
    if ($choiceConfig -match '^(Y|YES)$') { $skipConfig = $true }

    $confirm1 = Read-Host "Type 'I UNDERSTAND' to continue or anything else to cancel"
    if ($confirm1 -ne 'I UNDERSTAND') {
        Write-Host 'Uninstall aborted at first confirmation prompt.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $confirm2 = Read-Host "Type 'UNINSTALL' to confirm OpenIDSync uninstall"
    if ($confirm2 -ne 'UNINSTALL') {
        Write-Host 'Uninstall aborted at second confirmation prompt.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    $whatIfChoice = (Read-Host 'Run in preview mode (WhatIf) without making changes? [y/N]').Trim()
    $whatIf = $false
    if ($whatIfChoice -match '^(Y|YES)$') { $whatIf = $true }

    try {
        $result = Invoke-OpenIdSyncUninstall -ConfigPath $configPath -OnlineSyncConfigPath $onlineConfigPath -ClientSecretEnvVar $secretEnvName -SkipEnvVar:$skipEnv -SkipAppRemoval:$skipApp -SkipModuleRemoval:$skipModules -SkipConfigUpdate:$skipConfig -NonInteractive:$true -WhatIf:$whatIf
    } catch {
        Write-Host ("Uninstall routine failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to return to the dashboard...')
        return
    }

    Write-Host ''
    if ($whatIf) {
        Write-Host 'Preview mode complete. No changes were made.' -ForegroundColor Yellow
    } else {
        Write-Host 'Uninstall routine complete.' -ForegroundColor Green
    }

    if ($result) {
        Write-Host ''
        Write-Host '=== Uninstall Summary ===' -ForegroundColor Cyan
        if ($result.EnvVarClearedScopes -and $result.EnvVarClearedScopes.Count -gt 0) {
            Write-Host ("Environment variable cleared for scopes: {0}" -f ($result.EnvVarClearedScopes -join ', '))
        } elseif ($skipEnv) {
            Write-Host 'Environment variable cleanup skipped.' -ForegroundColor Yellow
        } else {
            Write-Host 'No environment variables were cleared.' -ForegroundColor Yellow
        }
        if ($result.EnvVarErrors -and $result.EnvVarErrors.Count -gt 0) {
            Write-Host 'Environment cleanup warnings:' -ForegroundColor Yellow
            foreach ($msg in $result.EnvVarErrors) { Write-Host ('  - {0}' -f $msg) -ForegroundColor Yellow }
        }

        if ($result.ServicePrincipalRemoved) {
            Write-Host 'Service principal removed.'
        } elseif ($skipApp) {
            Write-Host 'Service principal removal skipped.' -ForegroundColor Yellow
        } else {
            Write-Host 'Service principal not removed (not found or unsuccessful).' -ForegroundColor Yellow
        }

        if ($result.ApplicationRemoved) {
            Write-Host 'App registration removed.'
        } elseif ($skipApp) {
            Write-Host 'App registration removal skipped.' -ForegroundColor Yellow
        } else {
            Write-Host 'App registration not removed (not found or unsuccessful).' -ForegroundColor Yellow
        }

        if ($result.ModuleRemovalSucceeded -and $result.ModuleRemovalSucceeded.Count -gt 0) {
            Write-Host ("Modules uninstalled: {0}" -f ($result.ModuleRemovalSucceeded -join ', '))
        } elseif ($skipModules) {
            Write-Host 'Module uninstall skipped.' -ForegroundColor Yellow
        } else {
            Write-Host 'No modules were uninstalled.' -ForegroundColor Yellow
        }
        if ($result.ModuleRemovalFailed -and $result.ModuleRemovalFailed.Count -gt 0) {
            Write-Host 'Module uninstall warnings:' -ForegroundColor Yellow
            foreach ($msg in $result.ModuleRemovalFailed) { Write-Host ('  - {0}' -f $msg) -ForegroundColor Yellow }
        }

        if ($result.ConfigReset) {
            Write-Host 'Online sync configuration reset.'
        } elseif ($skipConfig) {
            Write-Host 'Online sync configuration reset skipped.' -ForegroundColor Yellow
        } else {
            Write-Host 'Online sync configuration not reset.' -ForegroundColor Yellow
            if ($result.ConfigResetError) { Write-Host ('  Reason: {0}' -f $result.ConfigResetError) -ForegroundColor Yellow }
        }

        if ($result.Notes -and $result.Notes.Count -gt 0) {
            Write-Host 'Additional notes:' -ForegroundColor Yellow
            foreach ($note in $result.Notes) { Write-Host ('  - {0}' -f $note) -ForegroundColor Yellow }
        }
    }

    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Invoke-OpenGwToolsRoadwarriorExport {
    param(
        [psobject]$State
    )

    Write-Host ''
    Write-Host '=== OpenGWTools VPN Roadwarriors Export ===' -ForegroundColor Cyan

    if (-not $State) {
        Write-Host 'Dashboard state not available. Run the dashboard again.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $tenantId = $null
    $clientId = $null
    if ($State.OnlineConfig -and $State.OnlineConfig.PSObject.Properties['OnlineSyncConfig']) {
        $osc = $State.OnlineConfig.OnlineSyncConfig
        if ($osc) {
            if ($osc.PSObject.Properties['TenantId']) { $tenantId = [string]$osc.TenantId }
            if ($osc.PSObject.Properties['ClientId']) { $clientId = [string]$osc.ClientId }
        }
    }
    $clientSecret = $null
    if ($State.SecretInfo -and $State.SecretInfo.PSObject.Properties['RawValue']) { $clientSecret = [string]$State.SecretInfo.RawValue }

    if ([string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId)) {
        Write-Host 'TenantId or ClientId is missing from OnlineSyncConfig. Complete requirement 2 first.' -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    if ([string]::IsNullOrWhiteSpace($clientSecret)) {
        Write-Host 'Client secret not found in environment; an interactive Microsoft Graph sign-in may be required.' -ForegroundColor Yellow
    }

    $baseDir = $null
    if ($State.ConfigPath) {
        try { $baseDir = Split-Path -Path $State.ConfigPath -Parent } catch { $baseDir = $null }
    }
    if (-not $baseDir) {
        try { $baseDir = (Get-Location).Path } catch { $baseDir = '.' }
    }
    $logDir = Join-Path -Path $baseDir -ChildPath 'log'
    try {
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
    } catch {
        Write-Host ("Failed to ensure log directory: {0}" -f $_.Exception.Message) -ForegroundColor Red
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $defaultPath = Join-Path -Path $logDir -ChildPath 'OpenGWTools-Roadwarriors.csv'
    $prompt = "Enter export path or press Enter for default [$defaultPath]"
    $userPath = (Read-Host $prompt).Trim()
    if ([string]::IsNullOrWhiteSpace($userPath)) { $userPath = $defaultPath }

    $outputPath = $userPath
    $outputDir = $null
    try { $outputDir = Split-Path -Path $outputPath -Parent } catch { $outputDir = $null }
    if (-not [string]::IsNullOrWhiteSpace($outputDir)) {
        try {
            if (-not (Test-Path -LiteralPath $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }
        } catch {
            Write-Host ("Failed to create output directory: {0}" -f $_.Exception.Message) -ForegroundColor Red
            [void](Read-Host 'Press Enter to continue...')
            return
        }
    }

    Write-Host 'Connecting to Microsoft Graph and preparing export (firstName,lastName,comment)...'
    try { Write-Log -Level 'ACTION' -Message ("OpenGWTools export initiated -> {0}" -f $outputPath) } catch {}

    $users = $null
    try {
        $users = Get-EntraUsersViaGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    } catch {
        $err = $_.Exception.Message
        Write-Host ("Failed to query Microsoft Graph: {0}" -f $err) -ForegroundColor Red
        try { Write-Log -Level 'ERROR' -Message ("OpenGWTools export failed: {0}" -f $err) } catch {}
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    if (-not $users -or $users.Count -eq 0) {
        Write-Host 'No users returned from Microsoft Graph.' -ForegroundColor Yellow
        try { Write-Log -Level 'WARN' -Message 'OpenGWTools export generated no rows (no users).' } catch {}
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $exportRows = @()
    $skippedNoOffice = 0
    foreach ($user in $users) {
        $firstName = [string]$user.'First name'
        $lastName = [string]$user.'Last name'
        if ([string]::IsNullOrWhiteSpace($firstName) -and [string]::IsNullOrWhiteSpace($lastName)) {
            $display = [string]$user.'Display name'
            if (-not [string]::IsNullOrWhiteSpace($display)) {
                $parts = $display -split '\s+', 2
                if ($parts.Length -ge 2) {
                    $firstName = $parts[0]
                    $lastName = $parts[1]
                } else {
                    $firstName = $display
                }
            }
        }

        $officeField = [string]$user.'Office'
        $commentValues = @()
        if (-not [string]::IsNullOrWhiteSpace($officeField)) {
            $commentValues = @($officeField -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
        }

        if ($commentValues.Count -eq 0) {
            $skippedNoOffice++
            try { Write-Log -Level 'DEBUG' -Message ("OpenGWTools export skip -> {0} {1} (no Office location)" -f $firstName, $lastName) } catch {}
            continue
        }

        foreach ($comment in $commentValues) {
            $row = [pscustomobject]@{
                firstName = $firstName
                lastName  = $lastName
                comment   = $comment
            }
            $exportRows += $row
            try { Write-Log -Level 'DEBUG' -Message ("OpenGWTools export row -> {0} {1} comment='{2}'" -f $row.firstName, $row.lastName, $row.comment) } catch {}
        }
    }

    try {
        if (Test-Path -LiteralPath $outputPath) {
            Remove-Item -LiteralPath $outputPath -Force
        }
        if ($exportRows.Count -gt 0) {
            $exportRows | Export-Csv -LiteralPath $outputPath -Encoding UTF8 -NoTypeInformation -Force
        } else {
            Set-Content -LiteralPath $outputPath -Value '"firstName","lastName","comment"'
        }
    } catch {
        $err = $_.Exception.Message
        Write-Host ("Failed to write CSV: {0}" -f $err) -ForegroundColor Red
        try { Write-Log -Level 'ERROR' -Message ("OpenGWTools export write failure: {0}" -f $err) } catch {}
        [void](Read-Host 'Press Enter to continue...')
        return
    }

    $userCount = ($users | Measure-Object).Count
    try { Write-Log -Level 'RESULT' -Message ("OpenGWTools export completed. Users: {0}, Rows: {1}, Path: {2}" -f $userCount, $exportRows.Count, $outputPath) } catch {}

    Write-Host ''
    if ($exportRows.Count -gt 0) {
        Write-Host ("Export successful. {0} rows written to {1}" -f $exportRows.Count, $outputPath) -ForegroundColor Green
    } else {
        Write-Host ("Export completed with no device entries. Header-only file written to {0}" -f $outputPath) -ForegroundColor Yellow
    }
    if ($skippedNoOffice -gt 0) {
        Write-Host ("Skipped {0} user(s) without Office location values." -f $skippedNoOffice) -ForegroundColor Yellow
    }
    Write-Host 'Import this CSV into OpenGWTools VPN Roadwarriors module.'
    [void](Read-Host 'Press Enter to return to the dashboard...')
}

function Invoke-OpenIdSyncDashboard {
    param(
        [string]$ConfigPath,
        [string]$OnlineConfigPath,
        [string]$CredentialFilePath,
        [string]$InitialSource,
        [string]$InitialTarget,
        [string]$DefaultOU
    )

    $forcePermissionRefresh = $false
    $forceOnlineRefresh = $false

    while ($true) {
    $state = Get-OpenIdSyncDashboardState -ConfigPath $ConfigPath -OnlineConfigPath $OnlineConfigPath -CredentialFilePath $CredentialFilePath -ForcePermissionRefresh:$forcePermissionRefresh -ForceOnlineRefresh:$forceOnlineRefresh
        if ([string]::IsNullOrWhiteSpace($state.PreferredSource) -and $InitialSource) {
            $state.PreferredSource = $InitialSource
        }
        if ([string]::IsNullOrWhiteSpace($state.Target) -and $InitialTarget) {
            $state.Target = $InitialTarget
        }

        $available = @()
        foreach ($req in $state.Requirements) {
            if (-not $req.IsMet) { $available += [string]$req.Id }
        }
        if ($state.AllRequirementsMet) {
            $available += '4','5','6','7','8','9','10','12','13','80','81','82'
        }
        $available += '11','99'

        Write-OpenIdSyncDashboard -State $state -AvailableOptions $available
        $forcePermissionRefresh = $false
        $forceOnlineRefresh = $false
        $choice = (Read-Host 'Select an option').Trim()
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice) {
            '1' {
                if ($available -contains '1') { Invoke-Requirement1Remediation } else { Write-Host 'Requirement 1 already satisfied.' -ForegroundColor Green; [void](Read-Host 'Press Enter to continue...') }
            }
            '2' {
                if ($available -contains '2') {
                    Invoke-Requirement2Bootstrap -ConfigPath $ConfigPath -OnlineConfigPath $OnlineConfigPath -State $state
                    $forceOnlineRefresh = $true
                } else {
                    Write-Host 'Requirement 2 already satisfied.' -ForegroundColor Green
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '3' {
                if ($available -contains '3') {
                    $forcePermissionRefresh = $true
                    try {
                        $null = Get-RequirementStatuses -BaseConfig $state.BaseConfig -OnlineConfig $state.OnlineConfig -SecretInfo $state.SecretInfo -ForcePermissionRefresh
                        Write-Host 'Permission check requested. Results will refresh on next screen.' -ForegroundColor Green
                    } catch {
                        Write-Host ("Permission verification failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    }
                } else {
                    Write-Host 'Requirement 3 already satisfied.' -ForegroundColor Green
                }
                [void](Read-Host 'Press Enter to continue...')
            }
            '4' {
                if ($state.AllRequirementsMet) {
                    $userInput = Read-Host ("Enter Users sync mode [S/A/P] (current: {0})" -f $state.UsersMode.Substring(0,1))
                    if (-not [string]::IsNullOrWhiteSpace($userInput)) {
                        $newVal = Normalize-SyncModeValue -Value $userInput -Default $state.UsersMode
                        if ($newVal -ne $state.UsersMode) {
                            Set-UserSyncMode -ConfigPath $ConfigPath -ModeName 'Users' -Value $newVal
                        }
                    }
                } else {
                    Write-Host 'Complete all requirements before adjusting sync modes.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '5' {
                if ($state.AllRequirementsMet) {
                    $userInput = Read-Host ("Enter Groups sync mode [S/A/P] (current: {0})" -f $state.GroupsMode.Substring(0,1))
                    if (-not [string]::IsNullOrWhiteSpace($userInput)) {
                        $newVal = Normalize-SyncModeValue -Value $userInput -Default $state.GroupsMode
                        if ($newVal -ne $state.GroupsMode) {
                            Set-UserSyncMode -ConfigPath $ConfigPath -ModeName 'Groups' -Value $newVal
                        }
                    }
                } else {
                    Write-Host 'Complete all requirements before adjusting sync modes.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '6' {
                if ($state.AllRequirementsMet) {
                    $userInput = Read-Host ("Enter Memberships sync mode [S/A/P] (current: {0})" -f $state.MembershipsMode.Substring(0,1))
                    if (-not [string]::IsNullOrWhiteSpace($userInput)) {
                        $newVal = Normalize-SyncModeValue -Value $userInput -Default $state.MembershipsMode
                        if ($newVal -ne $state.MembershipsMode) {
                            Set-UserSyncMode -ConfigPath $ConfigPath -ModeName 'Memberships' -Value $newVal
                        }
                    }
                } else {
                    Write-Host 'Complete all requirements before adjusting sync modes.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '7' {
                if ($state.AllRequirementsMet) {
                    Write-Host ''
                    Write-Host 'Select new source directory:'
                    Write-Host '  M - Azure Entra ID (Microsoft)'
                    Write-Host '  C - CSV File (Microsoft 365 Admin Portal Export)'
                    Write-Host '  (Other providers are listed but not yet supported.)'
                    $userInput = (Read-Host 'Enter choice [M/C]').Trim().ToUpper()
                    switch ($userInput) {
                        'M' { Set-PreferredSource -ConfigPath $ConfigPath -PreferredSource 'Online' }
                        'C' { Set-PreferredSource -ConfigPath $ConfigPath -PreferredSource 'CSV' }
                        default {
                            Write-Host 'Selected source is not supported yet. No changes made.' -ForegroundColor Yellow
                            [void](Read-Host 'Press Enter to continue...')
                        }
                    }
                } else {
                    Write-Host 'Complete all requirements before changing the source directory.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '8' {
                if ($state.AllRequirementsMet) {
                    Write-Host ''
                    Write-Host 'Select new target directory:'
                    Write-Host '  W - Windows Active Directory (Microsoft)'
                    Write-Host '  (Other options coming soon.)'
                    $userInput = (Read-Host 'Enter choice [W]').Trim().ToUpper()
                    if ($userInput -ne 'W') {
                        Write-Host 'Only Windows Active Directory is currently supported as target.' -ForegroundColor Yellow
                        [void](Read-Host 'Press Enter to continue...')
                    } else {
                        $script:Target = 'WindowsAD'
                    }
                } else {
                    Write-Host 'Complete all requirements before changing the target directory.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '9' {
                if (-not $state.AllRequirementsMet) {
                    Write-Host 'Resolve all requirements before starting synchronization.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                } else {
                    $final = Get-OpenIdSyncDashboardState -ConfigPath $ConfigPath -OnlineConfigPath $OnlineConfigPath -CredentialFilePath $CredentialFilePath
                    return [pscustomobject]@{
                        StartSync       = $true
                        ExitRequested   = $false
                        Source          = $final.PreferredSource
                        Target          = $final.Target
                        UsersMode       = $final.UsersMode
                        GroupsMode      = $final.GroupsMode
                        MembershipsMode = $final.MembershipsMode
                    }
                }
            }
            '10' {
                if ($state.AllRequirementsMet) {
                    Invoke-PasswordCredentialRedaction -CredentialFilePath $CredentialFilePath -DashboardState $state
                } else {
                    Write-Host 'Resolve requirements before managing password file.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '11' {
                Show-ConfigurationDetails -Details $state.ConfigurationDetails
            }
            '12' {
                if ($available -contains '12') {
                    Show-RequirementDetails -Requirements $state.Requirements
                } else {
                    Write-Host 'Requirement details are only available after all requirements pass.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '13' {
                if ($available -contains '13') {
                    Invoke-OpenGwToolsRoadwarriorExport -State $state
                } else {
                    Write-Host 'Resolve all requirements before exporting the OpenGWTools CSV.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '80' {
                if ($available -contains '80') {
                    Invoke-DangerZoneRemoveManagedUsers -State $state
                } else {
                    Write-Host 'Danger zone options are only available after all requirements are satisfied.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '81' {
                if ($available -contains '81') {
                    Invoke-DangerZoneRemoveManagedGroups -State $state
                } else {
                    Write-Host 'Danger zone options are only available after all requirements are satisfied.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '82' {
                if ($available -contains '82') {
                    Invoke-DangerZoneUninstallOpenIdSync -State $state
                } else {
                    Write-Host 'Danger zone options are only available after all requirements are satisfied.' -ForegroundColor Yellow
                    [void](Read-Host 'Press Enter to continue...')
                }
            }
            '99' {
                return [pscustomobject]@{
                    StartSync       = $false
                    ExitRequested   = $true
                    Source          = $state.PreferredSource
                    Target          = $state.Target
                    UsersMode       = $state.UsersMode
                    GroupsMode      = $state.GroupsMode
                    MembershipsMode = $state.MembershipsMode
                }
            }
            default {
                Write-Host 'Invalid selection. Please choose a valid option.' -ForegroundColor Yellow
                [void](Read-Host 'Press Enter to continue...')
            }
        }
    }
}
