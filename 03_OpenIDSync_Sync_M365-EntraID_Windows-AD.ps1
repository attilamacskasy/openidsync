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

# Try to load logging module
try {
    $logModulePath = Join-Path -Path $PSScriptRoot -ChildPath '50_OpenIDSync_Logging.ps1'
    if (Test-Path -LiteralPath $logModulePath) { . $logModulePath }
} catch {}

# ===== Graph Modules configuration (only what's needed) =====
# Centralized list of Microsoft Graph submodules to install/import for this script.
# Keep this minimal to avoid PS 5.1 function overflow. Add/remove here as capabilities grow.
$script:GraphModules = @(
    'Microsoft.Graph.Authentication',          # Connect-MgGraph
    'Microsoft.Graph.Users',                   # Get-MgUser
    'Microsoft.Graph.Applications',            # App/SP creation & role assignment
    'Microsoft.Graph.Identity.DirectoryManagement', # Directory roles activation/membership
    'Microsoft.Graph.Groups'                   # Future: group lookups (Get-MgGroup)
)

# Increase function capacity to avoid Graph import overflow on Windows PowerShell 5.1
try {
    $targetFuncCap = 32768
    $currentFuncCap = $MaximumFunctionCount
    if ($currentFuncCap -lt $targetFuncCap) {
        try { Set-Variable -Name MaximumFunctionCount -Value $targetFuncCap -Scope Global -Force } catch {}
        try { $global:MaximumFunctionCount = $targetFuncCap } catch {}
        try { $MaximumFunctionCount = $targetFuncCap } catch {}
    }
} catch {}

# ==================== Helpers ====================

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Please install RSAT Active Directory tools and try again." -ForegroundColor Yellow
        throw "Missing module: $Name"
    }
    Import-Module $Name -ErrorAction Stop
}

function Install-GraphModule {
    try {
        Write-Log -Level 'ACTION' -Message 'Attempting to install Microsoft Graph PowerShell submodules for current user...'
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }
        try { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue } catch {}
        foreach ($m in $script:GraphModules) {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                Install-Module $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
        }
        Write-Log -Level 'RESULT' -Message ("Microsoft Graph submodules installed: {0}" -f ($script:GraphModules -join ', '))
        return $true
    } catch {
        Write-Log -Level 'ERROR' -Message "Failed to install Microsoft Graph submodules: $($_.Exception.Message)"
        return $false
    }
}

function Ensure-GraphModule {
    # Import minimal required Microsoft Graph submodules to avoid function overflow.
    $required = $script:GraphModules
    $available = @()
    foreach ($r in $required) { if (Get-Module -ListAvailable -Name $r) { $available += $r } }
    if ($available.Count -lt $required.Count) {
        if ($script:AutoInstallGraphModules -or $script:NonInteractive) {
            $ok = Install-GraphModule
            if (-not $ok) { throw "Missing Graph modules (see $script:GraphModules list)" }
        } else {
            Write-Host "Microsoft Graph PowerShell is required for Online mode. Required submodules:" -ForegroundColor Yellow
            $listText = (" - " + ($required -join "`n - "))
            Write-Host $listText -ForegroundColor Yellow
            $installText = ("Install with: Install-Module {0} -Scope CurrentUser" -f ($required -join ','))
            Write-Host $installText -ForegroundColor Yellow
            $ans = Read-Host "Install required submodules now? [Y]es/[N]o"
            if ($ans -match '^(?i:y|yes)$') {
                $ok = Install-GraphModule
                if (-not $ok) { throw "Missing Graph modules (see $script:GraphModules list)" }
            } else {
                throw "Missing Graph modules (see $script:GraphModules list)"
            }
        }
    }
    foreach ($m in $required) { Import-Module $m -ErrorAction Stop }
    Write-Log -Level 'INFO' -Message ("Imported Graph submodules: {0}" -f ($required -join ', '))
}

function Verify-GraphCommands {
    $cmds = @(
        'Connect-MgGraph','Get-MgContext','Get-MgUser','Get-MgGroup',
        'New-MgApplication','Add-MgApplicationPassword','New-MgServicePrincipal','Get-MgServicePrincipal','New-MgServicePrincipalAppRoleAssignment',
        'Get-MgDirectoryRole','Get-MgDirectoryRoleTemplate','New-MgDirectoryRole','New-MgDirectoryRoleMemberByRef'
    )
    $missing = @()
    foreach ($c in $cmds) { if (-not (Get-Command -Name $c -ErrorAction SilentlyContinue)) { $missing += $c } }
    if ($missing.Count -gt 0) {
        $msg = "Missing Microsoft Graph cmdlets: " + ($missing -join ', ')
        Write-Log -Level 'ERROR' -Message $msg
        throw $msg
    }
}

function Get-TenantLicenseInfo {
    try {
        # Requires Directory.Read.All in delegated context which we already use
        $skus = Get-MgSubscribedSku -ErrorAction SilentlyContinue
        if (-not $skus) { return [pscustomobject]@{ HasPremium = $false; Plan = 'Unknown' } }
        $planNames = @($skus | ForEach-Object { $_.SkuPartNumber })
        $hasP1 = $planNames -match 'AAD_PREMIUM' -or $planNames -match 'AAD_PREMIUM_P1' -or $planNames -match 'ENTERPRISEPREMIUM'
        $hasP2 = $planNames -match 'AAD_PREMIUM_P2'
        $hasE3 = $planNames -match 'ENTERPRISEPACK' -or $planNames -match 'STANDARDPACK'
        $hasE5 = $planNames -match 'ENTERPRISEPREMIUM'
        $hasPremium = ($hasP1 -or $hasP2 -or $hasE3 -or $hasE5)
        $plan = if ($hasE5) { 'E5' } elseif ($hasE3) { 'E3' } elseif ($hasP2) { 'P2' } elseif ($hasP1) { 'P1' } else { 'Free' }
        return [pscustomobject]@{ HasPremium = [bool]$hasPremium; Plan = $plan }
    } catch {
        return [pscustomobject]@{ HasPremium = $false; Plan = 'Unknown' }
    }
}

function Save-OnlineSyncConfig {
    param(
        [Parameter(Mandatory=$true)][string]$OnlineConfigPath,
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [string]$SpObjectId,
        [string]$ClientSecretEnvVar
    )
    try {
        $cfgObj = $null
        if (Test-Path -LiteralPath $OnlineConfigPath) {
            try { $cfgObj = (Get-Content -LiteralPath $OnlineConfigPath -Raw | ConvertFrom-Json) } catch { $cfgObj = $null }
        }
        if (-not $cfgObj) { $cfgObj = [pscustomobject]@{} }

        # Ensure OnlineSyncConfig block exists as PSCustomObject
        if (-not ($cfgObj.PSObject.Properties['OnlineSyncConfig'])) {
            $cfgObj | Add-Member -NotePropertyName 'OnlineSyncConfig' -NotePropertyValue ([pscustomobject]@{})
        }
        $osc = $cfgObj.OnlineSyncConfig
        if (-not ($osc -is [pscustomobject])) { $osc = [pscustomobject]$osc }

        # Assign values (Add-Member -Force updates or creates)
        $osc | Add-Member -NotePropertyName 'TenantId' -NotePropertyValue $TenantId -Force
        $osc | Add-Member -NotePropertyName 'ClientId' -NotePropertyValue $ClientId -Force
    if ($SpObjectId) { $osc | Add-Member -NotePropertyName 'SpObjectId' -NotePropertyValue $SpObjectId -Force }
        if ($ClientSecretEnvVar) { $osc | Add-Member -NotePropertyName 'ClientSecretEnvVar' -NotePropertyValue $ClientSecretEnvVar -Force }

        # Re-attach in case above created a new PSCustomObject
        $cfgObj.OnlineSyncConfig = $osc

        $json = $cfgObj | ConvertTo-Json -Depth 8
        $json | Out-File -FilePath $OnlineConfigPath -Encoding UTF8 -Force
        Write-Log -Level 'INFO' -Message "Saved OnlineSyncConfig (no secrets) to: $OnlineConfigPath"
    } catch {
        Write-Log -Level 'WARN' -Message "Failed to save OnlineSyncConfig: $($_.Exception.Message)"
    }
}

function Ensure-DirectoryReadersRoleForSp {
    param([Parameter(Mandatory=$true)][string]$SpObjectId)
    Ensure-GraphModule
    Verify-GraphCommands
    $ok = Connect-GraphDelegated -Scopes @('RoleManagement.ReadWrite.Directory')
    if (-not $ok) { throw "Cannot assign Directory Readers role without delegated admin access." }
    # Try to get active Directory Readers role
    $role = Get-MgDirectoryRole -Filter "displayName eq 'Directory Readers'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $role) {
        # Activate from template if needed
        $tmpl = Get-MgDirectoryRoleTemplate -ErrorAction Stop | Where-Object { $_.DisplayName -eq 'Directory Readers' } | Select-Object -First 1
        if (-not $tmpl) { throw "Directory Readers role template not found." }
        $role = New-MgDirectoryRole -BodyParameter @{ roleTemplateId = $tmpl.Id } -ErrorAction Stop
    }
    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$SpObjectId" } -ErrorAction Stop | Out-Null
        Write-Log -Level 'RESULT' -Message "Assigned 'Directory Readers' to SP: $SpObjectId"
    } catch {
        # If already a member or other benign errors, warn and continue
        Write-Log -Level 'WARN' -Message "Directory Readers assignment may already exist or failed: $($_.Exception.Message)"
    }
}

function Print-SecuritySummary {
    param(
        [switch]$AppOnly,
        [switch]$CreatingApp
    )
    Write-Host ""; Write-Host "==== Entra ID Access & Security Summary ====" -ForegroundColor Cyan
    if ($AppOnly) {
        Write-Host "Mode: App-only (client credential flow)" -ForegroundColor Cyan
        Write-Host "Permissions: Microsoft Graph Application permissions 'User.Read.All' and 'Directory.Read.All'" -ForegroundColor Cyan
        Write-Host "Purpose: Read users and their mail/proxy attributes to sync into on-prem AD" -ForegroundColor Cyan
        Write-Host "Writes to Entra ID: None" -ForegroundColor Cyan
    } else {
        Write-Host "Mode: Delegated (interactive sign-in)" -ForegroundColor Cyan
        Write-Host "Permissions requested during sign-in: User.Read.All, Directory.Read.All (read-only)" -ForegroundColor Cyan
    }
    if ($CreatingApp) {
        Write-Host "App Registration creation: Requires delegated admin to create app & service principal and grant Graph 'User.Read.All' and 'Directory.Read.All' (Application)" -ForegroundColor Yellow
        Write-Host "Suggested admin roles during creation: Cloud Application Administrator and ability to grant admin consent (Privileged Role Administrator or Global Administrator)" -ForegroundColor Yellow
        Write-Host "Least privilege of created app: Graph 'User.Read.All' and 'Directory.Read.All' application permissions are granted." -ForegroundColor Yellow
    }
    Write-Host "Operational note: Client secret is NOT written to disk. Provide it via environment variable (e.g. %OPENIDSYNC_CLIENT_SECRET%)." -ForegroundColor DarkYellow
    Write-Host "==============================================" -ForegroundColor Cyan
}

function Print-AuthContextSummary {
    param(
        [switch]$AppOnly,
        [string]$TenantId,
        [string]$ClientId
    )
    try {
        $ctx = Get-MgContext
    } catch { $ctx = $null }

    Write-Host ""; Write-Host "==== Authentication Context Used ==== " -ForegroundColor Cyan
    if ($AppOnly -and $TenantId -and $ClientId) {
        $spInfo = $null
        try {
            # Best-effort to resolve SP by appId for display
            $spInfo = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue | Select-Object -First 1
        } catch {}
        $spName = if ($spInfo) { $spInfo.DisplayName } else { '(unknown display name)' }
        $spObjId = if ($spInfo) { $spInfo.Id } else { '(unknown SP object id)' }
        Write-Host ("Type       : App-only (Service Principal)") -ForegroundColor Cyan
        Write-Host ("App Name   : {0}" -f $spName)
        Write-Host ("Tenant Id  : {0}" -f $TenantId)
        Write-Host ("Client Id  : {0}" -f $ClientId)
        Write-Host ("SP Obj Id  : {0}" -f $spObjId)
    } else {
        # Delegated
        $userDisplay = $null; $upn = $null; $tenant = $null
        if ($ctx) {
            try { $tenant = $ctx.TenantId } catch {}
            try {
                $me = Get-MgUser -UserId 'me' -ErrorAction SilentlyContinue
                if ($me) { $userDisplay = $me.DisplayName; $upn = $me.UserPrincipalName }
            } catch {}
        }
        $dispOut = if ([string]::IsNullOrWhiteSpace($userDisplay)) { '(unknown)' } else { $userDisplay }
        $upnOut  = if ([string]::IsNullOrWhiteSpace($upn)) { '(unknown)' } else { $upn }
        Write-Host ("Type       : Delegated (interactive user)") -ForegroundColor Cyan
        Write-Host ("User       : {0}" -f $dispOut)
        Write-Host ("UPN/Email  : {0}" -f $upnOut)
        if ($tenant) { Write-Host ("Tenant Id  : {0}" -f $tenant) }
    }
    Write-Host "=======================================" -ForegroundColor Cyan
}

function Connect-GraphAppOnly {
    param(
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret
    )
    Ensure-GraphModule
    try {
        $cmd = Get-Command -Name Connect-MgGraph -ErrorAction Stop
        $paramNames = @()
        try { $paramNames = @($cmd.Parameters.Keys) } catch { $paramNames = @() }

        if ($paramNames -contains 'ClientSecret') {
            # Newer SDK supports -ClientSecret (string)
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -NoWelcome -ErrorAction Stop | Out-Null
        }
        elseif ($paramNames -contains 'ClientSecretCredential') {
            # Older SDK expects PSCredential (username: clientId, password: secret)
            $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop | Out-Null
        }
        else {
            throw "This version of Microsoft Graph SDK does not support client secret auth with Connect-MgGraph. Please update Microsoft.Graph.Authentication."
        }

        Write-Log -Level 'INFO' -Message "Connected to Microsoft Graph (App-Only)."
        $script:AuthMode = 'AppOnly'
        return $true
    } catch {
        Write-Log -Level 'ERROR' -Message "Failed to connect to Graph (App-Only): $($_.Exception.Message)"
        return $false
    }
}

function Connect-GraphDelegated {
    param([string[]]$Scopes = @('User.Read.All','Directory.Read.All'))
    Ensure-GraphModule
    try {
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
        Write-Log -Level 'INFO' -Message "Connected to Microsoft Graph (Delegated)."
        $script:AuthMode = 'Delegated'
        return $true
    } catch {
        Write-Log -Level 'ERROR' -Message "Failed to connect to Graph (Delegated): $($_.Exception.Message)"
        return $false
    }
}

function New-OpenIdSyncGraphApp {
    param(
        [string]$DisplayName = 'OpenIDSync_org__Entra_Sync_Windows_AD',
        [switch]$PersistToTmp
    )
    # Requires delegated admin: Application.ReadWrite.All and Directory.ReadWrite.All
    $ok = Connect-GraphDelegated -Scopes @('Application.ReadWrite.All','Directory.ReadWrite.All')
    if (-not $ok) { throw "Cannot create App Registration without Graph delegated admin access." }

    # Microsoft Graph service principal AppId
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    # App role IDs for required application permissions
    $graphSpObj = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    $userReadAllId = (
        $graphSpObj.AppRoles |
        Where-Object { $_.Value -eq 'User.Read.All' -and $_.AllowedMemberTypes -contains 'Application' }
    ).Id
    $directoryReadAllId = (
        $graphSpObj.AppRoles |
        Where-Object { $_.Value -eq 'Directory.Read.All' -and $_.AllowedMemberTypes -contains 'Application' }
    ).Id
    if (-not $userReadAllId) { throw "Could not locate Graph app role 'User.Read.All'" }
    if (-not $directoryReadAllId) { throw "Could not locate Graph app role 'Directory.Read.All'" }

    # Create application
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' -RequiredResourceAccess @(
        @{ ResourceAppId = $graphAppId; ResourceAccess = @(
            @{ Id = $userReadAllId; Type = 'Role' },
            @{ Id = $directoryReadAllId; Type = 'Role' }
        ) }
    ) -ErrorAction Stop
    Write-Log -Level 'ACTION' -Message "Created Azure AD application: $($app.AppId)"

    # Add service principal
    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Log -Level 'ACTION' -Message "Created service principal: $($sp.Id)"

    # Create client secret
    $appPwdResult = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ displayName = 'client-secret' } -ErrorAction Stop
    $clientSecret = $appPwdResult.SecretText

    # Admin consent: attempt to assign required application permissions to the SP on Graph
    try {
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $directoryReadAllId -ErrorAction Stop | Out-Null
            Write-Log -Level 'RESULT' -Message 'Granted application permission: Microsoft Graph Directory.Read.All'
        } catch {
            Write-Log -Level 'WARN' -Message "Admin consent for Graph Directory.Read.All failed: $($_.Exception.Message). A privileged admin must grant consent later."
        }
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $userReadAllId -ErrorAction Stop | Out-Null
            Write-Log -Level 'RESULT' -Message 'Granted application permission: Microsoft Graph User.Read.All'
        } catch {
            Write-Log -Level 'WARN' -Message "Admin consent for Graph User.Read.All failed: $($_.Exception.Message). A privileged admin must grant consent later."
        }
    } catch {
        Write-Log -Level 'WARN' -Message "Failed to locate Microsoft Graph service principal for admin consent: $($_.Exception.Message)"
        # Do not throw; continue and return IDs so caller can persist config and avoid re-creating app.
    }

    $tenantId = (Get-MgContext).TenantId
    $res = [pscustomobject]@{
        TenantId    = $tenantId
        ClientId    = $app.AppId
        ClientSecret= $clientSecret
        AppObjectId = $app.Id
        SpObjectId  = $sp.Id
    }

    if ($PersistToTmp) {
        $tmpDir = Join-Path -Path (Get-Location) -ChildPath 'tmp'
        if (-not (Test-Path -LiteralPath $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir | Out-Null }
        $outPath = Join-Path -Path $tmpDir -ChildPath 'openidsync_graph_app.json'
        $res | ConvertTo-Json | Out-File -FilePath $outPath -Encoding UTF8 -Force
        Write-Log -Level 'INFO' -Message "Graph app credentials saved to: $outPath (protect this file!)"
    }

    return $res
}

function Get-EntraUsersViaGraph {
    # Connect (app-only preferred if creds supplied; otherwise delegated)
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    $connected = $false
    if ($TenantId -and $ClientId -and $ClientSecret) {
        $connected = Connect-GraphAppOnly -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    }
    if (-not $connected) {
        $connected = Connect-GraphDelegated -Scopes @('User.Read.All','Directory.Read.All')
    }
    if (-not $connected) { throw "Unable to connect to Microsoft Graph." }

    # Print actual auth context used once connection is established
    if ($script:AuthMode -eq 'AppOnly') {
        Print-AuthContextSummary -AppOnly -TenantId $TenantId -ClientId $ClientId
    } else {
        Print-AuthContextSummary
    }

    Write-Log -Level 'ACTION' -Message 'Querying Entra ID users via Microsoft Graph...'
    $users = $null
    try {
        # Advanced query variant (count + consistency header) may require Directory.Read.All for app-only
        $users = Get-MgUser -All -ConsistencyLevel eventual -Count userCount -Property id,displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses,department,jobTitle,officeLocation,businessPhones,mobilePhone,city,state,postalCode,streetAddress,country,accountEnabled
    } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match 'Authorization_RequestDenied' -or $msg -match 'Insufficient privileges') {
            Write-Log -Level 'WARN' -Message 'App-only list with count/ConsistencyLevel was denied. Falling back to basic list (no $count). Consider granting Microsoft Graph Directory.Read.All (Application) for advanced queries.'
            $users = Get-MgUser -All -Property id,displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses,department,jobTitle,officeLocation,businessPhones,mobilePhone,city,state,postalCode,streetAddress,country,accountEnabled
        } else {
            throw
        }
    }

    $rows = @()
    foreach ($u in $users) {
        $proxy = $null
        if ($u.proxyAddresses) {
            # Join with '+' to match CSV parsing expectations
            $proxy = ($u.proxyAddresses -join '+')
        }
        $phone = $null; if ($u.businessPhones -and $u.businessPhones.Count -gt 0) { $phone = [string]$u.businessPhones[0] }
        $blocked = if ($u.AccountEnabled -eq $false) { 'true' } else { 'false' }
        $row = [pscustomobject]@{
            'User principal name'   = [string]$u.userPrincipalName
            'First name'            = [string]$u.givenName
            'Last name'             = [string]$u.surname
            'Display name'          = [string]$u.displayName
            'Department'            = [string]$u.department
            'Title'                 = [string]$u.jobTitle
            'Office'                = [string]$u.officeLocation
            'City'                  = [string]$u.city
            'StateOrProvince'       = [string]$u.state
            'Postal code'           = [string]$u.postalCode
            'Street address'        = [string]$u.streetAddress
            'CountryOrRegion'       = [string]$u.country
            'Phone number'          = [string]$phone
            'Mobile Phone'          = [string]$u.mobilePhone
            'Proxy addresses'       = [string]$proxy
            'Block credential'      = [string]$blocked
            'Password never expires'= 'false'
        }
        $rows += $row
    }
    Write-Log -Level 'RESULT' -Message ("Entra users fetched: {0}" -f $rows.Count)
    return $rows
}

function New-RandomPassword {
    param([int]$Length = 16)
    # Ensure complexity: at least 1 upper, 1 lower, 1 digit, 1 special
    $upper = 65..90 | ForEach-Object {[char]$_}
    $lower = 97..122 | ForEach-Object {[char]$_}
    $digits = 48..57 | ForEach-Object {[char]$_}
    $special = '!@#$%^&*()-_=+[]{}:,./?'.ToCharArray()

    $all = $upper + $lower + $digits + $special

    $passChars = @()
    $passChars += ($upper | Get-Random)
    $passChars += ($lower | Get-Random)
    $passChars += ($digits | Get-Random)
    $passChars += ($special | Get-Random)

    for ($i = $passChars.Count; $i -lt $Length; $i++) {
        $passChars += ($all | Get-Random)
    }

    # Shuffle
    -join ($passChars | Sort-Object {Get-Random})
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT')]
        [string]$Level = 'INFO'
    )
    try {
        Write-Syslog -Message $Message -Level $Level -MsgId '-' -Data $null
    } catch {
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "[$ts] [$Level] $Message"
        if ($script:AuditLogPath) { $line | Out-File -FilePath $script:AuditLogPath -Encoding UTF8 -Append }
        Write-Host $line
    }
}

function Write-CredentialLog {
    param(
        [string]$Email,
        [string]$UserPrincipalName,
        [string]$SamAccountName,
        [string]$Password
    )
    "$Email,$UserPrincipalName,$SamAccountName,$Password" | Out-File -FilePath $script:CredLogPath -Encoding UTF8 -Append
}

function Add-Summary {
    param([string]$Key)
    if (-not $script:Summary) { $script:Summary = @{} }
    $current = $script:Summary[$Key]
    if ($null -ne $current) {
        $script:Summary[$Key] = [int]$current + 1
    }
    else {
        $script:Summary[$Key] = 1
    }
}

function Show-UserCard {
    param($Row)
    Write-Host ""
    Write-Host "-------------------- USER PREVIEW --------------------" -ForegroundColor Cyan
    foreach ($p in $Row.PSObject.Properties) {
        $name = $p.Name
        $val = [string]$p.Value
        Write-Host ("{0,-28}: {1}" -f $name, $val)
    }
    # Preview sAMAccountName candidate derived from UPN local part (pre-Windows 2000)
    try {
        $upnLocalPreview = ([string]$Row.'User principal name').Split('@')[0].ToLower()
        $basePreview = if ($upnLocalPreview.Length -gt 20) { Get-Pre2000SamCandidate -UpnLocalPart $upnLocalPreview } else { $upnLocalPreview }
        $dispPreview = if ($basePreview.Length -gt 20) { $basePreview.Substring(0,20) } else { $basePreview }
        Write-Host ("{0,-28}: {1}" -f 'sAMAccountName (candidate)', $dispPreview)
    } catch {}
    Write-Host "------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Welcome {
    param([string]$Source)
    try {
        if ($Source -ne 'Online') { return }
        $hasAppIds = ($TenantId -and $ClientId)
        $envName = if ($ClientSecretEnvVar) { [string]$ClientSecretEnvVar } else { 'OPENIDSYNC_CLIENT_SECRET' }
        $envProc = [Environment]::GetEnvironmentVariable($envName, 'Process')
        $envUser = [Environment]::GetEnvironmentVariable($envName, 'User')
        $secretPresent = (-not [string]::IsNullOrWhiteSpace($envProc)) -or (-not [string]::IsNullOrWhiteSpace($envUser))

        Write-Host ""; Write-Host "==== Welcome to OpenIDSync — Getting ready for daily use ====" -ForegroundColor Cyan
        $flow = @(
            'Online onboarding flow:',
            '  1) Delegated sign-in (interactive) — first run',
            ('  2) Create App Registration + Service Principal, print secret; set env var {0}' -f $envName),
            '  3) App-only (Service Principal) — subsequent runs'
        )
        foreach ($l in $flow) { Write-Host $l; Write-Log -Level 'INFO' -Message $l }

        $status = @()
        if (-not $hasAppIds) {
            $status += 'Status: No App Registration found in OnlineSyncConfig. This run will use delegated sign-in.'
            $status += 'Tip: Add -AutoInstallGraphModules and optionally -AutoCreateGraphApp to create the app now.'
        } elseif ($hasAppIds -and -not $secretPresent) {
            $status += ("Status: App Registration detected, but client secret env var '{0}' is not set." -f $envName)
            $status += 'Action: Set the secret and open a NEW PowerShell window:'
            $status += ("        setx {0} `"YOUR_SECRET_HERE`"" -f $envName)
            $status += '        or run .\97_Set_OPENIDSYNC_CLIENT_SECRET.ps1'
        } else {
            $status += 'Status: App Registration and client secret found — App-only (Service Principal) is ready.'
        }
        if ($script:OnlineSyncConfigPath) {
            $status += ("Online sync IDs file: {0}" -f $script:OnlineSyncConfigPath)
        }
        $status += 'Reset cached tokens if switching modes: .\98_Reset_Azure_Login_Session.ps1'
        foreach ($l in $status) { Write-Host $l; Write-Log -Level 'INFO' -Message $l }
        Write-Host ('{0}' -f ('=' * 58)) -ForegroundColor Cyan; Write-Host ''
    } catch {}
}

function Get-PrimarySmtpFromProxyAddresses {
    param([string]$ProxyString)
    if ([string]::IsNullOrWhiteSpace($ProxyString)) { return $null }
    $items = $ProxyString -split '\+'
    $primary = $items | Where-Object { $_ -like 'SMTP:*' } | Select-Object -First 1
    if ($primary) { return $primary.Substring(5) }
    $any = $items | Where-Object { $_ -like 'smtp:*' } | Select-Object -First 1
    if ($any) { return $any.Substring(5) }
    return $null
}

function Normalize-Bool {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $false }
    $s = $Value.ToString().Trim()
    return @('true','1','yes','y') -contains $s.ToLower()
}

function Get-ADUserByEmail {
    param([string]$Email)
    if ([string]::IsNullOrWhiteSpace($Email)) { return $null }
    $emailLc = $Email.Trim().ToLower()
    # First try mail attribute exact
    $u = Get-ADUser -Filter "mail -eq '$emailLc'" -Properties mail,proxyAddresses,description,displayName,givenName,sn,userPrincipalName,samAccountName,department,title,telephoneNumber,mobile,l,st,postalCode,streetAddress,co,c -ErrorAction SilentlyContinue
    if ($u) { return $u }
    # Then try proxyAddresses contains
    $needle1 = "smtp:$emailLc"
    $needle2 = "SMTP:$emailLc"
    $candidates = Get-ADUser -Filter * -Properties proxyAddresses -ErrorAction SilentlyContinue | Where-Object {
        $_.proxyAddresses -and ($_.proxyAddresses -contains $needle1 -or $_.proxyAddresses -contains $needle2)
    }
    return $candidates | Select-Object -First 1
}

function Next-AvailableSam {
    param([string]$BaseSam)
    if ($BaseSam.Length -gt 20) {
        $orig = $BaseSam
        $sam = $BaseSam.Substring(0,20)
        try { Write-Log -Level 'WARN' -Message ("sAMAccountName base > 20 chars; truncating: '{0}' (len {1}) -> '{2}' (len {3})" -f $orig, $orig.Length, $sam, $sam.Length) } catch {}
    } else {
        $sam = $BaseSam
    }
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        return $sam
    }
    for ($i=1; $i -lt 1000; $i++) {
        $candidate = $sam
        $suffix = $i.ToString()
        $maxBase = 20 - $suffix.Length
        if ($candidate.Length -gt $maxBase) { $candidate = $candidate.Substring(0,$maxBase) }
        $candidate = "$candidate$suffix"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$candidate'" -ErrorAction SilentlyContinue)) {
            return $candidate
        }
    }
    throw "Unable to find available sAMAccountName based on '$BaseSam'"
}

function Get-Pre2000SamCandidate {
    param([Parameter(Mandatory=$true)][string]$UpnLocalPart)
    # Start from the local part (before @), lowercased
    $candidate = $UpnLocalPart.ToLower()

    # If already within the 20-char sAMAccountName limit, keep as-is
    if ($candidate.Length -le 20) { return $candidate }

    # Split into left/right by the first dot (e.g., last.first)
    $dotIdx = $candidate.IndexOf('.')
    $left = $candidate
    $right = ''
    if ($dotIdx -gt 0) {
        $left = $candidate.Substring(0, $dotIdx)
        $right = $candidate.Substring($dotIdx + 1)
    }

    # If left part has a dash, compress everything after the first dash to a single initial
    # Example: "macskasy-denes" -> "macskasy-d"
    $dashIdx = $left.IndexOf('-')
    if ($dashIdx -gt 0 -and ($dashIdx + 1) -lt $left.Length) {
        $initial = $left.Substring($dashIdx + 1, 1)
        $left = $left.Substring(0, $dashIdx + 1) + $initial
    }

    # Recombine (preserve format with dot if it existed)
    $compressed = if ($dotIdx -gt 0) { "$left.$right" } else { $left }
    return $compressed
}

function Get-NextDescription {
    param([string]$Existing)
    $count = 0
    if ($Existing -and $Existing -match '\[Update count:\s*(\d+)\]') {
        $count = [int]$matches[1]
    }
    $count++
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $src = if ($script:SourceLabel) { [string]$script:SourceLabel } else { 'Unknown' }
    return "[Last update: $ts] [Update count: $count] [Source: $src] [openidsync.org]"
}

function Process-User {
    param($Row, [string]$DefaultOU, [switch]$ProcessAll)

    $upn = ($Row.'User principal name' | ForEach-Object { $_.Trim() })
    $first = $Row.'First name'
    $last = $Row.'Last name'
    $display = if ($Row.'Display name') { $Row.'Display name' } elseif ($first -or $last) { "$first $last" } else { $upn.Split('@')[0] }
    $department = $Row.'Department'
    $title = $Row.'Title'
    $office = $Row.'Office'
    $city = $Row.'City'
    $state = $Row.'StateOrProvince'
    $postal = $Row.'Postal code'
    $street = $Row.'Street address'
    $countryOrRegion = $Row.'CountryOrRegion'
    $phone = $Row.'Phone number'
    $mobile = $Row.'Mobile Phone'
    $proxyString = $Row.'Proxy addresses'
    $primarySmtp = Get-PrimarySmtpFromProxyAddresses -ProxyString $proxyString
    $email = if ($primarySmtp) { $primarySmtp } else { $upn }
    $blocked = Normalize-Bool $Row.'Block credential'
    $pwdNeverExpires = Normalize-Bool $Row.'Password never expires'

    if ([string]::IsNullOrWhiteSpace($upn)) {
        Write-Log -Level 'WARN' -Message "Skipping row with empty UPN."
        Add-Summary 'SkippedEmptyUPN'
        return
    }

    # Skip based on UPN tokens from config
    if ($script:SkipUpnTokens -and $script:SkipUpnTokens.Count -gt 0) {
        $upnLc = $upn.ToLower()
        foreach ($tok in $script:SkipUpnTokens) {
            if (-not [string]::IsNullOrWhiteSpace($tok)) {
                $tokLc = ([string]$tok).ToLower()
                if ($upnLc -like "*${tokLc}*") {
                    Write-Log -Level 'RESULT' -Message "Skipped by UPN token '${tok}': ${upn}"
                    Add-Summary 'SkippedByUPN'
                    return
                }
            }
        }
    }

    # Skip based on Display name tokens from config
    if ($script:SkipDisplayNameTokens -and $script:SkipDisplayNameTokens.Count -gt 0 -and $display) {
        $dispLc = $display.ToLower()
        foreach ($tok in $script:SkipDisplayNameTokens) {
            if (-not [string]::IsNullOrWhiteSpace($tok)) {
                $tokLc = $tok.ToLower()
                if ($dispLc -like "*${tokLc}*") {
                    Write-Log -Level 'RESULT' -Message "Skipped by DisplayName token '${tok}': ${display} (${upn})"
                    Add-Summary 'SkippedByDisplayName'
                    return
                }
            }
        }
    }

    Show-UserCard -Row $Row

    $proceed = $false
    $skippedByPrompt = $false
    if ($script:ProcessAll -or $script:NonInteractive) {
        $proceed = $true
    } else {
        $q = "Do you want to import user $first $last ($upn) [Y]es/[N]o/[A]ll/[Q]uit"
        $answer = Read-Host $q
        Write-Log -Level 'PROMPT' -Message "$q -> [$answer]"
        switch ($answer.ToUpper()) {
            'Y' { $proceed = $true }
            'YES' { $proceed = $true }
            'A' { $proceed = $true; $script:ProcessAll = $true }
            'ALL' { $proceed = $true; $script:ProcessAll = $true }
            'Q' { $script:QuitRequested = $true; $proceed = $false }
            'QUIT' { $script:QuitRequested = $true; $proceed = $false }
            'N' { $proceed = $false; $skippedByPrompt = $true }
            'NO' { $proceed = $false; $skippedByPrompt = $true }
            default { $proceed = $false; $skippedByPrompt = $true }
        }
    }

    if (-not $proceed) {
        if (-not $script:QuitRequested -and $skippedByPrompt) { Add-Summary 'SkippedPrompt' }
        Write-Log -Level 'RESULT' -Message "Skipped: $upn"
        return
    }

    $existing = Get-ADUserByEmail -Email $email

    if ($existing) {
        if ($existing.SamAccountName -ieq 'administrator') {
            Write-Log -Level 'WARN' -Message "Skip managing 'administrator' account."
            Add-Summary 'SkippedAdministrator'
            return
        }

        $desc = Get-NextDescription -Existing $existing.Description
        $proxyAddrs = @()
        if ($proxyString) {
                $proxyAddrs = @($proxyString -split '\+') | Where-Object { $_ -match 'smtp:' } | ForEach-Object { [string]$_.Trim() } | Sort-Object -Unique
        }

        Write-Log -Level 'ACTION' -Message "Updating existing AD user: $($existing.SamAccountName) ($email)"
        try {
            Set-ADUser -Identity $existing.DistinguishedName `
                -UserPrincipalName $upn `
                -GivenName $first `
                -Surname $last `
                -DisplayName $display `
                -EmailAddress $email `
                -Department $department `
                -Title $title `
                -Office $office `
                -City $city `
                -State $state `
                -PostalCode $postal `
                -StreetAddress $street `
                -MobilePhone $mobile `
                -OfficePhone $phone `
                -Description $desc

            if ($proxyAddrs.Count -gt 0) {
                try { Set-ADUser -Identity $existing.DistinguishedName -Replace @{ proxyAddresses = ([string[]]$proxyAddrs) } -ErrorAction Stop }
                catch { Write-Log -Level 'WARN' -Message "Failed to set proxyAddresses for ${upn}: $($_.Exception.Message)" }
            }

            if ($pwdNeverExpires) {
                Set-ADUser -Identity $existing.DistinguishedName -PasswordNeverExpires $true -ErrorAction SilentlyContinue
            } else {
                Set-ADUser -Identity $existing.DistinguishedName -PasswordNeverExpires $false -ErrorAction SilentlyContinue
            }

            if ($blocked) {
                Disable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue
            } else {
                Enable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue
            }

            # Set country friendly name (co) if provided
            if ($countryOrRegion) {
                try { Set-ADUser -Identity $existing.DistinguishedName -Replace @{ co = [string]$countryOrRegion } -ErrorAction SilentlyContinue } catch { Write-Log -Level 'WARN' -Message "Failed to set country (co) for ${upn}: $($_.Exception.Message)" }
            }

            Write-Log -Level 'RESULT' -Message "Updated: $upn"
            Add-Summary 'Updated'
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Failed to update ${upn}: $($_.Exception.Message)"
            Add-Summary 'FailedUpdate'
        }
    }
    else {
        # Create new user
        $baseUpnLocal = ($upn.Split('@')[0]).ToLower()
        $baseSam = $baseUpnLocal
        if ($baseUpnLocal.Length -gt 20) {
            $compressed = Get-Pre2000SamCandidate -UpnLocalPart $baseUpnLocal
            if ($compressed -ne $baseUpnLocal) {
                Write-Log -Level 'WARN' -Message ("sAMAccountName base exceeded 20 chars; compressing dashed surname: '{0}' (len {1}) -> '{2}' (len {3})" -f $baseUpnLocal, $baseUpnLocal.Length, $compressed, $compressed.Length)
                $baseSam = $compressed
            }
        }
        $sam = Next-AvailableSam -BaseSam $baseSam
        if ($sam -ieq 'administrator') {
            Write-Log -Level 'WARN' -Message "Skip creating user with sAMAccountName 'administrator'."
            Add-Summary 'SkippedAdministrator'
            return
        }

        $desc = Get-NextDescription -Existing $null
        $proxyAddrs = @()
        if ($proxyString) {
                $proxyAddrs = @($proxyString -split '\+') | Where-Object { $_ -match 'smtp:' } | ForEach-Object { [string]$_.Trim() } | Sort-Object -Unique
        }

        $passwordPlain = New-RandomPassword -Length 16
        $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

    Write-Log -Level 'INFO' -Message ("sAMAccountName chosen: {0}" -f $sam)
    Write-Log -Level 'ACTION' -Message "Creating AD user: $sam ($email) in OU: $DefaultOU"
        # Create first; if it fails, do not attempt post-creation updates
        try {
            New-ADUser `
                -SamAccountName $sam `
                -UserPrincipalName $upn `
                -Name $display `
                -DisplayName $display `
                -GivenName $first `
                -Surname $last `
                -EmailAddress $email `
                -Department $department `
                -Title $title `
                -Office $office `
                -City $city `
                -State $state `
                -PostalCode $postal `
                -StreetAddress $street `
                -Enabled ($blocked -eq $false) `
                -ChangePasswordAtLogon $false `
                -AccountPassword $password `
                -Path $DefaultOU `
                -Description $desc

            # Credentials must be logged immediately upon successful creation
            Write-CredentialLog -Email $email -UserPrincipalName $upn -SamAccountName $sam -Password $passwordPlain
            Write-Log -Level 'RESULT' -Message "Created: $upn"
            Add-Summary 'Created'
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Failed to create ${upn}: $($_.Exception.Message)"
            Add-Summary 'FailedCreate'
            return
        }

        # Post-creation updates (best-effort; do not affect credentials logging)
        try {
            if ($proxyAddrs.Count -gt 0) {
                $newly = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Properties proxyAddresses
                if ($newly) {
                    Set-ADUser -Identity $newly.DistinguishedName -Replace @{ proxyAddresses = ([string[]]$proxyAddrs) } -ErrorAction Stop
                }
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Failed to set proxyAddresses for ${upn}: $($_.Exception.Message)"
        }

        try {
            $newly2 = Get-ADUser -Filter "SamAccountName -eq '$sam'"
            if ($newly2) {
                Set-ADUser -Identity $newly2.DistinguishedName -PasswordNeverExpires $pwdNeverExpires -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Failed to set PasswordNeverExpires for ${upn}: $($_.Exception.Message)"
        }
    }
}

function Suggest-Removals {
    param([string]$DefaultOU, [string[]]$CsvEmails)
    try {
        $csvSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $CsvEmails | Where-Object { $_ } | ForEach-Object { [void]$csvSet.Add($_) }

        $adUsers = Get-ADUser -SearchBase $DefaultOU -LDAPFilter "(objectClass=user)" -Properties mail,description,displayName,samAccountName,userPrincipalName | Where-Object {
            $_.mail -and $_.SamAccountName -ne 'administrator'
        }

        $candidates = @()
        foreach ($u in $adUsers) {
            if (-not $csvSet.Contains($u.mail)) {
                $isManaged = ($u.Description -like '*[openidsync.org]*')
                if (-not $isManaged) {
                    $candidates += $u
                }
            }
        }

        if ($candidates.Count -gt 0) {
            Write-Host ""
            Write-Host "Users in $DefaultOU not found in CSV and not managed by this tool (suggest review/removal):" -ForegroundColor Yellow
            foreach ($u in $candidates) {
                $msg = "Suggest removal -> sAM: $($u.SamAccountName), UPN: $($u.UserPrincipalName), Mail: $($u.mail), Name: $($u.DisplayName)"
                Write-Host $msg
                Write-Log -Level 'INFO' -Message $msg
            }
            Write-Host ""
        } else {
            Write-Log -Level 'INFO' -Message "No un-managed AD users (with mail) in $DefaultOU are missing from CSV."
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message "Suggest-Removals failed: $($_.Exception.Message)"
    }
}

# ==================== Main ====================

try {
    Ensure-Module -Name ActiveDirectory
}
catch { throw }

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
            Ensure-GraphModule
            Verify-GraphCommands
            Print-SecuritySummary -CreatingApp
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
                Ensure-DirectoryReadersRoleForSp -SpObjectId $appInfo.SpObjectId
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Auto app registration failed: $($_.Exception.Message). Falling back to delegated sign-in."
        }
    }
    # If requested and credentials provided for an existing app, assign Directory Readers to its SP
    if ($AssignDirectoryReaderToApp -and $ClientId) {
        try {
            Ensure-GraphModule
            Verify-GraphCommands
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
                if ($spIdToUse) { Ensure-DirectoryReadersRoleForSp -SpObjectId $spIdToUse }
                else { Write-Log -Level 'WARN' -Message "Service principal not found for appId: $ClientId" }
            }
        } catch {
            Write-Log -Level 'WARN' -Message "Failed to assign Directory Readers to existing app: $($_.Exception.Message)"
        }
    }
    try {
        Ensure-GraphModule
        Verify-GraphCommands
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
        if ($TenantId -and $ClientId -and $ClientSecret) { Print-SecuritySummary -AppOnly }
        else { Print-SecuritySummary }
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
    # Import CSV (new M365 Admin export format)
    $rows = Import-Csv -LiteralPath $CsvPath
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
}

# Process users
foreach ($row in $rows) {
    # Calculate UPN early for prompt text
    $upn = $row.'User principal name'
    $first = $row.'First name'
    $last = $row.'Last name'

    Process-User -Row $row -DefaultOU $DefaultOU

    if ($script:QuitRequested) {
        Write-Log -Level 'INFO' -Message 'Quit requested by user. Stopping import.'
        break
    }
}

# Suggest removals (not deleting, only suggesting)
if (-not $NoSuggestRemovals -and -not $script:QuitRequested) {
    $csvEmails = $rows | ForEach-Object {
        $p = Get-PrimarySmtpFromProxyAddresses -ProxyString $_.'Proxy addresses'
        if ($p) { $p } else { $_.'User principal name' }
    }
    Suggest-Removals -DefaultOU $DefaultOU -CsvEmails $csvEmails
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

