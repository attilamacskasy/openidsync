# Microsoft Graph helpers and Online source

# Submodule list for minimal import
$script:GraphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Groups'
)

# Increase function capacity for Windows PowerShell 5.1
try {
    $targetFuncCap = 32768
    if ($MaximumFunctionCount -lt $targetFuncCap) {
        try { Set-Variable -Name MaximumFunctionCount -Value $targetFuncCap -Scope Global -Force } catch {}
        try { $global:MaximumFunctionCount = $targetFuncCap } catch {}
        try { $MaximumFunctionCount = $targetFuncCap } catch {}
    }
} catch {}

function Install-GraphModules {
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

function Import-GraphModules {
    $required = $script:GraphModules
    $available = @()
    foreach ($r in $required) { if (Get-Module -ListAvailable -Name $r) { $available += $r } }
    if ($available.Count -lt $required.Count) {
        if ($script:AutoInstallGraphModules -or $script:NonInteractive) {
            $ok = Install-GraphModules
            if (-not $ok) { throw "Missing Graph modules (see $script:GraphModules list)" }
        } else {
            Write-Host "Microsoft Graph PowerShell is required for Online mode. Required submodules:" -ForegroundColor Yellow
            $listText = (" - " + ($required -join "`n - "))
            Write-Host $listText -ForegroundColor Yellow
            $installText = ("Install with: Install-Module {0} -Scope CurrentUser" -f ($required -join ','))
            Write-Host $installText -ForegroundColor Yellow
            $ans = Read-Host "Install required submodules now? [Y]es/[N]o"
            if ($ans -match '^(?i:y|yes)$') {
                $ok = Install-GraphModules
                if (-not $ok) { throw "Missing Graph modules (see $script:GraphModules list)" }
            } else {
                throw "Missing Graph modules (see $script:GraphModules list)"
            }
        }
    }
    foreach ($m in $required) { Import-Module $m -ErrorAction Stop }
    Write-Log -Level 'INFO' -Message ("Imported Graph submodules: {0}" -f ($required -join ', '))
}

function Test-GraphCommands {
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

function Show-SecuritySummary {
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

function Show-AuthContextSummary {
    param(
        [switch]$AppOnly,
        [string]$TenantId,
        [string]$ClientId
    )
    try { $ctx = Get-MgContext } catch { $ctx = $null }

    Write-Host ""; Write-Host "==== Authentication Context Used ==== " -ForegroundColor Cyan
    if ($AppOnly -and $TenantId -and $ClientId) {
        $spInfo = $null
        try { $spInfo = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
        $spName = if ($spInfo) { $spInfo.DisplayName } else { '(unknown display name)' }
        $spObjId = if ($spInfo) { $spInfo.Id } else { '(unknown SP object id)' }
        Write-Host ("Type       : App-only (Service Principal)") -ForegroundColor Cyan
        Write-Host ("App Name   : {0}" -f $spName)
        Write-Host ("Tenant Id  : {0}" -f $TenantId)
        Write-Host ("Client Id  : {0}" -f $ClientId)
        Write-Host ("SP Obj Id  : {0}" -f $spObjId)
    } else {
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
    Import-GraphModules
    try {
        $cmd = Get-Command -Name Connect-MgGraph -ErrorAction Stop
        $paramNames = @()
        try { $paramNames = @($cmd.Parameters.Keys) } catch { $paramNames = @() }

        if ($paramNames -contains 'ClientSecret') {
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -NoWelcome -ErrorAction Stop | Out-Null
        }
        elseif ($paramNames -contains 'ClientSecretCredential') {
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
    Import-GraphModules
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
    $ok = Connect-GraphDelegated -Scopes @('Application.ReadWrite.All','Directory.ReadWrite.All')
    if (-not $ok) { throw "Cannot create App Registration without Graph delegated admin access." }

    $graphAppId = '00000003-0000-0000-c000-000000000000'
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

    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' -RequiredResourceAccess @(
        @{ ResourceAppId = $graphAppId; ResourceAccess = @(
            @{ Id = $userReadAllId; Type = 'Role' },
            @{ Id = $directoryReadAllId; Type = 'Role' }
        ) }
    ) -ErrorAction Stop
    Write-Log -Level 'ACTION' -Message "Created Azure AD application: $($app.AppId)"

    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Log -Level 'ACTION' -Message "Created service principal: $($sp.Id)"

    $appPwdResult = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ displayName = 'client-secret' } -ErrorAction Stop
    $clientSecret = $appPwdResult.SecretText

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

function Grant-DirectoryReadersToServicePrincipal {
    param([Parameter(Mandatory=$true)][string]$SpObjectId)
    Import-GraphModules
    Test-GraphCommands
    $ok = Connect-GraphDelegated -Scopes @('RoleManagement.ReadWrite.Directory')
    if (-not $ok) { throw "Cannot assign Directory Readers role without delegated admin access." }
    $role = Get-MgDirectoryRole -Filter "displayName eq 'Directory Readers'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $role) {
        $tmpl = Get-MgDirectoryRoleTemplate -ErrorAction Stop | Where-Object { $_.DisplayName -eq 'Directory Readers' } | Select-Object -First 1
        if (-not $tmpl) { throw "Directory Readers role template not found." }
        $role = New-MgDirectoryRole -BodyParameter @{ roleTemplateId = $tmpl.Id } -ErrorAction Stop
    }
    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$SpObjectId" } -ErrorAction Stop | Out-Null
        Write-Log -Level 'RESULT' -Message "Assigned 'Directory Readers' to SP: $SpObjectId"
    } catch {
        Write-Log -Level 'WARN' -Message "Directory Readers assignment may already exist or failed: $($_.Exception.Message)"
    }
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

        Write-Host ""; Write-Host "==== Welcome to OpenIDSync - Getting ready for daily use ====" -ForegroundColor Cyan
        Write-Host "Online onboarding flow:"; Write-Log -Level 'INFO' -Message 'Online onboarding flow:'
        Write-Host "  1) Delegated sign-in (interactive) - first run"; Write-Log -Level 'INFO' -Message '1) Delegated sign-in (interactive) - first run'
        Write-Host ("  2) Create App Registration + Service Principal, print secret; set env var {0}" -f $envName); Write-Log -Level 'INFO' -Message ("2) Create App Registration + Service Principal, print secret; set env var {0}" -f $envName)
        Write-Host "  3) App-only (Service Principal) - subsequent runs"; Write-Log -Level 'INFO' -Message '3) App-only (Service Principal) - subsequent runs'

        $status = @()
        if (-not $hasAppIds) {
            $status += 'Status: No App Registration found in OnlineSyncConfig. This run will use delegated sign-in.'
            $status += 'Tip: Add -AutoInstallGraphModules and optionally -AutoCreateGraphApp to create the app now.'
    } elseif ($hasAppIds -and -not $secretPresent) {
            $status += ("Status: App Registration detected, but client secret env var '{0}' is not set." -f $envName)
            $status += 'Action: Set the secret and open a NEW PowerShell window:'
            $status += ("        setx {0} `"YOUR_SECRET_HERE`"" -f $envName)
            $status += '        or run .\\97_Set_OPENIDSYNC_CLIENT_SECRET.ps1'
        } else {
            $status += 'Status: App Registration and client secret found - App-only (Service Principal) is ready.'
        }
        if ($script:OnlineSyncConfigPath) { $status += ("Online sync IDs file: {0}" -f $script:OnlineSyncConfigPath) }
        $status += 'Reset cached tokens if switching modes: .\98_Reset_Azure_Login_Session.ps1'
        foreach ($l in $status) { Write-Host $l; Write-Log -Level 'INFO' -Message $l }
        Write-Host ('{0}' -f ('=' * 58)) -ForegroundColor Cyan; Write-Host ''
    } catch {}
}

function Get-EntraUsersViaGraph {
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

    if ($script:AuthMode -eq 'AppOnly') { Show-AuthContextSummary -AppOnly -TenantId $TenantId -ClientId $ClientId }
    else { Show-AuthContextSummary }

    Write-Log -Level 'ACTION' -Message 'Querying Entra ID users via Microsoft Graph...'
    $users = $null
    try {
        $users = Get-MgUser -All -ConsistencyLevel eventual -Count userCount -Property id,displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses,department,jobTitle,officeLocation,businessPhones,mobilePhone,city,state,postalCode,streetAddress,country,accountEnabled
    } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match 'Authorization_RequestDenied' -or $msg -match 'Insufficient privileges') {
            Write-Log -Level 'WARN' -Message 'App-only list with count/ConsistencyLevel was denied. Falling back to basic list (no $count). Consider granting Microsoft Graph Directory.Read.All (Application) for advanced queries.'
            $users = Get-MgUser -All -Property id,displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses,department,jobTitle,officeLocation,businessPhones,mobilePhone,city,state,postalCode,streetAddress,country,accountEnabled
        } else { throw }
    }

    $rows = @()
    foreach ($u in $users) {
        $proxy = $null
        if ($u.proxyAddresses) { $proxy = ($u.proxyAddresses -join '+') }
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

# Note: This is a dot-sourced script, not a module. Do not export members here.
