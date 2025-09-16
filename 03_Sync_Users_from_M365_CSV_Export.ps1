param(
    [string]$CsvPath,
    [string]$DefaultOU,
    [switch]$NoSuggestRemovals,
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath '00_OpenIDSync_Config.json')
)

# ==================== Helpers ====================

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Please install RSAT Active Directory tools and try again." -ForegroundColor Yellow
        throw "Missing module: $Name"
    }
    Import-Module $Name -ErrorAction Stop
}

function New-RandomPassword {
    param([int]$Length = 16)
    # Ensure complexity: at least 1 upper, 1 lower, 1 digit, 1 special
    $upper = 65..90 | ForEach-Object {[char]$_}
    $lower = 97..122 | ForEach-Object {[char]$_}
    $digits = 48..57 | ForEach-Object {[char]$_}
    $special = '!@#$%^&*()-_=+[]{}:,./?'.ToCharArray()

    $all = $upper + $lower + $digits + $special

    $pwd = @()
    $pwd += ($upper | Get-Random)
    $pwd += ($lower | Get-Random)
    $pwd += ($digits | Get-Random)
    $pwd += ($special | Get-Random)

    for ($i = $pwd.Count; $i -lt $Length; $i++) {
        $pwd += ($all | Get-Random)
    }

    # Shuffle
    -join ($pwd | Sort-Object {Get-Random})
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT')]
        [string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    $line | Out-File -FilePath $script:AuditLogPath -Encoding UTF8 -Append
    Write-Host $line
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

function Show-UserCard {
    param($Row)
    Write-Host ""
    Write-Host "-------------------- USER PREVIEW --------------------" -ForegroundColor Cyan
    foreach ($p in $Row.PSObject.Properties) {
        $name = $p.Name
        $val = [string]$p.Value
        Write-Host ("{0,-28}: {1}" -f $name, $val)
    }
    Write-Host "------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
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
    $sam = if ($BaseSam.Length -gt 20) { $BaseSam.Substring(0,20) } else { $BaseSam }
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

function Get-NextDescription {
    param([string]$Existing)
    $count = 0
    if ($Existing -and $Existing -match '\[Update count:\s*(\d+)\]') {
        $count = [int]$matches[1]
    }
    $count++
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    return "[Last update: $ts] [Update count: $count] [openidsync.org]"
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
        return
    }

    Show-UserCard -Row $Row

    $proceed = $false
    if ($script:ProcessAll) {
        $proceed = $true
    } else {
        $q = "Do you want to import user $first $last ($upn) [Y]es/[N]o/[A]ll"
        $answer = Read-Host $q
        Write-Log -Level 'PROMPT' -Message "$q -> [$answer]"
        switch ($answer.ToUpper()) {
            'Y' { $proceed = $true }
            'YES' { $proceed = $true }
            'A' { $proceed = $true; $script:ProcessAll = $true }
            'ALL' { $proceed = $true; $script:ProcessAll = $true }
            default { $proceed = $false }
        }
    }

    if (-not $proceed) {
        Write-Log -Level 'RESULT' -Message "Skipped: $upn"
        return
    }

    $existing = Get-ADUserByEmail -Email $email

    if ($existing) {
        if ($existing.SamAccountName -ieq 'administrator') {
            Write-Log -Level 'WARN' -Message "Skip managing 'administrator' account."
            return
        }

        $desc = Get-NextDescription -Existing $existing.Description
        $proxyAddrs = @()
        if ($proxyString) {
            $proxyAddrs = ($proxyString -split '\+') | Where-Object { $_ -match 'smtp:' } | ForEach-Object { $_.Trim() } | Select-Object -Unique
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
                -Country $countryOrRegion `
                -MobilePhone $mobile `
                -OfficePhone $phone `
                -Description $desc

            if ($proxyAddrs.Count -gt 0) {
                Set-ADUser -Identity $existing.DistinguishedName -Replace @{ proxyAddresses = $proxyAddrs } -ErrorAction SilentlyContinue
            }

            if ($pwdNeverExpires) {
                Set-ADUser -Identity $existing.DistinguishedName -PasswordNeverExpires $true
            } else {
                Set-ADUser -Identity $existing.DistinguishedName -PasswordNeverExpires $false
            }

            if ($blocked) {
                Disable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue
            } else {
                Enable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue
            }

            Write-Log -Level 'RESULT' -Message "Updated: $upn"
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Failed to update ${upn}: $($_.Exception.Message)"
        }
    }
    else {
        # Create new user
        $baseSam = ($upn.Split('@')[0]).ToLower()
        $sam = Next-AvailableSam -BaseSam $baseSam
        if ($sam -ieq 'administrator') {
            Write-Log -Level 'WARN' -Message "Skip creating user with sAMAccountName 'administrator'."
            return
        }

        $desc = Get-NextDescription -Existing $null
        $proxyAddrs = @()
        if ($proxyString) {
            $proxyAddrs = ($proxyString -split '\+') | Where-Object { $_ -match 'smtp:' } | ForEach-Object { $_.Trim() } | Select-Object -Unique
        }

        $passwordPlain = New-RandomPassword -Length 16
        $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

        Write-Log -Level 'ACTION' -Message "Creating AD user: $sam ($email) in OU: $DefaultOU"
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
                -Country $countryOrRegion `
                -Enabled ($blocked -eq $false) `
                -ChangePasswordAtLogon $false `
                -AccountPassword $password `
                -Path $DefaultOU `
                -Description $desc

            # Set proxy addresses if available
            if ($proxyAddrs.Count -gt 0) {
                $newly = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Properties proxyAddresses
                if ($newly) {
                    Set-ADUser -Identity $newly.DistinguishedName -Replace @{ proxyAddresses = $proxyAddrs } -ErrorAction SilentlyContinue
                }
            }

            # Password never expires setting
            $newly2 = Get-ADUser -Filter "SamAccountName -eq '$sam'"
            if ($newly2) {
                Set-ADUser -Identity $newly2.DistinguishedName -PasswordNeverExpires $pwdNeverExpires -ErrorAction SilentlyContinue
            }

            # Log credentials (requested)
            Write-CredentialLog -Email $email -UserPrincipalName $upn -SamAccountName $sam -Password $passwordPlain

            Write-Log -Level 'RESULT' -Message "Created: $upn"
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Failed to create ${upn}: $($_.Exception.Message)"
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
        }
    } catch {}
}
if (-not $CsvPath) {
    $CsvPath = Read-Host "Enter path to Microsoft 365 users CSV export"
}
if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}
if (-not $DefaultOU) {
    $DefaultOU = Read-Host "Enter default OU distinguishedName for new/managed users (e.g. OU=Users,DC=example,DC=com)"
}
if ([string]::IsNullOrWhiteSpace($DefaultOU)) {
    throw "Default OU is required."
}

# Logs
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:AuditLogPath = Join-Path -Path (Get-Location) -ChildPath "openidsync_audit_$ts.log"
$script:CredLogPath  = Join-Path -Path (Get-Location) -ChildPath "openidsync_credentials_$ts.csv"

"Email,UserPrincipalName,SamAccountName,GeneratedPassword" | Out-File -FilePath $script:CredLogPath -Encoding UTF8 -Force
Write-Log -Level 'INFO' -Message "Audit log initialized: $AuditLogPath"
Write-Log -Level 'INFO' -Message "Credential log initialized: $CredLogPath"
Write-Log -Level 'INFO' -Message "CSV: $CsvPath"
Write-Log -Level 'INFO' -Message "Default OU: $DefaultOU"

# Import CSV (new M365 Admin export format)
$rows = Import-Csv -LiteralPath $CsvPath

if (-not $rows -or $rows.Count -eq 0) {
    Write-Log -Level 'WARN' -Message "No rows found in CSV."
    return
}

$script:ProcessAll = $false

# Process users
foreach ($row in $rows) {
    # Calculate UPN early for prompt text
    $upn = $row.'User principal name'
    $first = $row.'First name'
    $last = $row.'Last name'

    Process-User -Row $row -DefaultOU $DefaultOU
}

# Suggest removals (not deleting, only suggesting)
if (-not $NoSuggestRemovals) {
    $csvEmails = $rows | ForEach-Object {
        $p = Get-PrimarySmtpFromProxyAddresses -ProxyString $_.'Proxy addresses'
        if ($p) { $p } else { $_.'User principal name' }
    }
    Suggest-Removals -DefaultOU $DefaultOU -CsvEmails $csvEmails
}

Write-Log -Level 'INFO' -Message "Finished."

#cd "c:\Users\Attila\Desktop\Code\openidsync"
#.\newuser.ps1 -CsvPath ".\users_9_15_2025 9_17_18 PM.csv" -DefaultOU "CN=Users,DC=modernworkplace,DC=hu"

