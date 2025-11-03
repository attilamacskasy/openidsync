# Windows AD target implementation for user operations

. $PSScriptRoot\..\logging\Write-Log.ps1
. $PSScriptRoot\..\ad\ActiveDirectory.ps1
. $PSScriptRoot\..\transform\Users.ps1

function Write-CredentialLog {
    param(
        [string]$Email,
        [string]$UserPrincipalName,
        [string]$SamAccountName,
        [System.Security.SecureString]$Password
    )
    # Convert back to plain text for the CSV only at this boundary (intentional for onboarding)
    $unsecure = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    "$Email,$UserPrincipalName,$SamAccountName,$unsecure" | Out-File -FilePath $script:CredLogPath -Encoding UTF8 -Append
}

function Show-UserCard {
    param($Row)
    Write-Host ""
    Write-Host "-------------------- USER PREVIEW --------------------" -ForegroundColor Cyan
    foreach ($p in $Row.PSObject.Properties) { $name = $p.Name; $val = [string]$p.Value; Write-Host ("{0,-28}: {1}" -f $name, $val) }
    try {
        $upnLocalPreview = ([string]$Row.'User principal name').Split('@')[0].ToLower()
        $basePreview = if ($upnLocalPreview.Length -gt 20) { Get-Pre2000SamCandidate -UpnLocalPart $upnLocalPreview } else { $upnLocalPreview }
        $dispPreview = if ($basePreview.Length -gt 20) { $basePreview.Substring(0,20) } else { $basePreview }
        Write-Host ("{0,-28}: {1}" -f 'sAMAccountName (candidate)', $dispPreview)
    } catch {}
    Write-Host "------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-UserSync {
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
    $blocked = ConvertTo-BooleanFriendly $Row.'Block credential'
    $pwdNeverExpires = ConvertTo-BooleanFriendly $Row.'Password never expires'

    if ([string]::IsNullOrWhiteSpace($upn)) { Write-Log -Level 'WARN' -Message "Skipping row with empty UPN."; Add-Summary 'SkippedEmptyUPN'; return }

    if ($script:SkipUpnTokens -and $script:SkipUpnTokens.Count -gt 0) {
        $upnLc = $upn.ToLower()
        foreach ($tok in $script:SkipUpnTokens) {
            if (-not [string]::IsNullOrWhiteSpace($tok)) {
                $tokLc = ([string]$tok).ToLower()
                if ($upnLc -like "*${tokLc}*") { Write-Log -Level 'RESULT' -Message "Skipped by UPN token '${tok}': ${upn}"; Add-Summary 'SkippedByUPN'; return }
            }
        }
    }

    if ($script:SkipDisplayNameTokens -and $script:SkipDisplayNameTokens.Count -gt 0 -and $display) {
        $dispLc = $display.ToLower()
        foreach ($tok in $script:SkipDisplayNameTokens) {
            if (-not [string]::IsNullOrWhiteSpace($tok)) {
                $tokLc = $tok.ToLower()
                if ($dispLc -like "*${tokLc}*") { Write-Log -Level 'RESULT' -Message "Skipped by DisplayName token '${tok}': ${display} (${upn})"; Add-Summary 'SkippedByDisplayName'; return }
            }
        }
    }

    Show-UserCard -Row $Row

    $proceed = $false
    $skippedByPrompt = $false
    if ($script:ProcessAll -or $script:NonInteractive) { $proceed = $true }
    else {
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

    if (-not $proceed) { if (-not $script:QuitRequested -and $skippedByPrompt) { Add-Summary 'SkippedPrompt' }; Write-Log -Level 'RESULT' -Message "Skipped: $upn"; return }

    $existing = Get-ADUserByEmail -Email $email

    if ($existing) {
        if ($existing.SamAccountName -ieq 'administrator') { Write-Log -Level 'WARN' -Message "Skip managing 'administrator' account."; Add-Summary 'SkippedAdministrator'; return }

        $normalizeString = {
            param($value)
            if ($null -eq $value) { return '' }
            return ([string]$value).Trim()
        }
        $equalsString = {
            param($a,$b)
            $aNorm = & $normalizeString $a
            $bNorm = & $normalizeString $b
            return [string]::Equals($aNorm, $bNorm, [System.StringComparison]::OrdinalIgnoreCase)
        }

        $proxyAddrs = @()
        if ($proxyString) {
            $proxyAddrs = @($proxyString -split '\+' | Where-Object { $_ -match 'smtp:' } | ForEach-Object { ([string]$_).Trim() })
            $proxyAddrs = $proxyAddrs | Sort-Object -Unique
        }
        $existingProxyAddrs = @()
        if ($existing.proxyAddresses) { $existingProxyAddrs = @($existing.proxyAddresses) }

        $existingDescMissing = (-not $existing.PSObject.Properties.Match('Description') -or [string]::IsNullOrWhiteSpace($existing.Description))

        $mainAttrChanges = $false
        if (-not (& $equalsString $existing.UserPrincipalName $upn)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.GivenName $first)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.Surname $last)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.DisplayName $display)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.mail $email)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.Department $department)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.Title $title)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.Office $office)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.l $city)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.st $state)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.PostalCode $postal)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.StreetAddress $street)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.mobile $mobile)) { $mainAttrChanges = $true }
        if (-not (& $equalsString $existing.telephoneNumber $phone)) { $mainAttrChanges = $true }

        $proxyChanged = $false
        if ($proxyAddrs.Count -gt 0) {
            $desiredProxyNormalized = $proxyAddrs | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique
            $existingProxyNormalized = $existingProxyAddrs | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique
            if (Compare-Object -ReferenceObject $desiredProxyNormalized -DifferenceObject $existingProxyNormalized) { $proxyChanged = $true }
        }

        $pwdFlagChanged = $false
        if ($existing.PSObject.Properties['PasswordNeverExpires']) {
            $pwdFlagChanged = ([bool]$existing.PasswordNeverExpires -ne [bool]$pwdNeverExpires)
        } else {
            $pwdFlagChanged = [bool]$pwdNeverExpires
        }

        $isEnabled = $true
        if ($existing.PSObject.Properties['Enabled']) { $isEnabled = [bool]$existing.Enabled }
        $shouldDisable = ($blocked -and $isEnabled)
        $shouldEnable = ((-not $blocked) -and (-not $isEnabled))

        $countryChanged = $false
        if ($countryOrRegion) {
            if (-not (& $equalsString $existing.co $countryOrRegion)) { $countryChanged = $true }
        }

        $anyChange = $mainAttrChanges -or $proxyChanged -or $pwdFlagChanged -or $shouldDisable -or $shouldEnable -or $countryChanged
        if ($existingDescMissing) { $anyChange = $true }
        $forceDesc = [bool]$script:ForceUpdateUserDescriptions
        $shouldUpdateDesc = $forceDesc -or $anyChange
        if ($existingDescMissing) { $shouldUpdateDesc = $true }

        if (-not $anyChange -and -not $forceDesc) {
            Write-Log -Level 'DEBUG' -Message ("No attribute changes detected for {0}; skipping update." -f $upn)
            return
        }

    $newDesc = $null
        if ($shouldUpdateDesc) {
            $descReset = $forceDesc -or $existingDescMissing
            $newDesc = Get-NextDescription -Existing $existing.Description -Reset:$descReset
        }

        Write-Log -Level 'ACTION' -Message "Updating existing AD user: $($existing.SamAccountName) ($email)"
        $performedUpdate = $false

        if ($mainAttrChanges) {
            $setParams = @{
                Identity          = $existing.DistinguishedName
                UserPrincipalName = $upn
                GivenName         = $first
                Surname           = $last
                DisplayName       = $display
                EmailAddress      = $email
                Department        = $department
                Title             = $title
                Office            = $office
                City              = $city
                State             = $state
                PostalCode        = $postal
                StreetAddress     = $street
                MobilePhone       = $mobile
                OfficePhone       = $phone
            }
            if ($newDesc) { $setParams['Description'] = $newDesc }
            try {
                Set-ADUser @setParams
                $performedUpdate = $true
            }
            catch {
                Write-Log -Level 'ERROR' -Message "Failed to update ${upn}: $($_.Exception.Message)"
                Add-Summary 'FailedUpdate'
                return
            }
        }
        elseif ($newDesc) {
            try {
                Set-ADUser -Identity $existing.DistinguishedName -Description $newDesc -ErrorAction Stop
                $performedUpdate = $true
            }
            catch {
                Write-Log -Level 'ERROR' -Message "Failed to update description for ${upn}: $($_.Exception.Message)"
                Add-Summary 'FailedUpdate'
                return
            }
        }

        if ($proxyChanged) {
            try {
                Set-ADUser -Identity $existing.DistinguishedName -Replace @{ proxyAddresses = ([string[]]$proxyAddrs) } -ErrorAction Stop
                $performedUpdate = $true
            }
            catch { Write-Log -Level 'WARN' -Message "Failed to set proxyAddresses for ${upn}: $($_.Exception.Message)" }
        }

        if ($pwdFlagChanged) {
            try {
                Set-ADUser -Identity $existing.DistinguishedName -PasswordNeverExpires $pwdNeverExpires -ErrorAction SilentlyContinue
                $performedUpdate = $true
            } catch {}
        }

        if ($shouldDisable) {
            try { Disable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue; $performedUpdate = $true } catch {}
        }
        elseif ($shouldEnable) {
            try { Enable-ADAccount -Identity $existing.DistinguishedName -ErrorAction SilentlyContinue; $performedUpdate = $true } catch {}
        }

        if ($countryChanged) {
            try { Set-ADUser -Identity $existing.DistinguishedName -Replace @{ co = [string]$countryOrRegion } -ErrorAction SilentlyContinue; $performedUpdate = $true }
            catch { Write-Log -Level 'WARN' -Message "Failed to set country (co) for ${upn}: $($_.Exception.Message)" }
        }

        if ($performedUpdate) {
            Write-Log -Level 'RESULT' -Message "Updated: $upn"
            Add-Summary 'Updated'
        } else {
            Write-Log -Level 'DEBUG' -Message ("No modifications were applied to {0}." -f $upn)
        }
    }
    else {
        $baseUpnLocal = ($upn.Split('@')[0]).ToLower()
        $baseSam = $baseUpnLocal
        if ($baseUpnLocal.Length -gt 20) {
            $compressed = Get-Pre2000SamCandidate -UpnLocalPart $baseUpnLocal
            if ($compressed -ne $baseUpnLocal) { Write-Log -Level 'WARN' -Message ("sAMAccountName base exceeded 20 chars; compressing dashed surname: '{0}' (len {1}) -> '{2}' (len {3})" -f $baseUpnLocal, $baseUpnLocal.Length, $compressed, $compressed.Length); $baseSam = $compressed }
        }
    $sam = Get-NextAvailableSam -BaseSam $baseSam
        if ($sam -ieq 'administrator') { Write-Log -Level 'WARN' -Message "Skip creating user with sAMAccountName 'administrator'."; Add-Summary 'SkippedAdministrator'; return }

    $desc = Get-NextDescription -Existing $null -Reset
        $proxyAddrs = @(); if ($proxyString) { $proxyAddrs = @($proxyString -split '\+') | Where-Object { $_ -match 'smtp:' } | ForEach-Object { [string]$_.Trim() } | Sort-Object -Unique }

    $passwordPlain = New-RandomPassword -Length 16
    $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

        Write-Log -Level 'INFO' -Message ("sAMAccountName chosen: {0}" -f $sam)
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
                -Enabled ($blocked -eq $false) `
                -ChangePasswordAtLogon $false `
                -AccountPassword $password `
                -Path $DefaultOU `
                -Description $desc

            Write-CredentialLog -Email $email -UserPrincipalName $upn -SamAccountName $sam -Password $password
            Write-Log -Level 'RESULT' -Message "Created: $upn"; Add-Summary 'Created'
        }
        catch { Write-Log -Level 'ERROR' -Message "Failed to create ${upn}: $($_.Exception.Message)"; Add-Summary 'FailedCreate'; return }

        try {
            if ($proxyAddrs.Count -gt 0) {
                $newly = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Properties proxyAddresses
                if ($newly) { Set-ADUser -Identity $newly.DistinguishedName -Replace @{ proxyAddresses = ([string[]]$proxyAddrs) } -ErrorAction Stop }
            }
        } catch { Write-Log -Level 'WARN' -Message "Failed to set proxyAddresses for ${upn}: $($_.Exception.Message)" }

        try { $newly2 = Get-ADUser -Filter "SamAccountName -eq '$sam'"; if ($newly2) { Set-ADUser -Identity $newly2.DistinguishedName -PasswordNeverExpires $pwdNeverExpires -ErrorAction SilentlyContinue } }
        catch { Write-Log -Level 'WARN' -Message "Failed to set PasswordNeverExpires for ${upn}: $($_.Exception.Message)" }
    }
}

function Show-RemovalSuggestions {
    param([string]$DefaultOU, [string[]]$CsvEmails)
    try {
        $csvSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $CsvEmails | Where-Object { $_ } | ForEach-Object { [void]$csvSet.Add($_) }
        $adUsers = Get-ADUser -SearchBase $DefaultOU -LDAPFilter "(objectClass=user)" -Properties mail,description,displayName,samAccountName,userPrincipalName | Where-Object { $_.mail -and $_.SamAccountName -ne 'administrator' }
        $candidates = @()
        foreach ($u in $adUsers) { if (-not $csvSet.Contains($u.mail)) { $isManaged = ($u.Description -like '*[openidsync.org]*'); if (-not $isManaged) { $candidates += $u } } }
        if ($candidates.Count -gt 0) {
            Write-Host ""
            Write-Host "Users in $DefaultOU not found in CSV and not managed by this tool (suggest review/removal):" -ForegroundColor Yellow
            foreach ($u in $candidates) { $msg = "Suggest removal -> sAM: $($u.SamAccountName), UPN: $($u.UserPrincipalName), Mail: $($u.mail), Name: $($u.DisplayName)"; Write-Host $msg; Write-Log -Level 'INFO' -Message $msg }
            Write-Host ""
        } else { Write-Log -Level 'INFO' -Message "No un-managed AD users (with mail) in $DefaultOU are missing from CSV." }
    }
    catch { Write-Log -Level 'ERROR' -Message "Suggest-Removals failed: $($_.Exception.Message)" }
}


