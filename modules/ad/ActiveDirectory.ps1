# Active Directory target operations

function Import-RequiredModule {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module '$Name' not found. Please install RSAT Active Directory tools and try again." -ForegroundColor Yellow
        throw "Missing module: $Name"
    }
    Import-Module $Name -ErrorAction Stop
}

function Get-ADUserByEmail {
    param([string]$Email)
    if ([string]::IsNullOrWhiteSpace($Email)) { return $null }
    $emailLc = $Email.Trim().ToLower()
    $u = Get-ADUser -Filter "mail -eq '$emailLc'" -Properties mail,proxyAddresses,description,displayName,givenName,sn,userPrincipalName,samAccountName,department,title,telephoneNumber,mobile,l,st,postalCode,streetAddress,co,c -ErrorAction SilentlyContinue
    if ($u) { return $u }
    $needle1 = "smtp:$emailLc"
    $needle2 = "SMTP:$emailLc"
    $candidates = Get-ADUser -Filter * -Properties proxyAddresses -ErrorAction SilentlyContinue | Where-Object {
        $_.proxyAddresses -and ($_.proxyAddresses -contains $needle1 -or $_.proxyAddresses -contains $needle2)
    }
    return $candidates | Select-Object -First 1
}

function Get-NextAvailableSam {
    param([string]$BaseSam)
    if ($BaseSam.Length -gt 20) {
        $orig = $BaseSam
        $sam = $BaseSam.Substring(0,20)
        try { Write-Log -Level 'WARN' -Message ("sAMAccountName base > 20 chars; truncating: '{0}' (len {1}) -> '{2}' (len {3})" -f $orig, $orig.Length, $sam, $sam.Length) } catch {}
    } else { $sam = $BaseSam }
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) { return $sam }
    for ($i=1; $i -lt 1000; $i++) {
        $candidate = $sam
        $suffix = $i.ToString()
        $maxBase = 20 - $suffix.Length
        if ($candidate.Length -gt $maxBase) { $candidate = $candidate.Substring(0,$maxBase) }
        $candidate = "$candidate$suffix"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$candidate'" -ErrorAction SilentlyContinue)) { return $candidate }
    }
    throw "Unable to find available sAMAccountName based on '$BaseSam'"
}

function Get-NextDescription {
    param([string]$Existing)
    $count = 0
    if ($Existing -and $Existing -match '\[Update count:\s*(\d+)\]') { $count = [int]$matches[1] }
    $count++
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $src = if ($script:SourceLabel) { [string]$script:SourceLabel } else { 'Unknown' }
    return "[Last update: $ts] [Update count: $count] [Source: $src] [openidsync.org]"
}

# Exception elevation logic: ensure specific users (e.g., Global Administrators) are members of Domain Admins
function Invoke-OpenIdSyncExceptionElevation {
    param(
        [Parameter(Mandatory=$true)][string]$Upn,
        [Parameter(Mandatory=$true)][string[]]$ExceptionTags,
        [string]$DomainAdminsGroup = 'Domain Admins'
    )
    try {
        if (-not $ExceptionTags -or $ExceptionTags.Count -eq 0) { return }
        # Present strategy: only tag we recognize now is 'GLOBAL_ADMIN'
        $needsDomainAdmin = $ExceptionTags -contains 'GLOBAL_ADMIN'
        if (-not $needsDomainAdmin) { return }
        $user = Get-ADUser -Filter "userPrincipalName -eq '$Upn'" -ErrorAction SilentlyContinue
        if (-not $user) { return }
        $da = Get-ADGroup -Filter "name -eq '$DomainAdminsGroup'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $da) { Write-Log -Level 'WARN' -Message "Domain Admins group not found: $DomainAdminsGroup"; return }
        $isMember = $false
        try {
            $members = Get-ADGroupMember -Identity $da.DistinguishedName -Recursive:$false -ErrorAction SilentlyContinue
            if ($members) { $isMember = $members | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName } | ForEach-Object { $true } | Select-Object -First 1 }
        } catch {}
        if (-not $isMember) {
            try {
                Add-ADGroupMember -Identity $da.DistinguishedName -Members $user.DistinguishedName -ErrorAction Stop
                Write-Log -Level 'RESULT' -Message "Elevated (GLOBAL_ADMIN) $Upn -> Domain Admins"
            } catch { Write-Log -Level 'ERROR' -Message "Failed to add $Upn to Domain Admins: $($_.Exception.Message)" }
        }
    } catch { Write-Log -Level 'ERROR' -Message "Exception elevation failure for ${Upn}: $($_.Exception.Message)" }
}


