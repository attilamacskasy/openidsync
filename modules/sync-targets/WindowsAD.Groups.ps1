# Windows AD group sync: ensure groups with prefixes and reconcile memberships

. $PSScriptRoot\..\logging\Write-Log.ps1
. $PSScriptRoot\..\ad\ActiveDirectory.ps1

function Remove-Diacritics {
    param([Parameter(Mandatory=$true)][string]$InputString)
    # Normalize to FormD and strip non-spacing marks, then normalize back
    $formD = $InputString.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $formD.ToCharArray()) {
        $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch)
        if ($cat -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) { [void]$sb.Append($ch) }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

function Convert-DisplayNameToSam {
    param(
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [string]$Prefix = ''
    )
    $name = Remove-Diacritics -InputString $DisplayName
    # Replace dots and whitespace with underscore
    $name = ($name -replace '\.', '_')
    $name = ($name -replace '\s+', '_')
    # Replace any non safe ASCII with underscore
    $name = $name -replace "[^A-Za-z0-9_\-]", '_'
    # Collapse multiple underscores and trim
    $name = ($name -replace '_+', '_').Trim('_')
    # Prepend prefix
    $sam = "$Prefix$name"
    # Collapse multiple underscores and trim underscores
    $sam = ($sam -replace '_+', '_').Trim('_')
    # Trim to sAMAccountName limit (20)
    if ($sam.Length -gt 20) { $sam = $sam.Substring(0,20).TrimEnd('_') }
    # Ensure not empty
    if ([string]::IsNullOrWhiteSpace($sam)) { $sam = 'Group_' + ([Guid]::NewGuid().ToString('N').Substring(0,6)) }
    # Ensure we do not end with underscore
    $sam = $sam.TrimEnd('_')
    return $sam
}

function Get-AdGroupBySamOrName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $g = Get-ADGroup -LDAPFilter "(sAMAccountName=$Name)" -ErrorAction SilentlyContinue
    if ($g) { return $g }
    return Get-ADGroup -LDAPFilter "(name=$Name)" -ErrorAction SilentlyContinue
}

function New-ADGroupIfMissing {
    param(
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][ValidateSet('Security','M365','Distribution','Other')]$Kind,
        [Parameter(Mandatory=$true)][string]$TargetOU,
        [string]$SecurityPrefix = 'Sec_',
        [string]$M365Prefix = 'Team_',
        [string]$DistributionPrefix = 'Distribution_'
    )
    $prefix = switch ($Kind) { 'Security' { $SecurityPrefix } 'M365' { $M365Prefix } 'Distribution' { $DistributionPrefix } default { '' } }
    $samBase = Convert-DisplayNameToSam -DisplayName $DisplayName -Prefix $prefix
    $existing = Get-AdGroupBySamOrName -Name $samBase
    if ($existing) { Write-Log -Level 'INFO' -Message ("AD Group exists: {0}" -f $existing.SamAccountName); return ([pscustomobject]@{ Group = $existing; Created = $false }) }

    $groupCategory = if ($Kind -eq 'Security') { 'Security' } else { 'Distribution' }
    $groupScope = 'Global'

    Write-Log -Level 'ACTION' -Message ("Creating AD group: {0} in OU: {1}" -f $samBase, $TargetOU)
    try {
    New-ADGroup -Name $samBase -SamAccountName $samBase -GroupCategory $groupCategory -GroupScope $groupScope -Path $TargetOU -ErrorAction Stop | Out-Null
    $g = Get-AdGroupBySamOrName -Name $samBase
    if ($g) {
        Write-Log -Level 'RESULT' -Message ("Created AD group: {0}" -f $samBase)
        try {
            Set-OpenIdSyncGroupDescription -Group $g -SourceGroupName $DisplayName -MemberCount 0
        } catch { Write-Log -Level 'WARN' -Message ("Failed to initialize description for {0}: {1}" -f $samBase, $_.Exception.Message) }
        return ([pscustomobject]@{ Group = $g; Created = $true })
    }
    } catch { Write-Log -Level 'ERROR' -Message ("Failed to create group {0}: {1}" -f $samBase, $_.Exception.Message) }
    return $null
}

function Set-AdGroupMemberships {
    param(
        [Parameter(Mandatory=$true)]$Group,
        [string[]]$MemberUpns = @()
    )
    # Resolve UPNs to AD users
    $membersDns = @()
    foreach ($upn in $MemberUpns) {
        try {
            $u = Get-ADUser -Filter "userPrincipalName -eq '$upn'" -ErrorAction SilentlyContinue
            if ($u) { $membersDns += $u.DistinguishedName }
        } catch {}
    }

    # Current members
    $current = @()
    try { $current = Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive:$false -ErrorAction SilentlyContinue } catch {}
    $currentDns = @($current | Where-Object { $_.ObjectClass -eq 'user' } | ForEach-Object { $_.DistinguishedName })

    $toAdd = @($membersDns | Where-Object { $currentDns -notcontains $_ })
    $toRemove = @($currentDns | Where-Object { $membersDns -notcontains $_ })

    $addedN = 0; $removedN = 0
    if ($toAdd.Count -gt 0) {
        try { Add-ADGroupMember -Identity $Group.DistinguishedName -Members $toAdd -ErrorAction Stop; $addedN = $toAdd.Count; Write-Log -Level 'RESULT' -Message ("Added {0} members to {1}" -f $toAdd.Count, $Group.SamAccountName) } catch { Write-Log -Level 'ERROR' -Message ("Failed to add members: {0}" -f $_.Exception.Message) }
    }
    if ($toRemove.Count -gt 0) {
        try { Remove-ADGroupMember -Identity $Group.DistinguishedName -Members $toRemove -Confirm:$false -ErrorAction Stop; $removedN = $toRemove.Count; Write-Log -Level 'RESULT' -Message ("Removed {0} members from {1}" -f $toRemove.Count, $Group.SamAccountName) } catch { Write-Log -Level 'ERROR' -Message ("Failed to remove members: {0}" -f $_.Exception.Message) }
    }
    return [pscustomobject]@{ Added = $addedN; Removed = $removedN }
}

function Set-OpenIdSyncGroupDescription {
    param(
        [Parameter(Mandatory=$true)]$Group,
        [Parameter(Mandatory=$true)][string]$SourceGroupName,
        [int]$MemberCount = 0,
        [string]$SourceLabel
    )

    if (-not $Group) { return }

    if ([string]::IsNullOrWhiteSpace($SourceLabel)) {
    if ($script:SourceLabel) { $SourceLabel = [string]$script:SourceLabel }
    elseif ($script:SourceFriendly) { $SourceLabel = [string]$script:SourceFriendly }
    elseif ($script:Source) { $SourceLabel = [string]$script:Source }
    else { $SourceLabel = 'Unknown' }
    }

    $safeSourceName = if ($SourceGroupName) { [string]$SourceGroupName } else { '(unknown)' }
    $safeSourceName = $safeSourceName -replace '\]', ')'
    if (-not [string]::IsNullOrWhiteSpace($safeSourceName)) { $safeSourceName = $safeSourceName.Trim() }

    try {
        $groupObj = Get-ADGroup -Identity $Group.DistinguishedName -Properties Description -ErrorAction Stop
    } catch {
        Write-Log -Level 'ERROR' -Message ("Failed to load AD group for description update ({0}): {1}" -f $Group.SamAccountName, $_.Exception.Message)
        return
    }

    $existingDesc = [string]$groupObj.Description
    $existingDescIsEmpty = [string]::IsNullOrWhiteSpace($existingDesc)
    $baseText = ''
    $existingUpdateCount = 0
    $existingSourceGroupName = $null
    $existingMemberCount = 0
    $parseFailed = $false

    if (-not $existingDescIsEmpty) {
        try {
            if ($existingDesc -match '\[openidsync\.org\]') {
                $updateMatch = [System.Text.RegularExpressions.Regex]::Match($existingDesc, '\[Update count:\s*(\d+)\]')
                if ($updateMatch.Success) { [void][int]::TryParse($updateMatch.Groups[1].Value, [ref]$existingUpdateCount) }
                $sourceMatch = [System.Text.RegularExpressions.Regex]::Match($existingDesc, '\[SourceGroupName:(.*?)\]')
                if ($sourceMatch.Success) { $existingSourceGroupName = ($sourceMatch.Groups[1].Value).Trim() }
                $membersMatch = [System.Text.RegularExpressions.Regex]::Match($existingDesc, '\[Members:(\d+)\]')
                if ($membersMatch.Success) { [void][int]::TryParse($membersMatch.Groups[1].Value, [ref]$existingMemberCount) }
                $baseText = [System.Text.RegularExpressions.Regex]::Replace($existingDesc, '(?s)\s*\[Last update:.*?\[openidsync\.org\]\s*$', '').Trim()
            } else {
                $baseText = $existingDesc.Trim()
            }
        }
        catch {
            $parseFailed = $true
            $existingUpdateCount = 0
            $existingSourceGroupName = $null
            $existingMemberCount = 0
            $baseText = ''
            try { Write-Log -Level 'DEBUG' -Message ("Failed to parse existing group description for {0}; regenerating from baseline." -f $groupObj.SamAccountName) } catch {}
        }
    }

    if ($null -eq $existingMemberCount) { $existingMemberCount = 0 }

    $forceUpdate = [bool]$script:ForceUpdateGroupDescriptions
    if ($forceUpdate -or $existingDescIsEmpty) {
        $existingUpdateCount = 0
        $baseText = ''
    }

    $originalBaseText = $baseText
    if ([string]::IsNullOrWhiteSpace($baseText)) { $baseText = '[OpenIDSync managed]' }

    $memberCountValue = if ($MemberCount -gt 0) { [int]$MemberCount } else { 0 }
    $sourceChanged = -not [string]::Equals($existingSourceGroupName, $safeSourceName, [System.StringComparison]::OrdinalIgnoreCase)
    $memberCountChanged = ($existingMemberCount -ne $memberCountValue)
    $metadataMissing = $existingDescIsEmpty -or $parseFailed -or -not ($existingDesc -match '\[openidsync\.org\]')
    $baseChanged = -not [string]::Equals($originalBaseText, $baseText, [System.StringComparison]::OrdinalIgnoreCase)

    $shouldUpdate = $forceUpdate -or $metadataMissing -or $sourceChanged -or $memberCountChanged -or $baseChanged

    if (-not $shouldUpdate) {
        Write-Log -Level 'DEBUG' -Message ("Description already current for AD group {0}" -f $groupObj.SamAccountName)
        return
    }

    $updateCount = if ($existingUpdateCount -gt 0) { $existingUpdateCount + 1 } else { 1 }
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $metadata = "[Last update: $timestamp] [Update count: $updateCount] [Source: $SourceLabel] [SourceGroupName:$safeSourceName] [Members:$memberCountValue] [openidsync.org]"
    $newDescription = ("{0} {1}" -f $baseText.Trim(), $metadata).Trim()

    try {
        Set-ADGroup -Identity $groupObj.DistinguishedName -Description $newDescription -ErrorAction Stop
        if ($forceUpdate -and -not ($metadataMissing -or $sourceChanged -or $memberCountChanged -or $baseChanged)) {
            Write-Log -Level 'INFO' -Message ("Updated description for AD group {0} (forced)" -f $groupObj.SamAccountName)
        } else {
            Write-Log -Level 'INFO' -Message ("Updated description for AD group {0}" -f $groupObj.SamAccountName)
        }
    } catch {
        Write-Log -Level 'ERROR' -Message ("Failed to update description for group {0}: {1}" -f $groupObj.SamAccountName, $_.Exception.Message)
    }
}
