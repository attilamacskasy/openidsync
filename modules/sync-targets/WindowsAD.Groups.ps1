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
    if ($g) { Write-Log -Level 'RESULT' -Message ("Created AD group: {0}" -f $samBase); return ([pscustomobject]@{ Group = $g; Created = $true }) }
    } catch { Write-Log -Level 'ERROR' -Message ("Failed to create group {0}: {1}" -f $samBase, $_.Exception.Message) }
    return $null
}

function Set-AdGroupMemberships {
    param(
        [Parameter(Mandatory=$true)]$Group,
        [Parameter(Mandatory=$true)][string[]]$MemberUpns
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
