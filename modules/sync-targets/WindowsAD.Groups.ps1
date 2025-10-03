# Windows AD group sync: ensure groups with prefixes and reconcile memberships

. $PSScriptRoot\..\logging\Write-Log.ps1
. $PSScriptRoot\..\ad\ActiveDirectory.ps1

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
        [Parameter(Mandatory=$true)][ValidateSet('Security','M365','Other')]$Kind,
        [Parameter(Mandatory=$true)][string]$TargetOU,
        [string]$SecurityPrefix = 'Sec_',
        [string]$M365Prefix = 'Team_'
    )
    $prefix = switch ($Kind) { 'Security' { $SecurityPrefix } 'M365' { $M365Prefix } default { '' } }
    $samBase = "$prefix$DisplayName" -replace '[^A-Za-z0-9_\-\.]','_'
    if ($samBase.Length -gt 20) { $samBase = $samBase.Substring(0,20) }
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
