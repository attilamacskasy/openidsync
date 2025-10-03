# Transform and per-user processing logic

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

function ConvertTo-BooleanFriendly {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $false }
    $s = $Value.ToString().Trim()
    return @('true','1','yes','y') -contains $s.ToLower()
}

function Get-Pre2000SamCandidate {
    param([Parameter(Mandatory=$true)][string]$UpnLocalPart)
    $candidate = $UpnLocalPart.ToLower()
    if ($candidate.Length -le 20) { return $candidate }
    $dotIdx = $candidate.IndexOf('.')
    $left = $candidate; $right = ''
    if ($dotIdx -gt 0) { $left = $candidate.Substring(0, $dotIdx); $right = $candidate.Substring($dotIdx + 1) }
    $dashIdx = $left.IndexOf('-')
    if ($dashIdx -gt 0 -and ($dashIdx + 1) -lt $left.Length) {
        $initial = $left.Substring($dashIdx + 1, 1)
        $left = $left.Substring(0, $dashIdx + 1) + $initial
    }
    $compressed = if ($dotIdx -gt 0) { "$left.$right" } else { $left }
    return $compressed
}

function New-RandomPassword {
    param([int]$Length = 16)
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
    for ($i = $passChars.Count; $i -lt $Length; $i++) { $passChars += ($all | Get-Random) }
    -join ($passChars | Sort-Object {Get-Random})
}


