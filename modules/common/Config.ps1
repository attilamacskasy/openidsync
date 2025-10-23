# Config utilities: load main and online sync config, expose script-scoped vars
function Load-OpenIdSyncConfig {
    param(
        [string]$ConfigPath,
        [string]$OnlineSyncConfigPath
    )
    $script:ConfigPath = $ConfigPath
    $script:OnlineSyncConfigPath = $OnlineSyncConfigPath

    $result = [ordered]@{}
    if (Test-Path -LiteralPath $ConfigPath) {
        try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch { $cfg = $null }
        if ($cfg) { $result.Main = $cfg }
    }
    if (Test-Path -LiteralPath $OnlineSyncConfigPath) {
        try { $osc = Get-Content -LiteralPath $OnlineSyncConfigPath -Raw | ConvertFrom-Json } catch { $osc = $null }
        if ($osc) { $result.Online = $osc }
    }
    return $result
}

function ConvertTo-OrderedObject {
    param(
        [Parameter(Mandatory=$true)][psobject]$Object,
        [string[]]$PreferredOrder
    )
    $ordered = [ordered]@{}
    if ($PreferredOrder) {
        foreach ($key in $PreferredOrder) {
            if ($Object.PSObject.Properties[$key]) {
                $ordered[$key] = $Object.$key
            }
        }
    }
    foreach ($prop in $Object.PSObject.Properties.Name) {
        if (-not $ordered.Contains($prop)) {
            $ordered[$prop] = $Object.$prop
        }
    }
    return $ordered
}

function ConvertTo-PrettyJson {
    param(
        [Parameter(Mandatory=$true)]$InputObject,
        [int]$Indent = 4,
        [int]$Depth = 16
    )

    $compressed = $InputObject | ConvertTo-Json -Depth $Depth -Compress
    $builder = New-Object System.Text.StringBuilder
    $indentLevel = 0
    $inString = $false
    $escape = $false
    $indentStr = ' ' * $Indent

    foreach ($char in $compressed.ToCharArray()) {
        if ($escape) {
            [void]$builder.Append($char)
            $escape = $false
            continue
        }
        switch ($char) {
            '\\' {
                [void]$builder.Append($char)
                if ($inString) { $escape = $true }
                continue
            }
            '"' {
                [void]$builder.Append($char)
                $inString = -not $inString
                continue
            }
        }

        if ($inString) {
            [void]$builder.Append($char)
            continue
        }

        switch ($char) {
            '{' { [void]$builder.AppendLine('{'); $indentLevel++; [void]$builder.Append($indentStr * $indentLevel); continue }
            '[' { [void]$builder.AppendLine('['); $indentLevel++; [void]$builder.Append($indentStr * $indentLevel); continue }
            '}' { $indentLevel--; [void]$builder.AppendLine(); [void]$builder.Append($indentStr * $indentLevel); [void]$builder.Append('}'); continue }
            ']' { $indentLevel--; [void]$builder.AppendLine(); [void]$builder.Append($indentStr * $indentLevel); [void]$builder.Append(']'); continue }
            ',' { [void]$builder.Append(','); [void]$builder.AppendLine(); [void]$builder.Append($indentStr * $indentLevel); continue }
            ':' { [void]$builder.Append(': '); continue }
            ' ' { continue }
            default { [void]$builder.Append($char); continue }
        }
    }

    return $builder.ToString().TrimEnd()
}

function Save-OnlineSyncConfig {
    param(
        [Parameter(Mandatory=$true)][string]$OnlineConfigPath,
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [string]$SpObjectId,
        [string]$ClientSecretEnvVar,
        [string]$AppRegistrationName
    )
    try {
        $cfgObj = $null
        if (Test-Path -LiteralPath $OnlineConfigPath) {
            try { $cfgObj = (Get-Content -LiteralPath $OnlineConfigPath -Raw | ConvertFrom-Json) } catch { $cfgObj = $null }
        }
        if (-not $cfgObj) { $cfgObj = [pscustomobject]@{} }

        if (-not ($cfgObj.PSObject.Properties['OnlineSyncConfig'])) {
            $cfgObj | Add-Member -NotePropertyName 'OnlineSyncConfig' -NotePropertyValue ([pscustomobject]@{})
        }
        $osc = $cfgObj.OnlineSyncConfig
        if (-not ($osc -is [pscustomobject])) { $osc = [pscustomobject]$osc }

        $osc | Add-Member -NotePropertyName 'AppRegistrationName' -NotePropertyValue $AppRegistrationName -Force
        $osc | Add-Member -NotePropertyName 'TenantId' -NotePropertyValue $TenantId -Force
        $osc | Add-Member -NotePropertyName 'ClientId' -NotePropertyValue $ClientId -Force
        if ($SpObjectId -ne $null) { $osc | Add-Member -NotePropertyName 'SpObjectId' -NotePropertyValue $SpObjectId -Force }
        if ($ClientSecretEnvVar -ne $null) { $osc | Add-Member -NotePropertyName 'ClientSecretEnvVar' -NotePropertyValue $ClientSecretEnvVar -Force }

        $cfgObj.OnlineSyncConfig = $osc
        $ordered = ConvertTo-OrderedObject -Object $cfgObj -PreferredOrder @('OnlineSyncConfig')
        $ordered.OnlineSyncConfig = ConvertTo-OrderedObject -Object $cfgObj.OnlineSyncConfig -PreferredOrder @('AppRegistrationName','TenantId','ClientId','SpObjectId','ClientSecretEnvVar')
        $json = ConvertTo-PrettyJson -InputObject $ordered -Depth 16
        $json | Out-File -FilePath $OnlineConfigPath -Encoding UTF8 -Force
        Write-Log -Level 'INFO' -Message "Saved OnlineSyncConfig (no secrets) to: $OnlineConfigPath"
    } catch {
        Write-Log -Level 'WARN' -Message "Failed to save OnlineSyncConfig: $($_.Exception.Message)"
    }
}

function Save-OpenIdSyncConfig {
    param(
        [Parameter(Mandatory=$true)][string]$ConfigPath,
        [Parameter(Mandatory=$true)][psobject]$ConfigObject
    )
    try {
        $ordered = ConvertTo-OrderedObject -Object $ConfigObject -PreferredOrder @('DomainPromotionConfig','PrepareConfig','UserSyncConfig','LoggingConfig')
        if ($ordered.Contains('UserSyncConfig') -and $ordered.UserSyncConfig) {
            $ordered.UserSyncConfig = ConvertTo-OrderedObject -Object ([pscustomobject]$ordered.UserSyncConfig) -PreferredOrder @(
                'CsvPath','DefaultOU','PreferredSource','SuggestRemovals','SkipUserBasedOnDisplayName','SkipUserBasedOnUserPrincipalName','UsersMode','GroupsMode','MembershipsMode','SyncModes'
            )
        }
        if ($ordered.Contains('LoggingConfig') -and $ordered.LoggingConfig) {
            $ordered.LoggingConfig = ConvertTo-OrderedObject -Object ([pscustomobject]$ordered.LoggingConfig) -PreferredOrder @('Mode','FilePath','SyslogServer','SyslogPort')
        }
        $json = ConvertTo-PrettyJson -InputObject $ordered -Depth 16
        $json | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
        Write-Log -Level 'INFO' -Message "Saved OpenIDSync config to: $ConfigPath"
    } catch {
        Write-Log -Level 'WARN' -Message "Failed to save OpenIDSync config: $($_.Exception.Message)"
    }
}


