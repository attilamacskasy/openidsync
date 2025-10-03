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

        if (-not ($cfgObj.PSObject.Properties['OnlineSyncConfig'])) {
            $cfgObj | Add-Member -NotePropertyName 'OnlineSyncConfig' -NotePropertyValue ([pscustomobject]@{})
        }
        $osc = $cfgObj.OnlineSyncConfig
        if (-not ($osc -is [pscustomobject])) { $osc = [pscustomobject]$osc }

        $osc | Add-Member -NotePropertyName 'TenantId' -NotePropertyValue $TenantId -Force
        $osc | Add-Member -NotePropertyName 'ClientId' -NotePropertyValue $ClientId -Force
        if ($SpObjectId) { $osc | Add-Member -NotePropertyName 'SpObjectId' -NotePropertyValue $SpObjectId -Force }
        if ($ClientSecretEnvVar) { $osc | Add-Member -NotePropertyName 'ClientSecretEnvVar' -NotePropertyValue $ClientSecretEnvVar -Force }

        $cfgObj.OnlineSyncConfig = $osc
        $json = $cfgObj | ConvertTo-Json -Depth 8
        $json | Out-File -FilePath $OnlineConfigPath -Encoding UTF8 -Force
        Write-Log -Level 'INFO' -Message "Saved OnlineSyncConfig (no secrets) to: $OnlineConfigPath"
    } catch {
        Write-Log -Level 'WARN' -Message "Failed to save OnlineSyncConfig: $($_.Exception.Message)"
    }
}


