function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT')]
        [string]$Level = 'INFO'
    )
    try {
        Write-Syslog -Message $Message -Level $Level -MsgId '-' -Data $null
    } catch {
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "[$ts] [$Level] $Message"
        if ($script:AuditLogPath) { $line | Out-File -FilePath $script:AuditLogPath -Encoding UTF8 -Append }
        Write-Host $line
    }
}


