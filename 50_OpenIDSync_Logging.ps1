<#
 50_OpenIDSync_Logging.ps1
 RFC 5424 syslog logging functions for OpenIDSync scripts.
 Dot-source this file in scripts that require structured logging.
#>

function Initialize-Logger {
    param(
        [string]$FilePath,
        [string]$AppName = 'openidsync',
        [ValidateSet('KERN','USER','MAIL','DAEMON','AUTH','SYSLOG','LPR','NEWS','UUCP','CRON','AUTHPRIV','FTP','NTP','SECURITY','CONSOLE','SOLARIS-CRON','LOCAL0','LOCAL1','LOCAL2','LOCAL3','LOCAL4','LOCAL5','LOCAL6','LOCAL7')]
        [string]$Facility = 'LOCAL0',
        [string]$SyslogServer,
        [int]$SyslogPort = 514,
        [ValidateSet('File','Syslog','Both')][string]$Mode = 'File',
        [switch]$EnableNetwork,
        [switch]$EnableJson
    )
    # Back-compat: if EnableNetwork is set but Mode not specified explicitly, flip to Syslog
    if ($EnableNetwork -and -not $PSBoundParameters.ContainsKey('Mode')) { $Mode = 'Syslog' }
    # Determine mode booleans
    $fileEnabled = ($Mode -eq 'File' -or $Mode -eq 'Both')
    $netEnabled  = ($Mode -eq 'Syslog' -or $Mode -eq 'Both' -or $EnableNetwork)
    # If file logging enabled and no FilePath provided, compute a default in CWD
    if ($fileEnabled -and [string]::IsNullOrWhiteSpace($FilePath)) {
        $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
        $FilePath = Join-Path -Path (Get-Location) -ChildPath ("openidsync_${ts}.log")
    }
    $script:Logger = @{
        FilePath     = $FilePath
        AppName      = $AppName
        Host         = $env:COMPUTERNAME
        ProcId       = $PID
        FacilityName = $Facility
        Facility     = $null
        UdpClient    = $null
        RemoteEP     = $null
        FileEnabled  = [bool]$fileEnabled
        NetEnabled   = [bool]$netEnabled
        JsonEnabled  = [bool]$EnableJson
        Mode         = $Mode
    }
    $script:Logger.Facility = (Get-SyslogFacility -Name $Facility)
    if ($script:Logger.NetEnabled -and $SyslogServer) {
        try {
            $client = New-Object System.Net.Sockets.UdpClient
            $addr = $null
            try { $addr = [System.Net.IPAddress]::Parse((Resolve-DnsName -Name $SyslogServer -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)) } catch {}
            if (-not $addr) { $addr = ([System.Net.Dns]::GetHostAddresses($SyslogServer) | Select-Object -First 1) }
            if ($addr) {
                $remote = New-Object System.Net.IPEndPoint($addr, $SyslogPort)
                $script:Logger.UdpClient = $client
                $script:Logger.RemoteEP = $remote
            }
        } catch {}
    }
}

function Get-SyslogFacility {
    param([Parameter(Mandatory=$true)][string]$Name)
    $map = @{
        'KERN'=0; 'USER'=1; 'MAIL'=2; 'DAEMON'=3; 'AUTH'=4; 'SYSLOG'=5; 'LPR'=6; 'NEWS'=7;
        'UUCP'=8; 'CRON'=9; 'AUTHPRIV'=10; 'FTP'=11; 'NTP'=12; 'SECURITY'=13; 'CONSOLE'=14; 'SOLARIS-CRON'=15;
        'LOCAL0'=16; 'LOCAL1'=17; 'LOCAL2'=18; 'LOCAL3'=19; 'LOCAL4'=20; 'LOCAL5'=21; 'LOCAL6'=22; 'LOCAL7'=23
    }
    $u = $Name.ToUpper()
    if ($map.ContainsKey($u)) { return [int]$map[$u] }
    return 16
}

function Get-SyslogSeverity {
    param([Parameter(Mandatory=$true)][string]$Level)
    switch ($Level.ToUpper()) {
        'ERROR' { 3 }
        'WARN' { 4 }
        'ACTION' { 5 }
        'PROMPT' { 5 }
        'INFO' { 6 }
        'RESULT' { 6 }
        'DEBUG' { 7 }
        default { 6 }
    }
}

function ConvertTo-SdEscapedValue {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $v = [string]$Value
    $v = $v.Replace('\\','\\\\').Replace('"','\"').Replace(']','\]')
    return $v
}

function New-SyslogLine {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$Level,
        [string]$MsgId = '-',
        [hashtable]$Data
    )
    $sev = Get-SyslogSeverity -Level $Level
    $fac = 16
    if ($script:Logger -and -not [object]::ReferenceEquals($script:Logger.Facility, $null)) { $fac = [int]$script:Logger.Facility }
    $pri = ($fac * 8) + $sev
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
    $hostname = if ($script:Logger) { $script:Logger.Host } else { $env:COMPUTERNAME }
    $app = if ($script:Logger) { $script:Logger.AppName } else { 'openidsync' }
    $proc = if ($script:Logger) { $script:Logger.ProcId } else { $PID }
    $sd = '-'
    if ($Data -and $Data.Count -gt 0) {
        $pairs = @()
        foreach ($k in $Data.Keys) {
            $key = [string]$k
            $val = ConvertTo-SdEscapedValue -Value $Data[$k]
            $pairs += ("{0}={1}" -f $key, ('"' + $val + '"'))
        }
        $sd = "[meta " + ($pairs -join ' ') + "]"
    }
    $id = if ([string]::IsNullOrWhiteSpace($MsgId)) { '-' } else { $MsgId }
    return ("<{0}>1 {1} {2} {3} {4} {5} {6} {7}" -f $pri, $ts, $hostname, $app, $proc, $id, $sd, $Message)
}

function Write-Syslog {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT','DEBUG')][string]$Level = 'INFO',
        [string]$MsgId = '-',
        [hashtable]$Data
    )
    # Machine line (RFC 5424) for file/syslog
    $line = New-SyslogLine -Message $Message -Level $Level -MsgId $MsgId -Data $Data
    if ($script:Logger -and $script:Logger.FileEnabled -and $script:Logger.FilePath) {
        try { [System.IO.File]::AppendAllText($script:Logger.FilePath, $line + [Environment]::NewLine, [System.Text.Encoding]::UTF8) } catch {}
    }
    if ($script:Logger -and $script:Logger.NetEnabled -and $script:Logger.UdpClient -and $script:Logger.RemoteEP) {
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
            [void]$script:Logger.UdpClient.Send($bytes, $bytes.Length, $script:Logger.RemoteEP)
        } catch {}
    }
    
    # Human-readable console line
    $tsHuman = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz')
    $kv = ''
    if ($Data -and $Data.Count -gt 0) {
        $pairs = @()
        foreach ($k in $Data.Keys) {
            $pairs += ("{0}={1}" -f [string]$k, [string]$Data[$k])
        }
        $kv = ' | ' + ($pairs -join ' ')
    }
    $human = ("{0} [{1}] {2}{3}" -f $tsHuman, $Level, $Message, $kv)
    $color = switch ($Level.ToUpper()) {
        'ERROR' { 'Red' }
        'WARN' { 'Yellow' }
        'PROMPT' { 'Cyan' }
        'ACTION' { 'Magenta' }
        'RESULT' { 'Green' }
        'DEBUG' { 'DarkGray' }
        default { 'White' }
    }
    try { Write-Host $human -ForegroundColor $color } catch { Write-Host $human }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PROMPT','ACTION','RESULT','DEBUG')][string]$Level = 'INFO',
        [string]$MsgId = '-',
        [hashtable]$Data
    )
    Write-Syslog -Message $Message -Level $Level -MsgId $MsgId -Data $Data
}

function Close-Logger {
    try {
        if ($script:Logger -and $script:Logger.UdpClient) {
            $script:Logger.UdpClient.Close()
        }
    } catch {}
    try { Remove-Variable -Name Logger -Scope Script -ErrorAction SilentlyContinue } catch {}
}
