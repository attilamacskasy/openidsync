<# 
  - One-way copy with rclone (no deletions on destination)
  - Excludes *.json and *.csv
  - Timestamped log file with -ok or -err<code> suffix
#>
param(
    [string]$Source        = 'C:\Users\Attila\Desktop\Code\openidsync',
    [string[]]$Destination = @('\\172.22.20.1\c$\openidsync','\\172.22.20.2\c$\openidsync'),
    [string]$LogDir      = 'C:\Users\Attila\Desktop\Code\openidsync\rclone-deploy\log',
    # If rclone.exe is not in PATH, set the full path here (e.g. 'C:\Program Files\rclone\rclone.exe')
    [string]$Rclone      = 'rclone.exe'
)

# --- Prep ---------------------------------------------------------------------

# Ensure log directory exists
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Build timestamped log file base name
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$jobName   = 'openidsync'
$baseName  = "$jobName-$timestamp"

# Verify rclone is available
if (-not (Get-Command $Rclone -ErrorAction SilentlyContinue)) {
    Write-Error "rclone not found at '$Rclone'. Add it to PATH or update the script's `\$Rclone` parameter."
    exit 127
}

# Normalize destination list
$destinations = @($Destination | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($destinations.Count -eq 1 -and $destinations[0] -like '*,*') {
    $destinations = @($destinations[0].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
if ($destinations.Count -eq 0) {
    Write-Error 'No destination paths supplied. Provide at least one UNC path via -Destination.'
    exit 1
}

$overallExit = 0
$resultSummary = @()
$i = 0

foreach ($dest in $destinations) {
    $i++
    $destTrim = $dest.Trim()
    $safeLabel = ($destTrim -replace '^[\\/]+', '') -replace '[^A-Za-z0-9]+', '-'
    if ([string]::IsNullOrWhiteSpace($safeLabel)) { $safeLabel = "dest$i" }
    $suffix = if ($destinations.Count -eq 1) { '' } else { "-$safeLabel" }
    $runBase = Join-Path $LogDir ("$baseName$suffix")
    $tmpLog  = "$runBase.tmp.log"

    Write-Host ("Starting rclone copy to {0}" -f $destTrim)

    $arguments = @(
        'copy', $Source, $destTrim,

        # Exclude file types
        '--exclude', '*.json',
        '--exclude', '*.csv',

        # Exclude the rclone-deploy\log folder under the Source
        '--exclude', 'rclone-deploy/log/**',
        '--exclude', '.git/**',

        '--create-empty-src-dirs',
        '--fast-list',
        '--log-file', $tmpLog,
        '--log-level', 'INFO'
    )

    & $Rclone @arguments
    $exitCode = $LASTEXITCODE

    if (Test-Path -LiteralPath $tmpLog) {
        if ($exitCode -eq 0) {
            $finalLog = "$runBase-ok.log"
            Rename-Item -Force -Path $tmpLog -NewName (Split-Path -Leaf $finalLog)
            Write-Host ("SUCCESS: rclone copy completed for {0}. Log: {1}" -f $destTrim, $finalLog)
            $resultSummary += [pscustomobject]@{ Destination = $destTrim; ExitCode = 0; Log = $finalLog }
        } else {
            $finalLog = "$runBase-err$exitCode.log"
            Rename-Item -Force -Path $tmpLog -NewName (Split-Path -Leaf $finalLog)
            Add-Content -Path $finalLog -Value "[{0}] FAILED with exit code {1}" -f (Get-Date), $exitCode
            Write-Error ("FAILED: rclone exited with code {0} for destination {1}. See log: {2}" -f $exitCode, $destTrim, $finalLog)
            $resultSummary += [pscustomobject]@{ Destination = $destTrim; ExitCode = $exitCode; Log = $finalLog }
            if ($overallExit -eq 0) { $overallExit = $exitCode }
        }
    } else {
        Write-Error ("FAILED: Log file not produced for destination {0}. rclone exit code {1}." -f $destTrim, $exitCode)
        $resultSummary += [pscustomobject]@{ Destination = $destTrim; ExitCode = $exitCode; Log = $null }
        if ($overallExit -eq 0) { $overallExit = if ($exitCode -ne 0) { $exitCode } else { 1 } }
    }
}

if ($overallExit -eq 0) {
    Write-Host ''
    Write-Host 'All destinations synchronized successfully:' -ForegroundColor Green
    foreach ($r in $resultSummary) {
        Write-Host ("  {0} -> {1}" -f $r.Destination, $r.Log)
    }
} else {
    Write-Host ''
    Write-Host 'One or more destinations failed:' -ForegroundColor Yellow
    foreach ($r in $resultSummary) {
        $status = if ($r.ExitCode -eq 0) { 'OK' } else { "ERR $($r.ExitCode)" }
        $logPath = if ($r.Log) { $r.Log } else { '(no log)' }
        Write-Host ("  [{0}] {1} -> {2}" -f $status, $r.Destination, $logPath)
    }
}

if ($overallExit -eq 0) { $overallExit = 0 }
exit $overallExit
