<# 
  - One-way copy with rclone (no deletions on destination)
  - Excludes *.json and *.csv
  - Timestamped log file with -ok or -err<code> suffix
#>
param(
    [string]$Source      = 'C:\Users\Attila\Desktop\Code\openidsync',
    [string]$Destination = '\\172.22.20.1\c$\Users\Administrator\Desktop\Code\openidsync',
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
$basePath  = Join-Path $LogDir "$jobName-$timestamp"
$tmpLog    = "$basePath.tmp.log"

# Verify rclone is available
if (-not (Get-Command $Rclone -ErrorAction SilentlyContinue)) {
    Write-Error "rclone not found at '$Rclone'. Add it to PATH or update the script's `\$Rclone` parameter."
    exit 127
}

# --- Run rclone copy ----------------------------------------------------------
# NOTE:
#   - 'copy' = copy new/changed files; DOES NOT delete extras on destination.
#   - --exclude patterns applied to source.
#   - Add '--use-json-log' if you prefer machine-readable logs.
$arguments = @(
    'copy', $Source, $Destination,

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

# --- Finalize log & exit code -------------------------------------------------
if ($exitCode -eq 0) {
    $finalLog = "$basePath-ok.log"
    Rename-Item -Force -Path $tmpLog -NewName (Split-Path -Leaf $finalLog)
    Write-Host "SUCCESS: rclone copy completed. Log: $finalLog"
} else {
    $finalLog = "$basePath-err$exitCode.log"
    Rename-Item -Force -Path $tmpLog -NewName (Split-Path -Leaf $finalLog)
    Add-Content -Path $finalLog -Value "[{0}] FAILED with exit code {1}" -f (Get-Date), $exitCode
    Write-Error "FAILED: rclone exited with code $exitCode. See log: $finalLog"
}

exit $exitCode
