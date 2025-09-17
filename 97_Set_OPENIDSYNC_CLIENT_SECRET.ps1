# ----------------------------
# Set OPENIDSYNC_CLIENT_SECRET
# ----------------------------

# Secret value
$secret = "OPENIDSYNC_CLIENT_SECRET"

# 1) Set for current PowerShell session only
$env:OPENIDSYNC_CLIENT_SECRET = $secret
Write-Host "OPENIDSYNC_CLIENT_SECRET set for this session."

# 2) Persist for the current user (survives logoff/reboot)
[System.Environment]::SetEnvironmentVariable("OPENIDSYNC_CLIENT_SECRET", $secret, "User")
Write-Host "OPENIDSYNC_CLIENT_SECRET stored persistently for current user."

# 3) (Optional) Persist system-wide (requires admin)
# Uncomment if needed:
# [System.Environment]::SetEnvironmentVariable("OPENIDSYNC_CLIENT_SECRET", $secret, "Machine")
# Write-Host "OPENIDSYNC_CLIENT_SECRET stored system-wide."

# Check session value
$env:OPENIDSYNC_CLIENT_SECRET

# Check persisted value
[System.Environment]::GetEnvironmentVariable("OPENIDSYNC_CLIENT_SECRET","User")

