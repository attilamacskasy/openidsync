@echo off
setlocal ENABLEEXTENSIONS

REM Move to the directory where this script resides (equivalent to Set-Location to current/script dir)
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul 2>&1
echo [OpenIDSync] Working directory set to: "%CD%"

echo.
echo [OpenIDSync] This helper prepares PowerShell by setting the Execution Policy.
echo [OpenIDSync] Choose how you want to apply it:
echo   [1] Bypass -Scope CurrentUser   ^(recommended default^)
echo   [2] Bypass -Scope Process       ^(affects only this session^)
echo.
set "choice="
set /p choice="Enter choice (1/2) [default: 1]: "

if /I "%choice%"=="2" (
	set "EP_SCOPE=Process"
) else (
	set "EP_SCOPE=CurrentUser"
)

echo [OpenIDSync] Applying: Set-ExecutionPolicy Bypass -Scope %EP_SCOPE% -Force
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope %EP_SCOPE% -Force"
if errorlevel 1 (
	echo [OpenIDSync] WARNING: Failed to set Execution Policy. You may need admin rights or different policy settings. ^(ErrorLevel=%ERRORLEVEL%^)
) else (
	echo [OpenIDSync] Execution Policy applied successfully.
)

echo.
echo [OpenIDSync] Environment is ready. You can now run the OpenIDSync PowerShell scripts in this folder.
echo         Examples: .\01_OpenIDSync_Prepare_Domain_Promotion.ps1   or   .\03_OpenIDSync_Sync_Users_from_M365_CSV_Export.ps1
echo.
pause

popd >nul 2>&1
endlocal
