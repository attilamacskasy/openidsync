# openidsync

Purpose: Spin up a new on‑premises Active Directory forest and interactively sync Microsoft 365 users into it — all driven by one JSON file and a simple run order (01 → 02 → 03).

## Quick start
1) Edit the JSON config
- Open `00_OpenIDSync_Config.json` and set at least `DomainName` and `NetBIOSName`.

2) Prepare the server (elevated PowerShell)
```powershell
Set-Location "c:\Users\Attila\Desktop\Code\openidsync"
./01_Prepare_Domain_Promotion.ps1
```

3) Promote to first domain controller (DSC)
```powershell
./02_Domain_Promotion.ps1
```
You will be prompted for:
- DSRM (Safe Mode Administrator) password
- A setup credential (use local `COMPUTERNAME\Administrator` unless you changed `AdministratorUsername` in JSON)

4) Sync Microsoft 365 users from CSV
```powershell
./03_Sync_Users_from_M365_CSV_Export.ps1
# Example override
./03_Sync_Users_from_M365_CSV_Export.ps1 -CsvPath ".\users_9_15_2025 9_17_18 PM.csv" -DefaultOU "CN=Users,DC=macskasy,DC=com"
```

## Files
- `00_OpenIDSync_Config.json` — Central configuration for all scripts
- `01_Prepare_Domain_Promotion.ps1` — Installs prerequisites (features and modules) and verifies DSC resources
- `02_Domain_Promotion.ps1` — Promotes the server to the first DC using DSC (`ADDomain` resource)
- `03_Sync_Users_from_M365_CSV_Export.ps1` — Interactive CSV-driven AD user sync

## Configuration (00_OpenIDSync_Config.json)
- `DomainPromotionConfig`:
	- `DomainName` (required): e.g., `contoso.local`
	- `NetBIOSName` (required): e.g., `CONTOSO`
	- `InstallDNS` (bool): Install DNS on the DC (default true)
	- `DNSDelegation` (bool): Create DNS delegation (optional)
	- `DatabasePath`, `LogPath`, `SYSVOLPath`: NTDS and SYSVOL locations
	- `InstallServerRoles` (bool): Pre-install roles before DSC (default true)
	- `AdministratorUsername`: Default username for the promotion credential prompt (defaults to `Administrator`)
- `PrepareConfig`:
	- `InstallDNS` (bool), `MinActiveDirectoryDsc` (e.g., `6.2.0`), `MinPSDscResources` (e.g., `2.12.0.0`)
- `UserSyncConfig`:
	- `CsvPath` (string), `DefaultOU` (DN), `SuggestRemovals` (bool)

Example:
```json
{
	"DomainPromotionConfig": {
		"DomainName": "contoso.local",
		"NetBIOSName": "CONTOSO",
		"InstallDNS": true,
		"DatabasePath": "C:\\Windows\\NTDS",
		"LogPath": "C:\\Windows\\NTDS",
		"SYSVOLPath": "C:\\Windows\\SYSVOL",
		"InstallServerRoles": true,
		"AdministratorUsername": "Administrator"
	},
	"PrepareConfig": {
		"InstallDNS": true,
		"MinActiveDirectoryDsc": "6.2.0",
		"MinPSDscResources": "2.12.0.0"
	},
	"UserSyncConfig": {
		"CsvPath": ".\\users.csv",
		"DefaultOU": "CN=Users,DC=contoso,DC=local",
		"SuggestRemovals": true
	}
}
```

## What happens in each step
1) Prepare (`01_...`)
- Ensures TLS 1.2, NuGet provider, trusted PSGallery
- Installs PowerShell modules: `PSDscResources`, `ActiveDirectoryDsc`
- Installs Windows features: `AD-Domain-Services` and optional `DNS`
- Verifies DSC resource `ADDomain` is available (diagnostics + retry)

2) Promote (`02_...`)
- Uses DSC `ADDomain` (from `ActiveDirectoryDsc`) to create a new forest/domain
- Respects `InstallDNS`, NTDS/SYSVOL paths, and sets `ForestMode`/`DomainMode` to `WinThreshold`
- Configures LCM to reboot and continue configuration as needed

3) Sync users (`03_...`)
- Reads Microsoft 365 Admin “Active users” CSV export
- Interactive per-user preview with `[Y]es/[N]o/[A]ll` prompt
- Idempotent updates by email (AD `mail` or `proxyAddresses`); creates users when missing
- Manages `proxyAddresses`, contact info, title/department, and `PasswordNeverExpires`
- Generates strong passwords for new users; logs credentials to a CSV
- Adds/updates Description tag: `[Last update: yyyy-MM-dd HH:mm:ss] [Update count: N] [openidsync.org]`
- Suggests removals for users in the target OU not in CSV (never deletes, and never touches the built‑in `administrator`)

## Logs
- Audit log: `openidsync_audit_YYYYMMDD_HHMMSS.log`
- Credentials log: `openidsync_credentials_YYYYMMDD_HHMMSS.csv` (store securely)

## Requirements
- Elevated Windows PowerShell 5.1 session
- Windows Server with ability to install AD DS (and DNS if selected)
- Internet access to install modules from PSGallery (on first run)

## Troubleshooting
- If `02_Domain_Promotion.ps1` says the `ADDomain` resource or `ActiveDirectoryDsc` is missing, run `01_Prepare_Domain_Promotion.ps1` again.
- Ensure you’re running Windows PowerShell (not PowerShell 7) and as Administrator.
- For network-restricted servers, pre-stage modules or configure proxy for PSGallery access.
