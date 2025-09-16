# openidsync

Purpose: Spin up a new on‑premises Active Directory forest and interactively sync Microsoft 365 users into it — all driven by one JSON file and a simple run order (01 → 02 → 03).

## Recent updates
- End-of-run decision summary table shows counts for: `Created`, `Updated`, `SkippedByUPN`, `SkippedByDisplayName`, `SkippedPrompt`, `SkippedEmptyUPN`, `SkippedAdministrator`, `FailedCreate`, `FailedUpdate`.
- Robust skip logic:
	- By User Principal Name (UPN): JSON-configurable tokens; defaults include `#EXT#`, `Temporary`; and always enforce base substrings `archiv`, `temp`.
	- By Display Name: JSON-configurable tokens; defaults include `(Archive)`, `(Temp)`.
- Creation flow hardened for PowerShell 5.1:
	- Credentials CSV is written immediately after a successful `New-ADUser` so passwords are never lost even if a later update fails.
	- `proxyAddresses` are parsed correctly and applied as a typed string array after creation.
	- Country is handled via the `co` attribute post‑creation (no `-Country` parameter to avoid range errors).
- New safety tool: `04_DANGER_Remove_OpenIDSync_Managed_Users.ps1` deletes only users previously created/managed by this tool (those with `[openidsync.org]` in `description`). Includes red‑banner warnings, double confirmation, `-WhatIf`, `-Force`, and automatic backup CSV.

## Quick start
1) Edit the JSON config
- Open `00_OpenIDSync_Config.json` and set at least `DomainName` and `NetBIOSName`.
# openidsync

Purpose: Spin up a new on‑premises Active Directory forest and interactively sync Microsoft 365 users into it — all driven by one JSON file and a simple run order (01 → 02 → 03).

## Recent updates
- End‑of‑run decision summary table shows counts for: `Created`, `Updated`, `SkippedByUPN`, `SkippedByDisplayName`, `SkippedPrompt`, `SkippedEmptyUPN`, `SkippedAdministrator`, `FailedCreate`, `FailedUpdate`.
- Robust skip logic:
	- By User Principal Name (UPN): JSON‑configurable tokens; defaults include `#EXT#`, `Temporary`; and base substrings `archiv`, `temp` are always enforced.
	- By Display Name: JSON‑configurable tokens; defaults include `(Archive)`, `(Temp)`.
- Creation flow hardened for PowerShell 5.1:
	- Credentials CSV is written immediately after a successful `New-ADUser` so passwords are never lost even if a later update fails.
	- `proxyAddresses` are parsed correctly and applied as a typed string array after creation.
	- Country is handled via the `co` attribute post‑creation (no `-Country` parameter to avoid range errors).
- New safety tool: `04_DANGER_Remove_OpenIDSync_Managed_Users.ps1` deletes only users previously created/managed by this tool (those with `[openidsync.org]` in `description`). Includes red‑banner warnings, double confirmation, `-WhatIf`, `-Force`, and automatic backup CSV.

## Quick start
1) Edit the JSON config
- Open `00_OpenIDSync_Config.json` and set at least `DomainName` and `NetBIOSName`.

2) Prepare the server (elevated Windows PowerShell)
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
- `03_Sync_Users_from_M365_CSV_Export.ps1` — Interactive CSV‑driven AD user sync
- `04_DANGER_Remove_OpenIDSync_Managed_Users.ps1` — DANGER ZONE cleanup tool that deletes only users managed by this tool

## Configuration (00_OpenIDSync_Config.json)
- `DomainPromotionConfig`:
	- `DomainName` (required): e.g., `contoso.local`
	- `NetBIOSName` (required): e.g., `CONTOSO`
	- `InstallDNS` (bool): Install DNS on the DC (default true)
	- `DNSDelegation` (bool): Create DNS delegation (optional)
	- `DatabasePath`, `LogPath`, `SYSVOLPath`: NTDS and SYSVOL locations
	- `InstallServerRoles` (bool): Pre‑install roles before DSC (default true)
	- `AdministratorUsername`: Default username for the promotion credential prompt (defaults to `Administrator`)
- `PrepareConfig`:
	- `InstallDNS` (bool)
	- `MinActiveDirectoryDsc` (e.g., `6.2.0`)
	- `MinPSDscResources` (e.g., `2.12.0.0`)
- `UserSyncConfig`:
	- `CsvPath` (string): Path to the Microsoft 365 users CSV export.
	- `DefaultOU` (DN): Distinguished Name where new users are created (and where suggestions/cleanup operate).
	- `SuggestRemovals` (bool): If true, after import it lists AD users with a `mail` attribute in the target OU that are not present in the CSV and are not managed by this tool (it never deletes).
	- `SkipUserBasedOnDisplayName` (array of strings): Substrings that, if found in `Display name`, skip processing that row. Defaults if omitted: `(Archive)`, `(Temp)`.
	- `SkipUserBasedOnUserPrincipalName` (array of strings): Substrings that, if found in UPN, skip processing that row. Defaults if omitted: `#EXT#`, `Temporary`. Additionally, base substrings `archiv` and `temp` are always enforced even if not listed, and all matching is case‑insensitive.

Example JSON:
```json
{
	"DomainPromotionConfig": {
		"DomainName": "contoso.local",
		"NetBIOSName": "CONTOSO",
		"InstallDNS": true,
		"DNSDelegation": false,
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
		"SuggestRemovals": true,
		"SkipUserBasedOnDisplayName": ["(Archive)", "(Temp)"],
		"SkipUserBasedOnUserPrincipalName": ["#EXT#", "Temporary"]
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
- Interactive per‑user preview with `[Y]es/[N]o/[A]ll/[Q]uit` prompt
- Idempotent updates by email (AD `mail` or `proxyAddresses`); creates users when missing
- Skip logic before any prompts:
	- UPN contains any token in `SkipUserBasedOnUserPrincipalName` (case‑insensitive) → skip
	- Display Name contains any token in `SkipUserBasedOnDisplayName` (case‑insensitive) → skip
- Manages `proxyAddresses`, contact info, title/department, and `PasswordNeverExpires`
- Generates strong passwords for new users; logs credentials to a CSV immediately after creation
- Adds/updates Description tag: `[Last update: yyyy-MM-dd HH:mm:ss] [Update count: N] [openidsync.org]`
- Suggests removals for users in the target OU not in CSV (never deletes, and never touches the built‑in `administrator`)

Details & compatibility notes:
- `proxyAddresses` are parsed from the CSV column `Proxy addresses` by splitting on `+` and applying only values matching `smtp:`/`SMTP:`; they are set after creation as a typed `string[]`.
- Country is applied by setting the `co` attribute post‑create/update (the `-Country` parameter is not used to avoid acceptable‑range errors across locales).
- The credentials CSV header is `Email,UserPrincipalName,SamAccountName,GeneratedPassword` and is written into the current working directory next to the audit log.
- The end‑of‑run summary table prints to console and is recorded in the audit log.

## Logs
- Audit log: `openidsync_audit_YYYYMMDD_HHMMSS.log`
- Credentials log: `openidsync_credentials_YYYYMMDD_HHMMSS.csv` (store securely)

## DANGER ZONE — Managed users removal

```diff
- DANGER ZONE: This tool can permanently DELETE AD user objects managed by openidsync.
```

Use `04_DANGER_Remove_OpenIDSync_Managed_Users.ps1` to wipe only users previously created/managed by this tool. A user is considered "managed" if their `description` contains the literal tag `[openidsync.org]`.

What it does:
- Scans the specified `-SearchBase` (defaults to `UserSyncConfig.DefaultOU` from the JSON if omitted).
- Selects only users whose `description` matches `[openidsync.org]`.
- Exports a backup CSV of targets before removal.
- Requires double confirmation unless `-Force` is supplied.
- Supports `-WhatIf` to preview without deleting.

Examples (run in elevated Windows PowerShell):
```powershell
Set-Location "c:\Users\Attila\Desktop\Code\openidsync"
# Preview
./04_DANGER_Remove_OpenIDSync_Managed_Users.ps1 -SearchBase "CN=Users,DC=contoso,DC=local" -WhatIf

# Delete with confirmations
./04_DANGER_Remove_OpenIDSync_Managed_Users.ps1 -SearchBase "CN=Users,DC=contoso,DC=local"

# Delete without prompts (CAUTION)
./04_DANGER_Remove_OpenIDSync_Managed_Users.ps1 -SearchBase "CN=Users,DC=contoso,DC=local" -Force
```

Consequences to understand:
- Deletions are permanent; re‑import will produce new object IDs and new passwords.
- Group memberships and manual changes will be lost.
- The tool never touches the built‑in `administrator` account.

## Requirements
- Elevated Windows PowerShell 5.1 session
- Windows Server with ability to install AD DS (and DNS if selected)
- Internet access to install modules from PSGallery (on first run)

## Troubleshooting
- If `02_Domain_Promotion.ps1` says the `ADDomain` resource or `ActiveDirectoryDsc` is missing, run `01_Prepare_Domain_Promotion.ps1` again.
- Ensure you’re running Windows PowerShell (not PowerShell 7) and as Administrator.
- For network‑restricted servers, pre‑stage modules or configure proxy for PSGallery access.
