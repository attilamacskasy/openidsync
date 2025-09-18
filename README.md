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
- New: Online (Graph API) mode to pull users directly from Entra ID; optional first‑time App Registration creation; CSV mode remains available.
- New safety tool: `04_DANGER_Remove_OpenIDSync_Managed_Users.ps1` deletes only users previously created/managed by this tool (those with `[openidsync.org]` in `description`). Includes red‑banner warnings, double confirmation, `-WhatIf`, `-Force`, and automatic backup CSV.

- Logging enhancements:
	- Structured logging module with three modes: `File`, `Syslog` (UDP), or `Both`.
	- Human‑readable console output; file and syslog keep RFC 5424 machine format.
	- Linux‑style default filenames: `openidsync.log` and `openidsync-credentials.csv`.
	- Configurable via `LoggingConfig` in `00_OpenIDSync_Config.json`; defaults to file‑only.

## Quick reference (how to use it in a nutshell)
Run these in an elevated Windows PowerShell (5.1) prompt from the repo folder.

1) Prepare (installs prerequisites)
```powershell
Set-Location "c:\Users\Attila\Desktop\Code\openidsync"
./01_OpenIDSync_Prepare_Domain_Promotion.ps1
```

2) Promote to first domain controller (DSC)
```powershell
./02_OpenIDSync_Domain_Promotion.ps1
```

3) First sync run (Online): create the App Registration & Service Principal automatically
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source Online -AutoInstallGraphModules -AutoCreateGraphApp -DefaultOU "CN=Users,DC=contoso,DC=local"
```
- The script prints a client secret once. Copy it and set it as an environment variable for your user:
```powershell
setx OPENIDSYNC_CLIENT_SECRET "<YOUR-SECRET-HERE>"
```

4) In the Azure portal: grant admin consent for Microsoft Graph `User.Read.All` (Application)
- Navigate: App registrations → your app (e.g., `OpenIDSync_org__Entra_Sync_Windows_AD`) → `API permissions`.
- Click `Grant admin consent for <your tenant>` (see screenshot in this repo).
- Requires a privileged admin (Global Administrator or Privileged Role Administrator).

5) Second sync run (Online): now uses App-only (Service Principal)
```powershell
# Open a NEW PowerShell window so the environment variable is available
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source Online -AutoInstallGraphModules -DefaultOU "CN=Users,DC=contoso,DC=local"
```
You will see an "Authentication Context Used" block showing App-only with App Name, Client Id, and SP Object Id.

CSV mode is still available any time:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source CSV -CsvPath ".\users.csv" -DefaultOU "CN=Users,DC=contoso,DC=local"
```

If you need to clear cached tokens before switching auth contexts, run:
```powershell
./98_Reset_Azure_Login_Session.ps1
```

## First-time use (safe, least-privilege) — detailed steps

This tool is designed to be safe and transparent:
- Read-only in Entra ID: The app gets only Microsoft Graph `User.Read.All` (Application).
- Optional Directory Readers: You may assign the built‑in `Directory Readers` directory role to the app’s service principal (no write permissions; optional for audit posture).
- Clear credential visibility: Every run prints an "Authentication Context Used" block so you always see whether the script uses your user (Delegated) or the app (App-only), along with IDs.

Step 1 — Create the App & SP
1. Run:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source Online -AutoInstallGraphModules -AutoCreateGraphApp -DefaultOU "CN=Users,DC=contoso,DC=local"
```
2. Sign in interactively when prompted (delegated) so the script can create the App Registration, Service Principal, and a client secret.
3. Copy the client secret printed by the script and set it as an environment variable for your user:
```powershell
setx OPENIDSYNC_CLIENT_SECRET "<YOUR-SECRET-HERE>"
```

Step 2 — Grant admin consent in the Azure portal
1. Open App registrations → your app → API permissions.
2. Click `Grant admin consent for <your tenant>` for Microsoft Graph `User.Read.All` (Application).
3. This step requires a privileged admin (Global Administrator or Privileged Role Administrator).

Step 3 — Use App-only on the next run
1. Open a NEW Windows PowerShell window (to load the environment variable).
2. Run:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source Online -AutoInstallGraphModules -DefaultOU "CN=Users,DC=contoso,DC=local"
```
3. Confirm the "Authentication Context Used" shows App-only with your app’s identifiers.

## Why this is safe (least privilege by design)

- Least privilege: Only Graph `User.Read.All` (Application) is granted to the app. The script never writes to Entra ID.
- Transparent auth: The script prints which identity is used (App/SP or Delegated) with names and IDs.
- No secrets on disk: The client secret is never written to files. You provide it via an environment variable (default `OPENIDSYNC_CLIENT_SECRET`).
- Auditable actions: A timestamped audit log and a credentials CSV (for new AD users) are written to the working directory.
- On‑prem changes are explicit: Each user is previewed, and you decide `[Y]es/[N]o/[A]ll/[Q]uit`. Updates are idempotent.

## Files
- `00_OpenIDSync_Config.json` — Central configuration for all scripts
- `01_OpenIDSync_Prepare_Domain_Promotion.ps1` — Installs prerequisites (features and modules) and verifies DSC resources
- `02_OpenIDSync_Domain_Promotion.ps1` — Promotes the server to the first DC using DSC (`ADDomain` resource)
- `03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1` — Online (Graph) or CSV user sync into AD
- `04_OpenIDSync_DANGER_Remove_Managed_Users.ps1` — DANGER ZONE cleanup tool that deletes only users managed by this tool
- `97_Set_OPENIDSYNC_CLIENT_SECRET.ps1` — Helper to set the `OPENIDSYNC_CLIENT_SECRET` env var
- `98_Reset_Azure_Login_Session.ps1` — Clears cached Graph/Az sessions and token caches
- `99_Get-Module.ps1` — Diagnostics for loaded modules

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
 
- `LoggingConfig`:
	- `Mode` (string): `File`, `Syslog`, or `Both`. Default: `File`.
	- `FilePath` (string): Path for the audit log. Default: `./openidsync.log` (Linux-like naming).
	- `SyslogServer` (string): Hostname or IP of a UDP syslog server.
	- `SyslogPort` (int): UDP port of the syslog server. Default: `514`.
  The sync script (`03_...`) reads this block and initializes logging accordingly. Console echo is preserved. When `Mode` is `Syslog` or `Both`, logs are also sent via UDP to the configured syslog endpoint.
 
- `00_OpenIDSync_OnlineSyncConfig.json` (auto‑populated; no secrets):
	- `TenantId` (string): Entra ID tenant ID.
	- `ClientId` (string): App Registration (application) ID.
	- `SpObjectId` (string): Service principal object id.
	- `PreferredSource` (string): `CSV` or `Online` default when not provided via CLI.
	- `ClientSecretEnvVar` (string): Environment variable name used to read the client secret (default `OPENIDSYNC_CLIENT_SECRET`).

Important: The online sync IDs are only persisted in `00_OpenIDSync_OnlineSyncConfig.json`. The main config `00_OpenIDSync_Config.json` is never auto‑modified by the online sync code.

Example JSON (trimmed):
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

And the separate online sync config file `00_OpenIDSync_OnlineSyncConfig.json`:

```json
{
	"OnlineSyncConfig": {
		"TenantId": "00000000-0000-0000-0000-000000000000",
		"ClientId": "11111111-1111-1111-1111-111111111111",
		"SpObjectId": "22222222-2222-2222-2222-222222222222",
		"PreferredSource": "Online",
		"ClientSecretEnvVar": "OPENIDSYNC_CLIENT_SECRET"
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
- Reads users from either:
  - Online: Microsoft Graph (Entra ID) — App‑only or delegated connection
  - CSV: Microsoft 365 Admin “Active users” export
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

Graph prerequisites:
- For Online mode with existing App Registration: assign Microsoft Graph Application permission `User.Read.All` and grant admin consent. Provide `TenantId`, `ClientId`, and set the secret via env var.
- For `-AutoCreateGraphApp`: sign in with delegated scopes `Application.ReadWrite.All` and `Directory.ReadWrite.All` to create an app, service principal, client secret, and attempt to grant `User.Read.All`. If consent fails (e.g., Entra Free or insufficient privileges), grant it later in the portal.
- `-AssignDirectoryReaderToApp` (optional): assigns the built-in directory role "Directory Readers" to your app's service principal. Requires delegated admin capable of role assignments (e.g., Privileged Role Administrator or Global Administrator). This does not grant write capabilities; it's optional.

Security notes for auditors:
- App-only runs are strictly read-only against Microsoft Graph. Only `User.Read.All` (Application) is granted.
- If you choose to assign Directory Readers via `-AssignDirectoryReaderToApp`, the delegated sign-in will request `RoleManagement.ReadWrite.Directory` to perform the one-time role assignment; this is not needed for normal syncing.

Graph modules (PowerShell 5.1):
- The script avoids importing the `Microsoft.Graph` meta-module to prevent function-capacity overflow. It loads only the needed submodules.
- Required: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Identity.DirectoryManagement`.
- You can let the script install them with `-AutoInstallGraphModules`, or install manually:
```powershell
Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Applications,Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

## Logs
- Audit log: `openidsync.log` (default path `./openidsync.log`; configurable via `LoggingConfig.FilePath`)
- Credentials log: `openidsync-credentials.csv` (store securely; written alongside the audit log)

Notes:
- Console output is human‑readable; file and syslog outputs use RFC 5424 machine format for ingestion.
- Default logging mode is file‑only. To send logs to a remote syslog server, set `LoggingConfig.Mode` to `Syslog` or `Both` and configure `SyslogServer`/`SyslogPort`.
- Rotation is not handled by the script. For long‑running systems, use external rotation (e.g., logrotate) or periodically archive the file.

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
- Graph import error "function capacity 4096 exceeded": Windows PowerShell 5.1 has a default function cap of 4096 and the Graph submodules can exceed it. This script automatically raises the limit early. If you still need to set it manually in your session:
```powershell
$global:MaximumFunctionCount = 32768
```
