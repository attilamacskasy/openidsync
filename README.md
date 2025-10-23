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

- Dashboard-first setup:
	- Launching the sync script now opens an interactive dashboard that highlights any outstanding requirements before a run can start.
	- Requirement banners disappear automatically once satisfied, and option `12) View requirement details` remains available for a full audit trail.
	- Sync mode, source, and target controls unlock only after all requirements pass, keeping new operators on the happy path.
- Unattended mode:
	- `-NonInteractive` switch for scheduled runs; combines well with `-AllUsers` to process every user without prompts.
	- `-NonInteractive` requires a defined source: either pass `-Source Online|CSV` or set `UserSyncConfig.PreferredSource` in `00_OpenIDSync_Config.json`. If missing, the script stops with guidance.
	- `PreferredSource` moved into the main config under `UserSyncConfig` (removed from the online config file).

- App creation permissions: First‑run app creation now requests Graph Application permissions `User.Read.All` and `Directory.Read.All` and attempts to grant admin consent programmatically.

- Logging enhancements:
	- Structured logging module with three modes: `File`, `Syslog` (UDP), or `Both`.
	- Human‑readable console output; file and syslog keep RFC 5424 machine format.
	- Linux‑style default filenames: `openidsync.log` and `openidsync-credentials.csv`.
	- Configurable via `LoggingConfig` in `00_OpenIDSync_Config.json`; defaults to file‑only.

### New Features (Groups, Memberships, Privileged Elevation, Multi-Target Prep)
- Group Synchronization (Entra → AD):
	- Creates corresponding AD groups for Entra Security, M365 (Unified), and Distribution groups.
	- Prefix policy: `Sec_` for Security, `Team_` for M365 (Unified), `Distribution_` for Distribution lists; `Other` groups keep original root.
	- Name normalization pipeline: removes Hungarian / accented diacritics, replaces spaces & dots with underscores, strips non `[A-Za-z0-9_]`, collapses repeated `_`, trims to 20 chars (AD `sAMAccountName` limit), removes trailing underscores.
	- Safely skips creation if normalized `sAMAccountName` already exists.
- Group Membership Parity:
	- For each mapped group, resolves Entra members (users only) and enforces exact membership in AD (adds missing, removes extraneous) with per-group logging: `Memberships set for <Group>: +X/-Y`.
	- Interactive membership mode options: `[A]ll / [P]rompt / [S]kip` plus `[Q]uit` early abort.
- Execution Modes Framework:
	- For Users, Groups, Memberships individually: `All`, `Prompt`, or `Skip` (each selectable interactively or via `SyncModes` in JSON for background runs).
	- Interactive menu now includes a `[Q]uit (abort run)` option at each stage.
- Global Administrator Elevation Logic (Exception Policy v1):
	- Detects Global Administrators (Company Administrator directory role) from Entra.
	- Expands group-assigned role memberships (transitive expansion) to individual user UPNs.
	- Ensures each detected Global Admin’s AD counterpart is added to `Domain Admins` (idempotent) and counts successful/confirmed elevations (`DomainAdminElevations`).
	- Logs individual elevation actions with `RESULT` level: `Elevated (GLOBAL_ADMIN) user@domain -> Domain Admins`.
	- Designed for future extension to additional role → group mappings.
- Dynamic Source / Target Labels:
	- Display & logging no longer hardcode “Microsoft Entra ID” / “Windows Active Directory”.
	- New `-Target` parameter (currently defaults to `WindowsAD`), paving way for additional targets (e.g., Keycloak, other LDAP, cloud directories).
- Early Quit Options Everywhere:
	- Per-group and per-membership reconciliation prompts accept `[Q]uit` for immediate, clean abort with summary of actions taken so far.

### Summary Counters Extended
- Added: `GroupsCreated`, `GroupsExisting`, `GroupMembersAdded`, `GroupMembersRemoved`, `DomainAdminElevations`.
- All counters dynamically included in the end-of-run summary (only non-zero displayed).

### Internal Architecture Enhancements
- Modular Domain-Driven Layout under `modules/`:
	- `microsoft-graph/Graph.ps1`: Graph connectivity + user, group, role/member queries.
	- `sync-targets/WindowsAD.ps1`: User provisioning/update logic.
	- `sync-targets/WindowsAD.Groups.ps1`: Group provisioning + membership parity.
	- `ad/ActiveDirectory.ps1`: AD helper + elevation exception orchestration.
	- `common/*`: Config load/save, summary builder, canonical contracts scaffolding.
- Exception Elevation Framework: Central function `Invoke-OpenIdSyncExceptionElevation` takes UPN + tag list (currently recognizes `GLOBAL_ADMIN`).
- HashSet-Based De-duplication: Global Admin expansion uses a .NET `HashSet[string]` to ensure unique UPNs before elevation enforcement.

### Planned / Roadmap (Not Yet Implemented)
- Multi-source providers: Keycloak, AWS IAM Identity Center, GCP Cloud Identity, OCI IAM (placeholders present in `sync-sources/Providers.ps1`).
- Multi-target adapters: Additional target backends beyond Windows AD.
- Collision handling for normalized group name conflicts (suffix strategy).
- Dry-run mode for group & membership sync (preview diffs without applying).
- Enhanced exception policies (e.g., Exchange Admin → specific AD group, Teams Admin → delegated group).
- Canonical object orchestration (wiring `Contracts.ps1` + `Orchestrator.ps1` end-to-end for any-source → any-target transforms).

## Interactive dashboard workflow
Running `./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1` interactively now launches a full-screen dashboard that summarizes your configuration, highlights any missing prerequisites, and lets you start synchronization only when everything is ready.

- Requirement cards show in red while unmet and disappear automatically once satisfied. After that, option `12) View requirement details (all passed)` gives you a read-only audit view on demand.
- Configuration, password-log, and logging summaries appear at the top of the screen so you always know which files the run will touch.
- Sync mode, source, target, and password-redaction tools unlock immediately after all requirements pass; until then you only see the remediation actions you need.

```
Menu:

	1) Fix Requirement 1 - Install PowerShell Graph API Modules [-AutoInstallGraphModules]
	2) Fix Requirement 2 - Create App Registration / Service Principal for credential-less use [-AutoCreateGraphApp]
	3) Fix Requirement 3 - Check if API permissions are granted for Service Principal
	4) Set user sync mode [S]KIP | [A]LL | [P]ROMPT (current: ALL)
	5) Set group sync mode [S]KIP | [A]LL | [P]ROMPT (current: ALL)
	6) Set group membership sync mode [S]KIP | [A]LL | [P]ROMPT (current: ALL)
	7) Change Source Directory
	8) Change Target Directory
	9) Start Synchronization
 10) Remove passwords from Password credentials file (after you backed up initial/temporary passwords in secure location)
 11) View configuration details
 12) View requirement details (all passed)
 99) Exit
```

Only options 1–3 and 11 appear when you first launch the dashboard. As soon as the requirements are green, the rest of the menu is revealed automatically.

## Meeting the requirements is easy
Each prerequisite has a dedicated action and clear on-screen guidance:

- **Requirement 1 — Install Microsoft Graph modules**: Option 1 calls the bundled installer, pulls the exact submodules (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Groups`), and refreshes the requirement card in-place. No manual module hunting required.
- **Requirement 2 — Create the app registration**: Option 2 signs you in once, creates the app + service principal, saves the identifiers to `00_OpenIDSync_OnlineSyncConfig.json`, and prints the generated client secret with masking guidance. The dashboard reminds you to store the secret by running `setx OPENIDSYNC_CLIENT_SECRET "<SECRET>"` and never writes the value to disk.
- **Requirement 3 — Verify API permissions**: Option 3 runs `Test-GraphReadOperations`, reads real directory data through Microsoft Graph, and surfaces any missing consent with friendly messages. Successful results are cached in `00_OpenIDSync_OnlineSyncConfig.json.PermissionVerification`, so subsequent dashboard launches open instantly while still letting you force a refresh if desired.

The net effect: new operators typically complete all three steps in a couple of minutes, and repeat runs skip straight to the sync options because the requirements stay satisfied and hidden.

---

## How to use OpenIDSync (brief)
Run these in an elevated Windows PowerShell (5.1) prompt from the repo folder.

1) **Prepare the host** (installs Windows/PowerShell prerequisites)
```powershell
Set-Location "c:\Users\Attila\Desktop\Code\openidsync"
./01_OpenIDSync_Prepare_Domain_Promotion.ps1
```

2) **Promote to the first domain controller** (Desired State Configuration)
```powershell
./02_OpenIDSync_Domain_Promotion.ps1
```

3) **Launch the dashboard and satisfy requirements**
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -DefaultOU "CN=Users,DC=contoso,DC=local"
```
- Choose option **1** if Graph modules are missing; the installer runs automatically.
- Choose option **2** to create the App Registration and Service Principal. The dashboard prints the client secret once—store it with:
```powershell
setx OPENIDSYNC_CLIENT_SECRET "<YOUR-SECRET-HERE>"
```
- Choose option **3** to verify Graph permissions. Once all requirements pass, the dashboard expands to show sync options.
- Option **11** always shows configuration details; option **12** appears after the requirements are green so you can review the success history.

4) **Start the synchronization**
- Press **9** from the dashboard to launch the user/group synchronization workflow.
- Use options **4–6** ahead of time if you want to switch between `All`, `Prompt`, or `Skip` processing modes for users, groups, or memberships.

5) **Optional maintenance**
- Option **10** redacts generated passwords from the credentials CSV after you store them elsewhere.
- Option **99** exits the dashboard; requirements stay cached so the next run jumps straight to the expanded menu.

CSV mode is still available any time—change the source via option **7** or pass `-Source CSV` on the command line for non-interactive runs:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -Source CSV -CsvPath ".\users.csv" -DefaultOU "CN=Users,DC=contoso,DC=local"
```

If you need to clear cached tokens before switching auth contexts, run:
```powershell
./98_Reset_Azure_Login_Session.ps1
```

### Unattended/scheduled runs (non-interactive)
```powershell
# Online (App-only) — ensure the client secret env var exists for the scheduled account
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -NonInteractive -AllUsers -Source Online -DefaultOU "CN=Users,DC=contoso,DC=local"

# CSV
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -NonInteractive -AllUsers -Source CSV -CsvPath ".\users.csv" -DefaultOU "CN=Users,DC=contoso,DC=local"
```
Notes for non‑interactive:
- If `-Source` isn’t passed and `UserSyncConfig.PreferredSource` isn’t set, the script will stop with guidance to set it (recommended: `Online`).
- Bootstrap the app registration and Graph permissions interactively first (use dashboard options 1–3), then schedule non-interactive runs.


## First-time use (safe, least-privilege) — detailed steps

This tool is designed to be safe and transparent:
- Read-only in Entra ID: The app gets Microsoft Graph `User.Read.All` and `Directory.Read.All` (Application).
- Optional Directory Readers: You may assign the built‑in `Directory Readers` directory role to the app’s service principal (no write permissions; optional for audit posture).
- Clear credential visibility: Every run prints an "Authentication Context Used" block so you always see whether the script uses your user (Delegated) or the app (App-only), along with IDs.

Step 1 — Launch the dashboard and create the App & SP
1. Run:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -DefaultOU "CN=Users,DC=contoso,DC=local"
```
2. In the dashboard, choose option **1** if the Microsoft Graph modules are missing, then choose option **2**. Sign in interactively when prompted so the script can create the App Registration, Service Principal, and a client secret.
3. The dashboard prints the client secret once. Copy it immediately and set it as an environment variable for your user:
```powershell
setx OPENIDSYNC_CLIENT_SECRET "<YOUR-SECRET-HERE>"
```
4. (Optional) Run option **3** to verify permissions. Until admin consent is granted, you will see an authorization warning that explains what is missing.

Step 2 — Grant admin consent in the Azure portal
1. Open App registrations → your app → API permissions.
2. Click `Grant admin consent for <your tenant>` for Microsoft Graph `User.Read.All` and `Directory.Read.All` (Application).
3. This step requires a privileged admin (Global Administrator or Privileged Role Administrator).

Step 3 — Use App-only on the next run
1. Open a NEW Windows PowerShell window (to load the environment variable).
2. Run:
```powershell
./03_OpenIDSync_Sync_M365-EntraID_Windows-AD.ps1 -DefaultOU "CN=Users,DC=contoso,DC=local"
```
3. The dashboard will reopen with the requirement cards hidden. Select option **3** to confirm permissions succeed, then press **9** to start the sync. The run summary prints an "Authentication Context Used" block showing App-only with your app’s identifiers.

## Why this is safe (least privilege by design)

- Least privilege: Only Graph read-only application permissions are granted to the app: `User.Read.All` and `Directory.Read.All`. The script never writes to Entra ID.
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
	- `PreferredSource` (string): Default source when `-Source` isn’t provided. `Online` (recommended) or `CSV`.
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
		"PreferredSource": "Online",
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
  - Online: Microsoft Graph (Entra ID) — App-only or delegated connection
  - CSV: Microsoft 365 Admin “Active users” export
	- Interactive runs: the dashboard (options **7** and **8**) controls the source/target before you press **9** to start synchronization.
	- Non-interactive runs: require `-Source` or `UserSyncConfig.PreferredSource`.
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
- For Online mode with existing App Registration: assign Microsoft Graph Application permissions `User.Read.All` and `Directory.Read.All` and grant admin consent. Provide `TenantId`, `ClientId`, and set the secret via env var.
- For `-AutoCreateGraphApp`: sign in with delegated scopes `Application.ReadWrite.All` and `Directory.ReadWrite.All` to create an app, service principal, client secret, and attempt to grant `User.Read.All` and `Directory.Read.All`. If consent fails (e.g., Entra Free or insufficient privileges), grant it later in the portal.
- `-AssignDirectoryReaderToApp` (optional): assigns the built-in directory role "Directory Readers" to your app's service principal. Requires delegated admin capable of role assignments (e.g., Privileged Role Administrator or Global Administrator). This does not grant write capabilities; it's optional.

Security notes for auditors:
- App-only runs are strictly read-only against Microsoft Graph. `User.Read.All` and `Directory.Read.All` (Application) are granted.
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
