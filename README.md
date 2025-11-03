# OpenIDSync.org

OpenIDSync.org synchronizes users, groups, and their memberships from Microsoft Entra ID (online) or an offline Microsoft 365 CSV into Windows Active Directory without requiring premium licensing.

| Source → Target | Windows Active Directory |
| --- | --- |
| Microsoft Entra ID (online) | ✅ |
| Microsoft 365 Admin CSV export | ✅ |

## Quickstart

1. Open **Windows PowerShell 5.1** as Administrator and change to the repo folder.
2. Run `./OpenIDSync.ps1`. The dashboard checks for requirements and walks you through Graph module installation, App Registration creation, and permission verification.
3. When the requirements turn green, choose your sync source/target, press **9**, and follow the guided user/group sync workflow.
4. Review the end-of-run summary, then rerun, return to the menu, or quit.

The dashboard remembers satisfied requirements between runs, so repeat launches jump straight to the sync options.

---

## Interactive dashboard tour

`OpenIDSync.ps1` opens a full-screen menu that exposes everything you need in one place. Options unlock gradually: you’ll only see the next set of actions once the prerequisites are satisfied.

| Option | Unlocks when… | What it does |
| --- | --- | --- |
| **1** | Requirement 1 not complete | Installs the exact Microsoft Graph modules required (`Authentication`, `Users`, `Applications`, `Identity.DirectoryManagement`, `Groups`). Equivalent to running `-AutoInstallGraphModules`.
| **2** | Requirement 2 not complete | Creates the Microsoft Entra App Registration and service principal, then writes the identifiers into `OpenIDSync_OnlineSyncConfig.json`. Prompts you once to copy the generated client secret.
| **3** | Requirement 3 not  complete | Calls `Test-GraphReadOperations` to verify delegated/app-only Graph access. Caches results so later runs start instantly, but lets you recheck on demand.
| **4** | All requirements complete | Sets the **user** sync mode (`All`, `Prompt`, `Skip`) for the coming run.
| **5** | All requirements complete | Sets the **group** sync mode (`All`, `Prompt`, `Skip`).
| **6** | All requirements complete | Sets the **group membership** parity mode (`All`, `Prompt`, `Skip`).
| **7** | All requirements complete | Switches the sync source (`Online`, `CSV`, or any future provider in `modules/sync-sources`).
| **8** | All requirements complete | Switches the target (`WindowsAD` today; other adapters plug into `modules/sync-targets`).
| **9** | All requirements complete | Starts the synchronization flow using your current modes and source/target selection.
| **10** | All requirements complete | Scrubs generated passwords from `openidsync-credentials.csv` after you store them elsewhere.
| **11** | Always visible | Displays the effective configuration: sync modes, log destination, client IDs, paths, and summary of pending requirements.
| **12** | Requirement checks passed once | Shows historical requirement results even after the cards disappear, giving you an audit trail.
| **13** | All requirements complete | Exports a VPN device CSV (`firstName,lastName,comment`) for OpenGWTools Roadwarriors based on the Entra Office location field.
| **99** | Always visible | Exits the dashboard.

After a sync completes, a post-run menu lets you rerun immediately, return to the dashboard, or exit — the choice is also logged for traceability.

---

## How the sync flow works

### Happy-path run

1. **Requirements check** – Options 1–3 disappear once satisfied, revealing the sync controls.
2. **Configure modes** – Choose per-object handling for users, groups, and memberships (`All`, `Prompt`, `Skip`).
3. **Select source/target** – Default is Microsoft Entra ID → Windows AD, but CSV mode is always available.
4. **Press 9** – The orchestrator reads the config, loads the modules under `modules/`, and starts the guided sync.
5. **Review output** – Each creation/update is shown on-screen (or auto-applied in `All` mode), and summary counters print at the end.

### Non-interactive scheduling

You can run unattended jobs once the requirements have been satisfied at least once. Examples:

```powershell
./OpenIDSync.ps1 -NonInteractive -AllUsers -Source Online -DefaultOU "CN=Users,DC=contoso,DC=local"
./OpenIDSync.ps1 -NonInteractive -AllUsers -Source CSV -CsvPath ".\users.csv" -DefaultOU "CN=Users,DC=contoso,DC=local"
```

Notes:

- Always prime the environment interactively first so the App Registration and permission cache exist.
- If you omit `-Source`, make sure `UserSyncConfig.PreferredSource` is set in `OpenIDSync_Config.json`.
- Non-interactive runs respect the same skip logic, logging, and summary counters as the dashboard.

---

## Configuration files

Two JSON files steer OpenIDSync. The dashboard never writes secrets to disk; you control everything from these files and environment variables.

### `OpenIDSync_Config.json`

The main configuration file is loaded on every run. Key sections:

- **`DomainPromotionConfig`** – Used by the optional promotion scripts (`01`/`02`). Defines domain name, NetBIOS name, DNS toggles, NTDS paths, and default admin username.
- **`PrepareConfig`** – Controls update/install behavior for prerequisite modules and Windows features (e.g., `ActiveDirectoryDsc` minimum version).
- **`UserSyncConfig`** – Governs the sync engine.
  - `DefaultOU`: Target OU for new users and removal suggestions.
  - `PreferredSource`: Default when you don’t pass `-Source` (`Online` or `CSV`).
  - `CsvPath`: Default CSV file path.
  - `SuggestRemovals`: After a run, list AD users in the OU that weren’t present in the source. No deletions happen automatically.
  - `SkipUserBasedOnDisplayName` / `SkipUserBasedOnUserPrincipalName`: Case-insensitive substrings that auto-skip entries (`(Archive)`, `(Temp)`, `#EXT#`, `Temporary` by default; `archiv`/`temp` enforced even if omitted).
  - `GroupSecurityExceptions`: Non-security source groups that should receive an additional `Sec_` prefixed security clone in AD.
  - `ForceUpdateUserDescriptions` / `ForceUpdateGroupDescriptions`: Force description rewrites even if nothing else changes (default `false`).
- **`LoggingConfig`** – Chooses `File`, `Syslog`, or `Both`. Controls file path (`./openidsync.log` by default) and optional syslog host/port.
- **`DangerZoneSkip`** (optional) – Lists users/groups that the dashboard danger-zone tools must never remove.

### `OpenIDSync_OnlineSyncConfig.json`

Auto-populated by option 2 (or by running `./OpenIDSync.ps1 -AutoCreateGraphApp`). It stores identifiers but **never** the client secret:

```json
{
  "OnlineSyncConfig": {
    "TenantId": "00000000-0000-0000-0000-000000000000",
    "ClientId": "11111111-1111-1111-1111-111111111111",
    "SpObjectId": "22222222-2222-2222-2222-222222222222",
    "ClientSecretEnvVar": "OPENIDSYNC_CLIENT_SECRET"
  },
  "PermissionVerification": {
    "LastChecked": "2024-05-01T12:34:56Z",
    "Succeeded": true
  }
}
```

Store the secret separately with `setx OPENIDSYNC_CLIENT_SECRET "<secret>"` (or pick another variable name and update `ClientSecretEnvVar`).

---

## Logs and artifacts

- **Audit log** – `./log/openidsync.log` by default (path configurable). Machine-parsable RFC 5424 format plus human-readable console output.
- **Credentials export** – `./log/openidsync-credentials.csv` captures generated passwords immediately after user creation. Use option 10 when you’ve archived them securely.
- **Run summary** – Printed to console and log: user/group counts, skip reasons, group membership deltas, domain admin elevations, etc.
- **OpenGWTools export** – Option 13 writes `./log/OpenGWTools-Roadwarriors.csv`, expanding each user’s Office location into per-device rows.

---

## Optional helper tools

These scripts live alongside `OpenIDSync.ps1` and help with preparation or maintenance. They’re optional but handy when building a fresh lab.

- **`00_Before_PowerShell.cmd`** – Launches Windows PowerShell 5.1 with `Set-ExecutionPolicy Bypass` so you can start immediately on a locked-down workstation.
- **`01_OpenIDSync_Prepare_Domain_Promotion.ps1`** – Installs AD DS prerequisites, required DSC modules, and validates the `ADDomain` resource before promotion.
- **`02_OpenIDSync_Domain_Promotion.ps1`** – Applies the first-domain-controller DSC configuration defined in `DomainPromotionConfig`.
- **`97_Set_OPENIDSYNC_CLIENT_SECRET.ps1`** – Prompts for the Microsoft Graph app secret and persists it to the configured environment variable (default `OPENIDSYNC_CLIENT_SECRET`).
- **`98_Reset_Azure_Login_Session.ps1`** – Clears cached Graph and Azure sign-ins. Useful when switching between tenants or accounts.

If you just want to sync an existing Entra tenant to an existing AD forest, you can ignore these helpers and go straight to `OpenIDSync.ps1`.

---

## Cleanup & danger zone

Once options 1–3 are satisfied, the dashboard exposes a red **DANGER ZONE** block (options 80–82). Each action is noisy on purpose — double confirmations, WhatIf previews, timestamped CSV exports, and dedicated log files.

- **80 – Remove OpenIDSync-managed users**
  - Targets the OU from `UserSyncConfig.DefaultOU` (unless overridden).
  - Only touches users whose descriptions contain `[openidsync.org]`.
  - Writes backups to `./log/openidsync_danger_remove_users_<timestamp>.csv`.
- **81 – Remove OpenIDSync-managed groups**
  - Removes memberships first, exports group and membership CSVs, then deletes the group.
- **82 – Uninstall OpenIDSync components**
  - Cleans secrets, optionally removes the Graph app, and resets configs/logs.

Use the `DangerZoneSkip` block in `OpenIDSync_Config.json` to list UPNs or sAMAccountNames you never want removed by these tools.

---

## Requirements & best practices

- Windows Server capable of running Active Directory Domain Services.
- Elevated Windows PowerShell 5.1 session (not PowerShell 7).
- Internet access for the first run to install modules from PowerShell Gallery.
- Grant Microsoft Graph **Application** permissions `User.Read.All` and `Directory.Read.All` to the created app and approve admin consent.
- Store the client secret outside of source control (environment variable recommended).

Security posture highlights:

- Entra interactions are read-only; all changes happen inside Windows AD.
- Authentication context (delegated vs. app-only) is printed at the start of each run.
- Passwords for new users are captured immediately so they’re never lost, then you can purge them with menu option 10.

---

## Troubleshooting

- **Missing DSC resources** – Re-run `01_OpenIDSync_Prepare_Domain_Promotion.ps1` to reinstall modules.
- **Graph permission failures** – Use option 3 to re-test; if consent hasn’t been granted, the dashboard explains which scope is missing.
- **Function capacity exceeded (PowerShell 5.1)** – The script raises `$MaximumFunctionCount`, but if you still hit the limit, increase it manually: `$global:MaximumFunctionCount = 32768`.
- **Auth context confusion** – Run option 11 to review which identifiers are in use, or option 2 again to recreate the app registration.
- **Stale tokens** – Run `./98_Reset_Azure_Login_Session.ps1` before signing in with a different account.

Need a clean slate? Use the danger-zone options with `-WhatIf`, review the logs in `./log`, and only confirm once you’re comfortable with the deletion plan.

## Roadmap

We’re expanding OpenIDSync to cover more cloud directories and downstream targets. Use the matrix below to track progress.

- ✅ Supported today
- 🚧 Planned / in development
- ❌ Not yet scheduled or Invalid source/target combination

Short codes: [A] Azure (Microsoft Entra ID) • [G] Google Cloud Identity • [O] Oracle Cloud Infrastructure IAM • [W] Windows Active Directory • [K] Keycloak • [C] Microsoft 365 CSV export • [S] AWS IAM Identity Center

| Source ↓ \ Target → | Windows AD [W] | Keycloak [K] | AWS IAM Identity Center [S] | Azure Entra ID [A] | Google Cloud Identity [G] | Oracle Cloud IAM [O] |
| --- | --- | --- | --- | --- | --- | --- |
| Microsoft 365 CSV export [C] | ✅ | 🚧 | 🚧 | ❌ | 🚧 | 🚧 |
| Azure Entra ID [A] | ✅ | 🚧 | 🚧 | ❌ | 🚧 | 🚧 |
| AWS IAM Identity Center [S] | 🚧 | 🚧 | ❌ | 🚧 | 🚧 | 🚧 |
| Google Cloud Identity [G] | 🚧 | 🚧 | 🚧 | 🚧 | ❌ | 🚧 |
| Oracle Cloud Infrastructure IAM [O] | 🚧 | 🚧 | 🚧 | 🚧 | 🚧 | ❌ |
| Windows Active Directory (cross-forest) [W] | ❌ | 🚧 | 🚧 | 🚧 | 🚧 | 🚧 |
| Keycloak [K] | 🚧 | ❌ | 🚧 | 🚧 | 🚧 | 🚧 |
