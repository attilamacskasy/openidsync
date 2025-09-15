# openidsync

Automation to set up a new on‑premises Active Directory forest and synchronize Microsoft 365 users into it, driven by a single JSON file and a simple run order (01 → 02 → 03).

What you get:
- A DSC-based domain promotion to create the first domain controller of a new forest.
- A prep script that installs all prerequisites (features and modules) on a fresh Windows Server 2025.
- A user sync script that reads the new Microsoft 365 Admin “Active users” CSV format and creates/updates users in AD, interactive with preview.
- Full audit logs and a separate credentials log for newly created users.

## Files
- `00_OpenIDSync_Config.json` – Central configuration (edit this file first).
- `01_Prepare_Domain_Promotion.ps1` – Installs prerequisites (features/modules) for DSC.
- `02_Domain_Promotion.ps1` – Promotes the server to first DC using DSC and DomainPromotionConfig.
- `03_Sync_Users_from_M365_CSV_Export.ps1` – Interactive CSV-driven AD user sync.

## 0) Configure JSON
Edit `00_OpenIDSync_Config.json` and fill out these sections:
# openidsync

Automation to set up a new on‑premises Active Directory forest and synchronize Microsoft 365 users into it, driven by a single JSON file and a simple run order (01 → 02 → 03).

What you get:
- A DSC-based domain promotion to create the first domain controller of a new forest.
- A prep script that installs all prerequisites (features and modules) on a fresh Windows Server 2025.
- A user sync script that reads the new Microsoft 365 Admin “Active users” CSV format and creates/updates users in AD, interactive with preview.
- Full audit logs and a separate credentials log for newly created users.

## Files
- `00_OpenIDSync_Config.json` – Central configuration (edit this file first).
- `01_Prepare_Domain_Promotion.ps1` – Installs prerequisites (features/modules) for DSC.
- `02_Domain_Promotion.ps1` – Promotes the server to first DC using DSC and DomainPromotionConfig.
- `03_Sync_Users_from_M365_CSV_Export.ps1` – Interactive CSV-driven AD user sync.

## 0) Configure JSON
Edit `00_OpenIDSync_Config.json` and fill out these sections:

- `DomainPromotionConfig`:
   - `DomainName` (required), `NetBIOSName` (required)
   - `DNSDelegation` (bool), `InstallDNS` (bool), `DatabasePath`, `LogPath`, `SYSVOLPath`, `InstallServerRoles` (bool)
   - `AdministratorUsername` (kept for parity; not required by DSC)
- `PrepareConfig` (optional defaults for 01):
   - `InstallDNS` (bool), `MinActiveDirectoryDsc` (e.g. `6.2.0`), `MinPSDscResources` (e.g. `2.12.0.0`)
- `UserSyncConfig` (optional defaults for 03):
   - `CsvPath` (string), `DefaultOU` (DN string), `SuggestRemovals` (bool)

Example:
```json
{
   "DomainPromotionConfig": {
      "DomainName": "macskasy.com",
      "NetBIOSName": "MACSKASY",
      "DNSDelegation": false,
      "InstallDNS": true,
      "DatabasePath": "C:\\Windows\\NTDS",
      "LogPath": "C:\\Windows\\NTDS",
      "SYSVOLPath": "C:\\Windows\\SYSVOL",
      "InstallServerRoles": true,
      "AdministratorUsername": "administrator"
   },
   "PrepareConfig": {
      "InstallDNS": true,
      "MinActiveDirectoryDsc": "6.2.0",
      "MinPSDscResources": "2.12.0.0"
   },
   "UserSyncConfig": {
      "CsvPath": ".\\users_9_15_2025 9_17_18 PM.csv",
      "DefaultOU": "CN=Users,DC=modernworkplace,DC=hu",
      "SuggestRemovals": true
   }
}
```

## 1) Prepare the server
Run in an elevated PowerShell:

```powershell
cd "c:\Users\Attila\Desktop\Code\openidsync"
.\u003101_Prepare_Domain_Promotion.ps1             # reads PrepareConfig from 00_OpenIDSync_Config.json
# or override:
.1_Prepare_Domain_Promotion.ps1 -InstallDNS:$false -ConfigPath .\00_OpenIDSync_Config.json
```

What it does:
- Sets execution policy (process scope), ensures TLS 1.2, installs NuGet provider and trusts PSGallery.
- Installs modules: `PSDscResources`, `ActiveDirectoryDsc` (min versions from JSON if provided).
- Installs Windows Features: `AD-Domain-Services` and optionally `DNS` with management tools.

## 2) Promote to first domain controller (DSC)
```powershell
.2_Domain_Promotion.ps1                     # reads DomainPromotionConfig from 00_OpenIDSync_Config.json
# or
.2_Domain_Promotion.ps1 -ConfigPath .\00_OpenIDSync_Config.json
```

You will be prompted for the DSRM (Safe Mode Administrator) password. DSC will compile and apply the configuration and may reboot the server.

## 3) Sync Microsoft 365 users from CSV
```powershell
.3_Sync_Users_from_M365_CSV_Export.ps1      # uses UserSyncConfig defaults from JSON if present
# or override
.3_Sync_Users_from_M365_CSV_Export.ps1 -CsvPath ".\users_9_15_2025 9_17_18 PM.csv" -DefaultOU "CN=Users,DC=modernworkplace,DC=hu"
```

What the sync does:
- Interactive per-user preview “card”. Prompt: `Do you want to import user FIRST LAST (email) [Y]es/[N]o/[A]ll`.
- Re‑runnable: matches by email (AD `mail` or `proxyAddresses`). Updates attributes if user exists.
- Creates strong passwords for new users, logs to `openidsync_credentials_YYYYMMDD_HHMMSS.csv`.
- Stamps Description: `[Last update: YYYY-MM-DD HH:MM:SS] [Update count: N] [openidsync.org]`.
- Suggests removals for users in the target OU missing from CSV and not managed by this tool (can be disabled via JSON `SuggestRemovals=false` or `-NoSuggestRemovals`).
- Never manages or removes the built‑in `administrator` account.

## CSV format (Microsoft 365 Admin export)
Export path: Microsoft 365 Admin Center → Users → Active users → Export users.

Columns used include:
- Display name, User principal name, First name, Last name, Title, Department
- City, StateOrProvince, CountryOrRegion, Office, Street address, Postal code
- Phone number, Mobile Phone, Password never expires, Block credential
- Proxy addresses (multi-value joined by `+`, with primary in `SMTP:`)

Primary email is taken from the `SMTP:` entry in `Proxy addresses`; if missing, falls back to UPN.

## Logs and security
- Audit log: `openidsync_audit_YYYYMMDD_HHMMSS.log`
- Credentials log: `openidsync_credentials_YYYYMMDD_HHMMSS.csv` (handle securely)

## Requirements
- Run scripts in an elevated PowerShell session.
- Windows Server with ability to install AD DS and DNS roles.
- RSAT/AD PowerShell module (installed by script 01 or via DSC module install).
- Run PowerShell as a domain user with rights to create/update users in the target OU.
- Network connectivity to a writable domain controller.

## CSV source (Microsoft 365 Admin export)

Export path: Microsoft 365 Admin Center → Users → Active users → Export users.

The script expects columns like the Admin export, including:
- Display name, User principal name, First name, Last name, Title, Department
- City, StateOrProvince, CountryOrRegion, Office, Street address, Postal code
- Phone number, Mobile Phone, Password never expires, Block credential
- Proxy addresses (multi-value joined by “+”, with primary in “SMTP:”)

Example (header + one row):
```csv
Display name,DirSyncEnabled,User principal name,Object Id,First name,Last name,When created,Soft deletion time stamp,Title,Department,Preferred data location,City,CountryOrRegion,Office,StateOrProvince,Usage location,Last dirsync time,Block credential,Licenses,Password never expires,Last password change time stamp,Mobile Phone,Phone number,Postal code,Preferred language,Street address,Fax,Proxy addresses
Admin,False,admin@contoso.com,15e91f38-3651-425f-810a-56e0fb00287a,Admin,,2022-03-18 19:49:35Z,,Tenant Admin,,,,,,,US,,True,Unlicensed,False,2022-03-18 19:49:35Z,,,,,,,
```

Notes:
- Primary email used for matching is taken from Proxy addresses entry starting with “SMTP:”. If missing, the script falls back to the UPN.
- If multiple proxy addresses are present, they are applied to AD proxyAddresses.

## What the script does

For each CSV row:
1. Shows a preview “card” with all CSV fields for that user.
2. Prompts: Do you want to import user FIRSTNAME LASTNAME (e‑mail) [Y]es/[N]o/[A]ll
   - Y: process this user.
   - N: skip this user.
   - A: process this and all remaining users without further prompts.
3. Finds an AD user by email (mail or proxyAddresses). If found:
   - Updates UPN, name fields, department, title, office, address fields, phone/mobile, proxyAddresses, PasswordNeverExpires, enable/disable per “Block credential”.
   - Updates Description stamp and increments “[Update count: N]”.
4. If not found:
   - Creates a new AD user in the specified OU.
   - Generates a complex random password, sets it, and enables/disables per “Block credential”.
   - Writes credentials (email, UPN, sAMAccountName, password) to a credentials CSV.
5. Writes all actions and prompt responses to an audit log.

Additionally:
- Suggests removals for users in the target OU that have a mail attribute but are not in the CSV and are not tagged with “[openidsync.org]”. No deletion is performed. Use -NoSuggestRemovals to skip this step.
- The built‑in “administrator” account is never managed.

## Logs

Written to the working directory (current folder) with timestamps:
- Audit log: openidsync_audit_YYYYMMDD_HHMMSS.log
- Credentials log: openidsync_credentials_YYYYMMDD_HHMMSS.csv

Protect the credentials log as it contains generated passwords.

## Usage

Run in an elevated PowerShell session:

```powershell
cd "c:\Users\Attila\Desktop\Code\openidsync"

# Basic run (interactive)
.\newuser.ps1 -CsvPath ".\users_9_15_2025 9_17_18 PM.csv" -DefaultOU "CN=Users,DC=modernworkplace,DC=hu"

# Skip the post-run removal suggestions
.\newuser.ps1 -CsvPath ".\users_9_15_2025 9_17_18 PM.csv" -DefaultOU "CN=Users,DC=modernworkplace,DC=hu" -NoSuggestRemovals
```

Parameters:
- -CsvPath: Path to the Microsoft 365 “Active users” CSV export.
- -DefaultOU: Distinguished Name where new users are created and where removal suggestions are evaluated (e.g., OU=Users,DC=example,DC=com or CN=Users,DC=example,DC=com).
- -NoSuggestRemovals: Disable suggestions for un-managed users missing from CSV.

## Behavior details

- sAMAccountName: Derived from the UPN left part, truncated to 20 chars, and uniqued with a numeric suffix if needed.
- Passwords: 16 chars, include upper/lower/digit/special to meet Windows Server default complexity.
- Matching: Primary identifier is email (mail/proxyAddresses). If not found, a new user is created.
- Description tag: “[Last update: YYYY-MM-DD HH:MM:SS] [Update count: N] [openidsync.org]” is set or updated on every create/update.