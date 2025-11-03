# Copilot / AI Assistant Instructions for `openidsync`

This document gives AI coding assistants (and human contributors) the *project-aware* context, constraints, and style expectations required to generate safe, compatible, and maintainable changes.

---
## 1. Project Purpose (High-Level)
`openidsync` provisions a new on‑prem Active Directory forest and synchronizes identities (users, groups, memberships) from Microsoft 365 / Entra ID (or CSV) into Windows AD. It is moving toward a pluggable "any source → any target" architecture with canonical object shapes and exception policies (e.g., privileged role elevation).

---
## 2. Runtime & Compatibility Constraints
- Baseline: **Windows PowerShell 5.1** (not PowerShell 7+). Generated code MUST remain compatible.
- Avoid features exclusive to newer PowerShell versions (e.g. class-based enums, `ForEach-Object -Parallel`).
- Keep function count growth in mind (PowerShell 5.1 function cap) – do **not** import the `Microsoft.Graph` meta-module; only import required submodules.
- Do **not** add `Export-ModuleMember` in plain `.ps1` files (they are dot-sourced, not modules).

---
## 3. Directory & Module Layout (Domain Driven)
```
modules/
  logging/Write-Log.ps1                 (central logging)
  common/Config.ps1                     (config load/save)
  common/Contracts.ps1                  (canonical object constructors – WIP)
  common/Orchestrator.ps1               (future any-source→any-target orchestrator – WIP)
  common/Summary.ps1                    (summary helper – minimal)
  ad/ActiveDirectory.ps1                (AD helpers + privileged elevation logic)
  microsoft-graph/Graph.ps1             (Graph connectivity + user/group/role queries)
  transform/Users.ps1                   (user transform helpers)
  sync-sources/CSV.ps1                  (CSV source)
  sync-sources/Providers.ps1            (placeholders for future providers)
  sync-targets/WindowsAD.ps1            (user provisioning and updates in AD)
  sync-targets/WindowsAD.Groups.ps1     (group create & membership parity)
```
Top-level numbered scripts orchestrate phases (01 prepare, 02 promote, 03 sync, 04 danger remove, etc.).

---
## 4. Core Responsibilities
- `OpenIDSync.ps1`: Orchestrates run; reads config; interactive/background mode selection; calls Graph + AD modules.
- `Graph.ps1`: Keeps *only* what’s needed (users, groups, directory role membership, group member expansion). Reconnects with required scopes as needed.
- `ActiveDirectory.ps1`: AD lookup helpers, sAM generation, description tagging, and privileged elevation (`Invoke-OpenIdSyncExceptionElevation`).
- `WindowsAD.Groups.ps1`: Group name normalization + membership reconciliation idempotency.

---
## 5. Coding & Style Guidelines
| Topic | Guideline |
|-------|-----------|
| Functions | Use `function Verb-Noun { param(...) ... }`; prefer explicit `[string]`, `[int]`, `[switch]` types. |
| Error Handling | Wrap external / Graph / AD calls in `try { } catch { Write-Log -Level 'ERROR' -Message ... }`. Never swallow silently unless purposeful, then comment. |
| Logging | Always use `Write-Log` with one of: `INFO`,`WARN`,`ERROR`,`ACTION`,`RESULT`,`PROMPT`. No `Write-Host` except for deliberate interactive UI. |
| Parameters | Provide `[Parameter(Mandatory=...)]` where user clarity is improved; avoid mandatory if script sets defaults. |
| Null Safety | Coalesce arrays to `@()` before enumerating; treat potential null returns from Graph. |
| String Interpolation | When variable is followed by a colon or other char that could confuse the parser (`$var:`) enclose as `${var}`. |
| Reusability | Push complex logic into modules, keep orchestration script linear & readable. |
| Secrets | Never echo secrets to logs; only display new client secret once in console. |
| Length Limits | AD `sAMAccountName` must be ≤ 20 chars after normalization; truncate deterministically, log if truncated. |

---
## 6. Logging Strategy
`Write-Log` is central. Do not invent new logging primitives. Each meaningful action should have one of:
- ACTION: Starting a phase (e.g., group reconciliation)
- RESULT: Completed measurable outcome (counts, created objects)
- WARN / ERROR: Problems; include concise diagnostic context
- PROMPT: Records the user’s response to an interactive question

Avoid multi-line messages; keep log parsing easy.

---
## 7. Configuration Sources
- `OpenIDSync_Config.json`: Main (UserSyncConfig, LoggingConfig, DomainPromotionConfig, etc.).
- `OpenIDSync_OnlineSyncConfig.json`: Stores *only* tenant/app IDs & secret env var name. **Never** store client secrets in any file.
- Background run modes optionally set via `SyncModes` object: `{ "Users": "All|Prompt|Skip", "Groups": ..., "Memberships": ... }`.

If adding new config keys: update README with description + defaults; maintain backward compatibility (probe, fallback, convert).

---
## 8. Execution Modes (Interactive vs Background)
Three independent dimensions: Users, Groups, Memberships each: `All`, `Prompt`, `Skip`. Interactive menus include `[Q]uit` to abort early. Background loads the same from JSON.

When adding new sync dimensions (e.g., Devices, ServicePrincipals), follow pattern:
1. Add `$script:ModeX` default `All`.
2. Extend JSON parsing for `SyncModes.X`.
3. Add interactive prompt section (with All/Prompt/Skip/Quit) before execution.
4. Incorporate summary counters.

---
## 9. Group Sync Naming Rules
Ordered normalization pipeline (do not reorder without reason):
1. Remove diacritics (e.g., Hungarian accents) using `Remove-Diacritics`.
2. Replace spaces & dots with underscores.
3. Remove invalid chars (keep `[A-Za-z0-9_]`).
4. Collapse multiple underscores to single.
5. Apply prefix by group kind: `Sec_`, `Team_`, `Distribution_`.
6. Trim to 20 chars (AD limit).
7. Trim trailing underscore(s).
8. Resolve potential collision (future: implement suffix strategy `_1`, `_2`, etc.).

When modifying: ensure legacy groups previously created are still matched (idempotent); log any change in normalization algorithm.

---
## 10. Membership Parity Algorithm
`Set-AdGroupMemberships` receives:
- Target AD group (retrieved or created).
- Desired member UPN list (unique, sanitized).
Steps:
1. Resolve UPNs → AD users (`Get-ADUser -Filter`).
2. Build current vs desired DistinguishedName sets.
3. Add missing, remove extraneous (skip built‑ins if any future filtering added).
4. Return `{ Added, Removed }` counts.

Edge cases: empty or null list → ensure AD group becomes empty (unless future protect rules introduced).

---
## 11. Privileged Elevation Framework
Current implementation: Map Entra Global Administrators to AD `Domain Admins` group.
- Discovery: `Get-EntraGlobalAdministratorUpns` (handles group-assigned role expansion).
- Enforcement: `Invoke-OpenIdSyncExceptionElevation -Upn <upn> -ExceptionTags @('GLOBAL_ADMIN')`.
- Extendable: Provide more tags (e.g. `EXCHANGE_ADMIN`) and map to additional AD groups inside same function or a new dispatcher.

If adding new mappings: 
1. Introduce constant or lookup hashtable (`$roleMap`).
2. Ensure idempotent membership check before `Add-ADGroupMember`.
3. Add new summary counters (e.g., `ExchangeAdminElevations`).

---
## 12. Adding a New Source Provider (Blueprint)
Implement in `sync-sources/Providers.ps1`:
```powershell
function Get-UsersFrom<Keycloak|Aws|Gcp|Oci> {
    param([hashtable]$Config)
    # 1. Query external service API (read-only)
    # 2. Project into the established row shape with required fields:
    #    'User principal name','First name','Last name','Display name','Department','Title', ...
    # 3. Return array of PSCustomObjects.
    throw 'Not implemented'
}
```
Then update orchestrator (eventually canonical path) to select based on `Source` value. Keep external dependencies optional.

---
## 13. Adding a New Target Backend
Create `modules/sync-targets/<TargetName>.ps1` with functions parallel to `WindowsAD.ps1`:
- `Invoke-<TargetName>UserSync`
- Group Create / Membership functions (or reuse abstract adapter signatures).
Add `-Target <TargetName>` pathway in main script; branch logic but keep existing Windows AD path intact.

---
## 14. Canonical Object Model (Planned)
`Contracts.ps1` & `Orchestrator.ps1` will host canonical user/group objects:
```powershell
[pscustomobject]@{ Type='User'; UPN=''; Email=''; GivenName=''; Surname=''; Enabled=$true; Attributes=@{} }
```
Sources: convert raw schema → canonical.
Targets: accept canonical → apply diff.
When implementing, ensure *backward compatibility* by preserving existing row path until fully migrated.

---
## 15. Security & Secrets
- No secrets in repo: environment variables only (`OPENIDSYNC_CLIENT_SECRET` by default).
- Avoid writing secrets to logs or summary.
- Validate untrusted input (e.g., CSV fields) before using in filters – wrap string values in quotes; avoid direct injection into `-Filter` without sanitization.

---
## 16. Testing / Validation Strategy (Lightweight for PS 5.1)
Because there is no dedicated test harness yet:
- For new functions: include a minimal inline self-test block guarded by `if ($false) { ... }` or supply a `test/` script – do **not** run automatically.
- Validate: user creation (happy path), skip logic, group name normalization edge cases (accented chars, long names), membership parity with add/remove scenarios, elevation when Global Admin is both direct & group-assigned.
- Smoke test logs: ensure each new action emits one ACTION and at least one RESULT line.

---
## 17. Common Pitfalls & Guardrails
| Pitfall | Mitigation |
|---------|------------|
| Variable interpolation errors like `$var:` | Use `${var}` before colon. |
| Null membership arrays | Default param arrays to `@()` + null coalesce at caller. |
| Function count limit (4096) | Do NOT import large aggregated modules. Keep only needed Graph submodules. |
| sAMAccountName collisions | (Planned) implement suffix strategy; currently first existing wins silently. |
| Accidental destructive operations | No deletes in user sync path; removal script isolated in `04_*` with explicit prompts. |

---
## 18. Roadmap Tags & Conventions
Use inline comments `# TODO:` for near-term, `# FUTURE:` for longer-term. Do not remove TODOs without implementation or rationale. Large features should be summarized in README Roadmap section as well.

---
## 19. Example Pattern (User Update Snippet)
```powershell
try {
    $updateParams = @{ GivenName=$row.'First name'; Surname=$row.'Last name' }
    Set-ADUser -Identity $adUser.DistinguishedName @updateParams -ErrorAction Stop
    Write-Log -Level 'RESULT' -Message ("Updated user {0}" -f $adUser.SamAccountName)
} catch {
    Write-Log -Level 'ERROR' -Message ("Failed user update {0}: {1}" -f $adUser.SamAccountName, $_.Exception.Message)
}
```

---
## 20. When Unsure – Ask Minimally, Act Maximally
AI suggestions should:
1. Infer missing trivial details (state assumption in comments if impactful).
2. Avoid blocking on user feedback for obvious routine scaffolding.
3. Keep patches *surgical* – only touch necessary lines.
4. Provide delta value: new features, bug fixes, or refactors with measurable clarity/performance/logging improvements.

---
## 21. Do Not
- Do not embed binary data or screenshots in code.
- Do not reflow large existing scripts just for style; preserve blame history.
- Do not add external dependencies unless absolutely required (and document them clearly in README).
- Do not introduce write operations against Entra ID (project scope is read-only upstream).

---
## 22. Quick Checklist Before Submitting AI-Generated Patch
- [ ] PowerShell 5.1 compatible? (No 7+ syntax)
- [ ] Logging levels used consistently
- [ ] No secrets / credentials present
- [ ] Null-safe operations on collections
- [ ] Summary counters updated if new action type added
- [ ] README / COPILOT_INSTRUCTIONS updated if public behavior changed
- [ ] Added braces for interpolations before colon

---
*End of Copilot / AI assistant instructions.*
