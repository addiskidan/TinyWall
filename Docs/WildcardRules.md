# Executable Folder Wildcards

This development branch is based on `rel-3.5.1`
(`1df71b146d01d734d5b5a45a814b29e6a073f4d0`). It adds executable folder
wildcards and corrects application identity normalization for temporary child
process rules. It does not include local installer customizations or binaries.
The upstream installer sources are unchanged; this is not an official release.

## Selecting a Folder

In **Manage > Application exceptions > Add application**, choose
**File / wildcard... > Wildcard path... > Folder...**. The Windows common folder
picker supports an address bar. Select a folder, choose the policy and lifetime
in the exception dialog, save the exception, and click **Apply** in Manage.

New folder selections include subfolders by default. For example, selecting
`C:\Apps\Example` produces `C:\Apps\Example\**\*.exe`. This matches every `.exe`
in that folder and its subfolders, not just one named executable. Clear
**Include subfolders** for `C:\Apps\Example\*.exe`, which matches only the
selected folder. Cancelling the folder picker does not change the pattern.

The same patterns support allow and block policies. For outgoing-only access,
select **Allow outgoing UDP and TCP traffic**; unrestricted traffic also permits
inbound connections. Select the block policy to block matched applications.

## Pattern Syntax

| Pattern | Matches |
| --- | --- |
| `C:\Apps\Example\*.exe` | All executables directly in the folder |
| `C:\Apps\Example\**\*.exe` | All executables in the folder and subfolders |
| `C:\Apps\Example\**\helper.exe` | A specific executable name at any depth |
| `C:\Apps\Example\version-*\app?.exe` | Versioned folders and a single-character filename wildcard |

Matching is case-insensitive. `*` and `?` match within one path component; `**`
must occupy a complete directory component and matches zero or more directories.
The final component must end in `.exe`. Patterns must be absolute local paths
anchored below a fixed folder. Relative paths, network shares, drive-wide
patterns, traversal components, alternate data streams, and ambiguous path
components are rejected. Scans do not follow junctions or symbolic links.

## Rules and Limits

- Patterns are saved as executable subjects and expanded into exact executable
  identities before Windows Filtering Platform filters are installed. Existing
  policy, lifetime, creation time, and rule IDs are preserved.
- File watchers trigger reconciliation after membership changes. Periodic scans
  also detect missed changes and roots that did not exist when the rule was
  applied. Reconciliation is asynchronous, not a synchronous launch-time check.
- A known blocked identity is retained while its pattern rule is active in the
  service, even if its file is deleted. Removing the pattern removes those
  expanded rules. This history is not persisted across service restarts.
- **Apply same rule to child processes** is available for wildcard rules and is
  off by default. When enabled, children launched by matched executables can
  inherit the policy even outside the selected folder. The exception dialog
  asks for confirmation of this broader scope.
- Folder-wide allow rules trust any matching executable placed in that folder.
  Prefer folders whose contents are controlled by a trusted administrator.
  Scan failures do not create allow rules, but an unreadable folder may also
  prevent discovery of previously unknown executables for a block rule.
- Explicit blocks retain their higher priority over allows. **Disable firewall**
  intentionally bypasses application allow and block exceptions. Use a mode that
  processes application exceptions, such as Normal or Allow outgoing, to enforce
  application blocks. **Enable Blocklist** is a separate setting.

The child-process fix normalizes Windows paths to native NT paths in the shared
rule installer, for both full rebuilds and incremental temporary rules. This
keeps child identities consistent with the filter constructor's expectations.

## Focused Tests

On Windows, use PowerShell 7 and the Visual Studio MSBuild tools described in the
repository README. Build `TinyWall/TinyWall.csproj` in Release first, then run
each script in a separate PowerShell process:

```powershell
pwsh -NoProfile -File tests/Test-Wildcards.ps1
pwsh -NoProfile -File tests/Test-SourceRegression.ps1
pwsh -NoProfile -File tests/Test-WildcardCreation.ps1
```

For a different application build path:

```powershell
pwsh -NoProfile -File tests/Test-WildcardCreation.ps1 -ApplicationPath C:\Build\TinyWall.exe
```

The suites cover pattern parsing, folder membership, file watchers, allow/block
expansion, opt-in child inheritance, source pipeline regressions, valid-subject
creation before JSON cloning, serialization round trips, and native folder
dialog COM setup. They do not modify live firewall settings, run a service, or
show dialogs. The creation suite loads the real built application. Manual
testing is still needed for firewall integration and visible dialog behavior.
