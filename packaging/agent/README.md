# Edge Agent Packages

AG-7 distributes the Edge Agent as versioned platform archives.

The installer is user-scoped by default so the running Agent remains under the same OS user that owns the accepted local secret store.

| Platform | Persistence integration | Default binary location |
| --- | --- | --- |
| Linux | `systemd --user` service | `~/.local/bin/hooshix-agent` |
| macOS | LaunchAgent | `~/Library/Application Support/HooshiXAgent/bin/hooshix-agent` |
| Windows | current-user logon Scheduled Task | `%LOCALAPPDATA%\HooshiXAgent\bin\hooshix-agent.exe` |

Windows deliberately does not install a LocalSystem service because Agent secret state is protected with DPAPI CurrentUser. Changing that trust boundary requires a later approved decision.

## Install

Linux/macOS archive:

```bash
./install.sh
```

Windows archive:

```powershell
.\Install-HooshiXAgent.ps1
```

Installers preserve an existing binary as `.previous` before replacing it.

## Rollback

Linux/macOS:

```bash
./install.sh --rollback
```

Windows:

```powershell
.\Install-HooshiXAgent.ps1 -Rollback
```

Only the previous binary is rolled back. Agent state/config/identity are preserved.

## Uninstall

The uninstallers preserve state by default. Use the explicit purge option only when device identity/configuration should be destroyed.

Deterministic CI clean-install tests use the no-service/no-persistence mode and temporary installation directories; platform CI separately verifies persistence-spec generation and package execution.

## R-9 destructive-path safety

Installers reject unsafe/shallow state-directory targets such as the filesystem/volume root, the current user home/profile, and existing symlink/reparse-point state directories. Agent initialization writes a versioned `.hooshix-agent-state` ownership marker. Explicit state purge is fail-closed unless the target is a safe real directory carrying that valid marker; Unix uninstall also rejects parent-traversal and symlink purge paths. CI runs negative package tests on Unix and Windows in addition to the normal clean install/rollback/uninstall smoke.

Release-package construction refuses destructive output targets such as the repository root, filesystem root, user home, shallow/parent-traversal paths, or a symlink output directory. A non-empty output directory is recursively replaced only when it carries the valid `.hooshix-release-output` ownership marker from an earlier release build; the marker is operational-only and excluded from release checksums/subjects.
