# Edge Agent Packages

AG-7 distributes the Edge Agent as versioned platform archives.

The archive installer is user-scoped on Linux and macOS so the running Agent remains under the same OS user that owns the accepted local secret store.

| Platform | Persistence integration | Default binary location |
| --- | --- | --- |
| Linux | `systemd --user` service | `~/.local/bin/hooshix-agent` |
| macOS | LaunchAgent | `~/Library/Application Support/HooshiXAgent/bin/hooshix-agent` |
| Windows | `HooshiXAgent` service (LocalSystem) — see below | `C:\Program Files\HooshiXAgent\hooshix-agent.exe` |

## Windows: accepted model and what this archive installs

The Windows Agent persistence and secret trust model is the **service model**, recorded as Accepted in `docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md`: the Agent runs as the `HooshiXAgent` service under the LocalSystem default account, with state at `%ProgramData%\HooshiXAgent` and secrets protected by DPAPI in the service account's user scope (not machine scope), plus an installer-applied state-tree ACL and no password-bearing service account. ADR-0014 supersedes the Windows clauses of ADR-0010, which had chosen the user-scoped model.

The supported Windows distribution channel is `HooshiXAgent-Setup.exe` produced by `scripts/build-setup.ps1` from `cmd/hooshix-setup`, which installs that service model together with the tray binary, `uninstall.exe` and the Windows uninstall (ARP) entry.

**This archive installs the same model.** `Install-HooshiXAgent.ps1` now defaults to `C:\Program Files\HooshiXAgent` and `%ProgramData%\HooshiXAgent` and registers persistence through the Agent binary itself (`hooshix-agent.exe service install` / `service start`), which requires an elevated session; `-NoPersistence` installs the files only. This is ADR-0014 rollout step R1, executed 2026-09-17. The script also unregisters a legacy per-user logon Scheduled Task named `HooshiXAgent` as migration cleanup, because an earlier release of this archive registered one and a device must not run two persistence mechanisms against one device identity.

Two consequences for operators:

- uninstall stops and uninstalls the service through the binary and fails if the registration survives; it also removes any leftover legacy task;
- this archive still does not provide the tray binary, `uninstall.exe` or the ARP entry, so `HooshiXAgent-Setup.exe` remains the supported channel for a Windows desktop device. `docs/runtime/packaging-and-operations.md` is the current packaging/operations contract.

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

### Checksum verification

Every package ships a `SHA256SUMS` manifest next to the binary and both installers verify the binary against it before replacing anything. A missing manifest, a manifest without an entry for the binary, and a digest mismatch are all fatal: the installer exits non-zero and installs nothing.

- `./install.sh --checksums <path>` (or `HOOSHIX_AGENT_CHECKSUMS`) overrides the default lookup next to the script and in its parent directory.
- `.\Install-HooshiXAgent.ps1 -Checksums <path>` (or `HOOSHIX_AGENT_CHECKSUMS`) does the same on Windows.

Verify the downloaded package against the release manifest before installing, following `docs/runtime/packaging-and-operations.md`.

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

## RA-6 Windows transactional replacement

The Windows installer validates every existing install/state path component and rejects reparse points before creating or replacing files. Upgrade and rollback stage a same-directory candidate and use `File.Replace` with a real same-volume backup when a destination already exists. A rollback failure before replacement leaves both the current binary and `.previous` byte-for-byte unchanged; `.previous` is consumed only after the replacement and persistence restart succeed. `HOOSHIX_INSTALLER_FAULT` is a CI-only fault-injection hook used by the Windows smoke to prove this failure behavior and is not a runtime Agent setting.
