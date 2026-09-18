[CmdletBinding()]
param(
    # Machine-wide paths that match the supported desktop installer
    # (cmd/hooshix-setup, installDir/stateDirName) exactly: both Windows
    # distribution channels must install one Agent, in one place, under one
    # persistence model (ADR-0014).
    [string]$Prefix = 'C:\Program Files\HooshiXAgent',
    [string]$StateDir = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HooshiXAgent'),
    [string]$Checksums = $env:HOOSHIX_AGENT_CHECKSUMS,
    [switch]$NoPersistence,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$Source = Join-Path $PSScriptRoot 'hooshix-agent.exe'
$Target = Join-Path $Prefix 'hooshix-agent.exe'
$Previous = "$Target.previous"
# The SCM service name the Agent binary registers and that the supported
# installer installs (internal/agent/svc.ServiceName).
$ServiceName = 'HooshiXAgent'

function Get-SafeFullPath([string]$Label, [string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label directory must not be empty." }
    $raw = [System.IO.Path]::GetFullPath($Path)
    $full = $raw.TrimEnd('\', '/')
    $rootRaw = [System.IO.Path]::GetPathRoot($raw)
    $root = $rootRaw.TrimEnd('\', '/')
    $profile = if ($env:USERPROFILE) { [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\', '/') } else { '' }
    if ($full -eq $root -or ($profile -and $full -ieq $profile)) {
        throw "Refusing unsafe $Label directory: $Path"
    }
    $relative = $full.Substring($rootRaw.Length).Trim('\', '/')
    $segments = @($relative -split '[\\/]' | Where-Object { $_ })
    if ($segments.Count -lt 2) {
        throw "Refusing shallow $Label directory: $Path"
    }
    return @{ Full = $full; Root = $rootRaw; Segments = $segments }
}

function Ensure-SafeDirectory([string]$Label, [string]$Path) {
    $safe = Get-SafeFullPath $Label $Path
    $current = $safe.Root
    foreach ($segment in $safe.Segments) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -Force -LiteralPath $current
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer) {
                throw "$Label path component must be a real directory: $current"
            }
        }
        else {
            New-Item -ItemType Directory -Path $current | Out-Null
            $item = Get-Item -Force -LiteralPath $current
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer) {
                throw "$Label created unsafe directory component: $current"
            }
        }
    }
}

function Assert-RegularFile([string]$Label, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label file is unavailable: $Path" }
    $item = Get-Item -Force -LiteralPath $Path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) {
        throw "$Label must be a regular non-reparse file: $Path"
    }
}

function Resolve-ChecksumManifest([string]$Explicit) {
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) {
            throw "Agent checksum manifest not found: $Explicit"
        }
        return $Explicit
    }
    foreach ($candidate in @((Join-Path $PSScriptRoot 'SHA256SUMS'), (Join-Path (Split-Path -Parent $PSScriptRoot) 'SHA256SUMS'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw "no SHA256SUMS next to ${Source}: pass -Checksums <path> or set HOOSHIX_AGENT_CHECKSUMS; refusing to install an unverified Agent binary"
}

# Release packages carry a SHA256SUMS manifest next to the binary. Promoting an
# unverified binary to the persistence path would let a corrupted or
# substituted build run as the Agent, so a missing manifest, a missing entry
# and a digest mismatch are all fatal (fail closed).
function Assert-VerifiedBinary([string]$ManifestPath, [string]$BinaryPath) {
    $name = [System.IO.Path]::GetFileName($BinaryPath)
    $expected = $null
    foreach ($line in (Get-Content -LiteralPath $ManifestPath)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $entry = $parts[1].Trim().TrimStart('*')
        if ($entry -ieq $name -or $entry -ieq "./$name") {
            $expected = $parts[0].Trim().ToLowerInvariant()
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($expected)) {
        throw "checksum manifest $ManifestPath has no entry for $name; refusing to install an unverified Agent binary"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $BinaryPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Agent binary SHA-256 mismatch for ${name}: manifest=$expected actual=$actual; refusing to install"
    }
    Write-Output "verified $name SHA-256 against $ManifestPath"
}

function Invoke-InstallerFault([string]$Point) {
    if ($env:HOOSHIX_INSTALLER_FAULT -eq $Point) {
        throw "Synthetic installer fault at $Point"
    }
}

function Replace-TargetTransactionally([string]$Candidate, [string]$Destination, [string]$BackupPath) {
    if (Test-Path -LiteralPath $Destination) {
        Assert-RegularFile 'Existing Agent binary' $Destination
        if ([string]::IsNullOrWhiteSpace($BackupPath)) { throw 'Transactional replacement requires a backup path when the destination exists.' }
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $BackupPath
        [System.IO.File]::Replace($Candidate, $Destination, $BackupPath, $true)
    }
    else {
        [System.IO.File]::Move($Candidate, $Destination)
    }
}

function Commit-PreviousBinary([string]$Candidate, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Candidate)) { return }
    if (Test-Path -LiteralPath $Destination) {
        Assert-RegularFile 'Existing previous Agent binary' $Destination
        $swapBackup = "$Destination.swap-backup-$([guid]::NewGuid().ToString('N'))"
        try {
            [System.IO.File]::Replace($Candidate, $Destination, $swapBackup, $true)
        }
        finally {
            Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $swapBackup
        }
    }
    else {
        Move-Item -LiteralPath $Candidate -Destination $Destination
    }
}

if (-not $NoPersistence) {
    $serviceState = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HooshiXAgent'
    if ([IO.Path]::GetFullPath($StateDir).TrimEnd('\') -ine [IO.Path]::GetFullPath($serviceState).TrimEnd('\')) {
        throw 'The Windows service uses the machine-wide state directory. Use -NoPersistence for a custom state directory.'
    }
    $servicePrefix = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'HooshiXAgent'
    if ([IO.Path]::GetFullPath($Prefix).TrimEnd('\') -ine [IO.Path]::GetFullPath($servicePrefix).TrimEnd('\')) {
        throw 'The LocalSystem service binary must be installed under Program Files. Use -NoPersistence for a custom prefix.'
    }
}
Ensure-SafeDirectory 'Agent install prefix' $Prefix
Ensure-SafeDirectory 'Agent state' $StateDir

# Windows Agent persistence is exactly one thing (ADR-0014): the LocalSystem
# `HooshiXAgent` service, registered by the Agent binary itself
# (`hooshix-agent service install` -> internal/agent/svc.Install). This archive
# installer must never register a per-user logon Scheduled Task again: two
# mechanisms would race for the state tree and the fixed loopback pairing port
# and present an ambiguous identity to the Gateway.
function Stop-HooshiXPersistence {
    if ($NoPersistence) { return }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Installing the $ServiceName Windows service requires an elevated (Run as administrator) session. Pass -NoPersistence to install the files only."
    }
    # The previously registered service holds the old image open; stop it so the
    # transactional replacement below can rename the file. A missing service, a
    # stopped service and an already-removed service are all valid states.
    if (Test-Path -LiteralPath $Target) {
        try { & $Target service stop 2>$null | Out-Null } catch { }
    }
    $waited = 0
    while ($waited -lt 30) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 500
        $waited++
    }
    if ($waited -ge 30) {
        Write-Warning "The $ServiceName service did not stop within the bounded wait; the replacement below may fail on a locked image."
    }
    # Migration cleanup: an earlier release of this archive registered a per-user
    # logon Scheduled Task named HooshiXAgent. Remove it so a device cannot run
    # both persistence models against one device identity.
    try { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}

function Start-HooshiXPersistence {
    if ($NoPersistence) { return }
    Initialize-HooshiXStateAccess
    & $Target service install
    if ($LASTEXITCODE -ne 0) { throw "Agent service install failed with exit code $LASTEXITCODE" }
    & $Target service start
    if ($LASTEXITCODE -ne 0) { throw "Agent service start failed with exit code $LASTEXITCODE" }
}

function Initialize-HooshiXStateAccess {
    # No credential is created until the new directory DACL is in place.
    # The service creates its own DPAPI identity on first start; never create
    # that identity here under the elevated installer's different account.
    $stateItem = Get-Item -Force -LiteralPath $StateDir
    if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Agent state must not be a reparse point.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User.Value
    $directorySecurity = New-Object Security.AccessControl.DirectorySecurity
    $directorySecurity.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;$sid)")
    Set-Acl -LiteralPath $StateDir -AclObject $directorySecurity
    $capabilityPath = Join-Path $StateDir 'pairing.capability'
    if (Test-Path -LiteralPath $capabilityPath) {
        Assert-RegularFile 'Pairing capability' $capabilityPath
        $fileSecurity = New-Object Security.AccessControl.FileSecurity
        $fileSecurity.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;$sid)")
        Set-Acl -LiteralPath $capabilityPath -AclObject $fileSecurity
    }
}

if ($Rollback) {
    Assert-RegularFile 'Previous Agent binary' $Previous
    $RollbackCandidate = "$Target.rollback-new-$([guid]::NewGuid().ToString('N'))"
    $RollbackBackup = "$Target.rollback-backup-$([guid]::NewGuid().ToString('N'))"
    try {
        Copy-Item -LiteralPath $Previous -Destination $RollbackCandidate
        Assert-RegularFile 'Rollback candidate' $RollbackCandidate
        Invoke-InstallerFault 'before-rollback-replace'
        Stop-HooshiXPersistence
        Replace-TargetTransactionally $RollbackCandidate $Target $RollbackBackup
        Invoke-InstallerFault 'after-rollback-replace'
        Start-HooshiXPersistence
        Remove-Item -Force -LiteralPath $Previous
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $RollbackBackup
    }
    finally {
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $RollbackCandidate
    }
    Write-Output "HooshiX Agent rollback restored $Target"
    exit 0
}

Assert-RegularFile 'Agent package binary' $Source
Assert-VerifiedBinary (Resolve-ChecksumManifest $Checksums) $Source
$InstallCandidate = "$Target.install-new-$([guid]::NewGuid().ToString('N'))"
$PreviousCandidate = "$Target.previous-new-$([guid]::NewGuid().ToString('N'))"
try {
    if (Test-Path -LiteralPath $Target) {
        Assert-RegularFile 'Existing Agent binary' $Target
    }
    Copy-Item -LiteralPath $Source -Destination $InstallCandidate
    Assert-RegularFile 'Install candidate' $InstallCandidate
    Invoke-InstallerFault 'before-install-replace'
    Stop-HooshiXPersistence
    $InstallBackup = if (Test-Path -LiteralPath $Target) { $PreviousCandidate } else { $null }
    Replace-TargetTransactionally $InstallCandidate $Target $InstallBackup
    Commit-PreviousBinary $PreviousCandidate $Previous
    Start-HooshiXPersistence
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $InstallCandidate
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $PreviousCandidate
}

Write-Output "HooshiX Agent installed at $Target"
Write-Output "Agent state directory: $StateDir"
