[CmdletBinding()]
param(
    [string]$Prefix = "$env:LOCALAPPDATA\HooshiXAgent\bin",
    [string]$StateDir = "$env:LOCALAPPDATA\HooshiXAgent",
    [switch]$NoPersistence,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$Source = Join-Path $PSScriptRoot 'hooshix-agent.exe'
$Target = Join-Path $Prefix 'hooshix-agent.exe'
$Previous = "$Target.previous"
$TaskName = 'HooshiXAgent'

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

Ensure-SafeDirectory 'Agent install prefix' $Prefix
Ensure-SafeDirectory 'Agent state' $StateDir

function Restart-HooshiXPersistence {
    if ($NoPersistence) { return }
    $Action = New-ScheduledTaskAction -Execute $Target -Argument ('run --state-dir "{0}"' -f $StateDir)
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $Principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

if ($Rollback) {
    Assert-RegularFile 'Previous Agent binary' $Previous
    $RollbackCandidate = "$Target.rollback-new-$([guid]::NewGuid().ToString('N'))"
    $RollbackBackup = "$Target.rollback-backup-$([guid]::NewGuid().ToString('N'))"
    try {
        Copy-Item -LiteralPath $Previous -Destination $RollbackCandidate
        Assert-RegularFile 'Rollback candidate' $RollbackCandidate
        Invoke-InstallerFault 'before-rollback-replace'
        Replace-TargetTransactionally $RollbackCandidate $Target $RollbackBackup
        Invoke-InstallerFault 'after-rollback-replace'
        Restart-HooshiXPersistence
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
$InstallCandidate = "$Target.install-new-$([guid]::NewGuid().ToString('N'))"
$PreviousCandidate = "$Target.previous-new-$([guid]::NewGuid().ToString('N'))"
try {
    if (Test-Path -LiteralPath $Target) {
        Assert-RegularFile 'Existing Agent binary' $Target
    }
    Copy-Item -LiteralPath $Source -Destination $InstallCandidate
    Assert-RegularFile 'Install candidate' $InstallCandidate
    Invoke-InstallerFault 'before-install-replace'
    $InstallBackup = if (Test-Path -LiteralPath $Target) { $PreviousCandidate } else { $null }
    Replace-TargetTransactionally $InstallCandidate $Target $InstallBackup
    Commit-PreviousBinary $PreviousCandidate $Previous
    Restart-HooshiXPersistence
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $InstallCandidate
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $PreviousCandidate
}

Write-Output "HooshiX Agent installed at $Target"
Write-Output "Agent state directory: $StateDir"
