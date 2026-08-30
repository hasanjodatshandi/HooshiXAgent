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

function Assert-SafeDirectory([string]$Label, [string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label directory must not be empty." }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $rootRaw = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
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
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -Force -LiteralPath $Path
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer) {
            throw "$Label directory must be a real directory: $Path"
        }
    }
}

Assert-SafeDirectory 'Agent install prefix' $Prefix
Assert-SafeDirectory 'Agent state' $StateDir

New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Restart-HooshiXPersistence {
    if ($NoPersistence) { return }
    $Action = New-ScheduledTaskAction -Execute $Target -Argument ('run --state-dir "{0}"' -f $StateDir)
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $Principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

if ($Rollback) {
    if (-not (Test-Path -LiteralPath $Previous)) {
        throw 'No previous Agent binary is available for rollback.'
    }
    if (Test-Path -LiteralPath $Target) {
        Remove-Item -Force -LiteralPath $Target
    }
    Move-Item -Force -LiteralPath $Previous -Destination $Target
    Restart-HooshiXPersistence
    Write-Output "HooshiX Agent rollback restored $Target"
    exit 0
}

if (-not (Test-Path -LiteralPath $Source)) {
    throw "Agent binary not found: $Source"
}

if (Test-Path -LiteralPath $Target) {
    Copy-Item -Force -LiteralPath $Target -Destination $Previous
}
Copy-Item -Force -LiteralPath $Source -Destination $Target
Restart-HooshiXPersistence

Write-Output "HooshiX Agent installed at $Target"
Write-Output "Agent state directory: $StateDir"
