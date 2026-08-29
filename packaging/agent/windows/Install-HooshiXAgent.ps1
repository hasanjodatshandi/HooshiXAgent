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
