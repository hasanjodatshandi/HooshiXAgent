[CmdletBinding()]
param(
    [string]$Prefix = "$env:LOCALAPPDATA\HooshiXAgent\bin",
    [string]$StateDir = "$env:LOCALAPPDATA\HooshiXAgent",
    [switch]$NoPersistence,
    [switch]$PurgeState
)

$ErrorActionPreference = 'Stop'
$TaskName = 'HooshiXAgent'
$Target = Join-Path $Prefix 'hooshix-agent.exe'
$Previous = "$Target.previous"

if (-not $NoPersistence) {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}

Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $Target
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $Previous
if ($PurgeState -and (Test-Path -LiteralPath $StateDir)) {
    Remove-Item -Recurse -Force -LiteralPath $StateDir
}

Write-Output 'HooshiX Agent uninstalled'
if (-not $PurgeState) {
    Write-Output "State preserved at $StateDir"
}
