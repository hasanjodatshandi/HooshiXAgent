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

function Assert-SafePurgeDirectory([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Agent purge state directory must not be empty.' }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $full = $fullPath.TrimEnd('\', '/')
    $rootRaw = [System.IO.Path]::GetPathRoot($fullPath)
    $root = $rootRaw.TrimEnd('\', '/')
    $profile = if ($env:USERPROFILE) { [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\', '/') } else { '' }
    if ($full -eq $root -or ($profile -and $full -ieq $profile)) {
        throw "Refusing unsafe Agent state purge path: $Path"
    }
    $relative = $full.Substring($rootRaw.Length).Trim('\', '/')
    $segments = @($relative -split '[\\/]' | Where-Object { $_ })
    if ($segments.Count -lt 2) {
        throw "Refusing shallow Agent state purge path: $Path"
    }
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -Force -LiteralPath $Path
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer) {
            throw "Refusing non-directory/reparse-point Agent purge path: $Path"
        }
        $children = @(Get-ChildItem -Force -LiteralPath $Path)
        if ($children.Count -gt 0) {
            $marker = Join-Path $Path '.hooshix-agent-state'
            if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
                throw "Refusing to purge unowned non-empty Agent state directory without marker: $Path"
            }
            $markerItem = Get-Item -Force -LiteralPath $marker
            if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing reparse-point Agent state marker: $marker"
            }
            $markerText = (Get-Content -Raw -LiteralPath $marker).Trim()
            if ($markerText -ne 'hooshix-agent-state-v1') {
                throw "Refusing to purge Agent state directory with invalid marker: $Path"
            }
        }
    }
}

if ($PurgeState) { Assert-SafePurgeDirectory $StateDir }

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
