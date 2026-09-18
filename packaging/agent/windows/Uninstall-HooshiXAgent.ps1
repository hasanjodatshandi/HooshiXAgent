[CmdletBinding()]
param(
    # Machine-wide paths matching the supported desktop installer
    # (cmd/hooshix-setup) and Install-HooshiXAgent.ps1.
    [string]$Prefix = 'C:\Program Files\HooshiXAgent',
    [string]$StateDir = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HooshiXAgent'),
    [switch]$NoPersistence,
    [switch]$PurgeState
)

$ErrorActionPreference = 'Stop'
# The SCM service name (internal/agent/svc.ServiceName). The superseded
# per-user logon Scheduled Task used the same name, which is why the migration
# cleanup below removes it too.
$ServiceName = 'HooshiXAgent'
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
    # One persistence model on Windows (ADR-0014): the LocalSystem service,
    # removed through the Agent binary itself. The service is removed FIRST, and
    # verified, because a registration that outlives its image is exactly the
    # state this uninstaller must not leave behind.
    if (Test-Path -LiteralPath $Target) {
        try { & $Target service stop 2>$null | Out-Null } catch { }
        try { & $Target service uninstall 2>$null | Out-Null } catch { }
    }
    $waited = 0
    while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and $waited -lt 30) {
        Start-Sleep -Milliseconds 500
        $waited++
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        throw "uninstall incomplete: the $ServiceName service is still registered"
    }
    # Migration cleanup for the superseded per-user logon Scheduled Task: if an
    # older archive install left one behind, it would relaunch the Agent at the
    # next logon against this removed installation.
    try { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}

# Remove with verification: report failures instead of claiming success
# while locked files remain installed.
foreach ($file in @($Target, $Previous)) {
    if (Test-Path -LiteralPath $file) {
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $file
        if (Test-Path -LiteralPath $file) {
            throw "uninstall incomplete: could not remove $file (still locked by a running process?)"
        }
    }
}
if ($PurgeState -and (Test-Path -LiteralPath $StateDir)) {
    Remove-Item -Recurse -Force -LiteralPath $StateDir
}

Write-Output 'HooshiX Agent uninstalled'
if (-not $PurgeState) {
    Write-Output "State preserved at $StateDir"
}
