$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $RepoRoot
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("hooshix-agent-install-" + [guid]::NewGuid().ToString('N'))
$Stage = Join-Path $Work 'package'
$Prefix = Join-Path $Work 'install\bin'
$State = Join-Path $Work 'install\state'
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

try {
    go build -o (Join-Path $Stage 'hooshix-agent.exe') ./cmd/agent
    Copy-Item packaging\agent\windows\Install-HooshiXAgent.ps1 $Stage
    Copy-Item packaging\agent\windows\Uninstall-HooshiXAgent.ps1 $Stage

    $UnsafeHome = Join-Path $Work 'unsafe-home'
    New-Item -ItemType Directory -Force -Path $UnsafeHome | Out-Null
    Set-Content -LiteralPath (Join-Path $UnsafeHome 'sentinel') -Value 'keep'
    $OldProfile = $env:USERPROFILE
    $env:USERPROFILE = $UnsafeHome
    try {
        $Rejected = $false
        try { & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix (Join-Path $Work 'unsafe-bin') -StateDir $UnsafeHome -NoPersistence | Out-Null } catch { $Rejected = $true }
        if (-not $Rejected) { throw 'Windows installer unexpectedly accepted the user profile as state directory' }
        $Rejected = $false
        try { & (Join-Path $Stage 'Uninstall-HooshiXAgent.ps1') -Prefix (Join-Path $Work 'unsafe-bin') -StateDir $UnsafeHome -NoPersistence -PurgeState | Out-Null } catch { $Rejected = $true }
        if (-not $Rejected) { throw 'Windows uninstaller unexpectedly accepted the user profile as purge target' }
        if (-not (Test-Path -LiteralPath (Join-Path $UnsafeHome 'sentinel'))) { throw 'unsafe purge guard failed to preserve sentinel' }
    }
    finally { $env:USERPROFILE = $OldProfile }

    & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence
    $Installed = Join-Path $Prefix 'hooshix-agent.exe'
    & $Installed init --state-dir $State --json | Out-Null
    & $Installed status --state-dir $State --json | Out-Null
    $MarkerPath = Join-Path $State '.hooshix-agent-state'
    if ((Get-Content -Raw -LiteralPath $MarkerPath).Trim() -ne 'hooshix-agent-state-v1') {
        throw 'Agent state marker was not created'
    }

    $DriveRoot = [System.IO.Path]::GetPathRoot($State)
    $Rejected = $false
    try { & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $DriveRoot -NoPersistence } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Windows installer accepted drive root as Agent state' }
    $Rejected = $false
    try { & (Join-Path $Stage 'Uninstall-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $DriveRoot -NoPersistence -PurgeState } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Windows uninstaller accepted drive-root purge' }

    $Unowned = Join-Path $Work 'unowned\state'
    New-Item -ItemType Directory -Force -Path $Unowned | Out-Null
    Set-Content -NoNewline -LiteralPath (Join-Path $Unowned 'sentinel') -Value 'keep'
    $Rejected = $false
    try { & (Join-Path $Stage 'Uninstall-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $Unowned -NoPersistence -PurgeState } catch { $Rejected = $true }
    if (-not $Rejected -or (Get-Content -Raw -LiteralPath (Join-Path $Unowned 'sentinel')) -ne 'keep') {
        throw 'Windows uninstaller did not protect unowned state directory'
    }

    $Victim = Join-Path $Work 'victim\state'
    New-Item -ItemType Directory -Force -Path $Victim | Out-Null
    Set-Content -NoNewline -LiteralPath (Join-Path $Victim '.hooshix-agent-state') -Value 'hooshix-agent-state-v1'
    Set-Content -NoNewline -LiteralPath (Join-Path $Victim 'sentinel') -Value 'keep'
    $Junction = Join-Path $Work 'state-junction'
    New-Item -ItemType Junction -Path $Junction -Target $Victim | Out-Null
    $Rejected = $false
    try { & (Join-Path $Stage 'Uninstall-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $Junction -NoPersistence -PurgeState } catch { $Rejected = $true }
    if (-not $Rejected -or (Get-Content -Raw -LiteralPath (Join-Path $Victim 'sentinel')) -ne 'keep') {
        throw 'Windows uninstaller did not protect reparse-point state directory'
    }
    $Spec = & $Installed service-spec --state-dir $State --binary $Installed
    if ($Spec -notmatch 'schtasks.exe' -or $Spec -notmatch 'ONLOGON') {
        throw "Windows persistence spec does not preserve the current-user Scheduled Task model: $Spec"
    }

    $OldSource = Join-Path $Work 'old.go'
    @'
package main
import "fmt"
func main() { fmt.Println("old-marker") }
'@ | Set-Content -Encoding utf8 $OldSource
    go build -o $Installed $OldSource

    & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence
    if (-not (Test-Path "$Installed.previous")) {
        throw 'previous Agent binary was not preserved'
    }
    & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence -Rollback
    $Marker = (& $Installed).Trim()
    if ($Marker -ne 'old-marker') {
        throw "rollback did not restore the previous binary: $Marker"
    }

    & (Join-Path $Stage 'Uninstall-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence -PurgeState
    if (Test-Path $Installed) { throw 'Agent binary remains after uninstall' }
    if (Test-Path $State) { throw 'Agent state remains after explicit purge' }

    Write-Output 'Agent clean install/rollback/uninstall smoke: PASSED (windows)'
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Work
}
