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

    & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence
    $Installed = Join-Path $Prefix 'hooshix-agent.exe'
    & $Installed init --state-dir $State --json | Out-Null
    & $Installed status --state-dir $State --json | Out-Null
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
