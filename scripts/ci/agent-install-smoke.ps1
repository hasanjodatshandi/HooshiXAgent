$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $RepoRoot
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("hooshix-agent-install-" + [guid]::NewGuid().ToString('N'))
$Stage = Join-Path $Work 'package'
$Prefix = Join-Path $Work 'install\bin'
$State = Join-Path $Work 'install\state'
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

try {
    if ($env:HOOSHIX_AGENT_TEST_BINARY) {
        Copy-Item -LiteralPath $env:HOOSHIX_AGENT_TEST_BINARY -Destination (Join-Path $Stage 'hooshix-agent.exe')
    }
    else {
        go build -o (Join-Path $Stage 'hooshix-agent.exe') ./cmd/agent
    }
    Copy-Item packaging\agent\windows\Install-HooshiXAgent.ps1 $Stage
    Copy-Item packaging\agent\windows\Uninstall-HooshiXAgent.ps1 $Stage
    # Release packages always ship SHA256SUMS next to the binary and the
    # installer verifies against it, so the smoke package stages the same shape.
    $StageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Stage 'hooshix-agent.exe')).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $Stage 'SHA256SUMS') -Value "$StageHash  hooshix-agent.exe" -Encoding ascii

    # A tampered or unmanifested package must be refused before any replacement.
    $Tampered = Join-Path $Work 'tampered-package'
    New-Item -ItemType Directory -Force -Path $Tampered | Out-Null
    Copy-Item packaging\agent\windows\Install-HooshiXAgent.ps1 $Tampered
    Set-Content -LiteralPath (Join-Path $Tampered 'hooshix-agent.exe') -Value 'tampered-agent' -Encoding ascii
    $Zeros = '0' * 64
    Set-Content -LiteralPath (Join-Path $Tampered 'SHA256SUMS') -Value "$Zeros  hooshix-agent.exe" -Encoding ascii
    $Rejected = $false
    try { & (Join-Path $Tampered 'Install-HooshiXAgent.ps1') -Prefix (Join-Path $Work 'tampered-bin') -StateDir (Join-Path $Work 'tampered-state') -NoPersistence | Out-Null } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Windows installer accepted a binary that does not match the package SHA256SUMS' }
    Set-Content -LiteralPath (Join-Path $Tampered 'SHA256SUMS') -Value "$Zeros  other-binary.exe" -Encoding ascii
    $Rejected = $false
    try { & (Join-Path $Tampered 'Install-HooshiXAgent.ps1') -Prefix (Join-Path $Work 'tampered-bin') -StateDir (Join-Path $Work 'tampered-state') -NoPersistence | Out-Null } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Windows installer accepted a SHA256SUMS manifest with no entry for the Agent binary' }
    Remove-Item -Force -LiteralPath (Join-Path $Tampered 'SHA256SUMS')
    $Rejected = $false
    try { & (Join-Path $Tampered 'Install-HooshiXAgent.ps1') -Prefix (Join-Path $Work 'tampered-bin') -StateDir (Join-Path $Work 'tampered-state') -NoPersistence | Out-Null } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Windows installer accepted a package with no SHA256SUMS manifest' }
    if (Test-Path -LiteralPath (Join-Path $Work 'tampered-bin\hooshix-agent.exe')) { throw 'a rejected package still installed the Agent binary' }

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

    $ParentVictim = Join-Path $Work 'parent-victim'
    New-Item -ItemType Directory -Force -Path $ParentVictim | Out-Null
    $ParentJunction = Join-Path $Work 'parent-junction'
    New-Item -ItemType Junction -Path $ParentJunction -Target $ParentVictim | Out-Null
    $Rejected = $false
    try { & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir (Join-Path $ParentJunction 'nested\state') -NoPersistence | Out-Null } catch { $Rejected = $true }
    if (-not $Rejected -or (Test-Path -LiteralPath (Join-Path $ParentVictim 'nested'))) {
        throw 'Windows installer traversed a reparse-point parent'
    }

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
    # The installed Agent's own persistence definition must describe the
    # accepted Windows model (ADR-0014): the LocalSystem SCM service registered
    # by `hooshix-agent service install`. This leg runs with -NoPersistence so it
    # never mutates the runner; the real service install/run/uninstall gate is
    # scripts/ci/windows-service-install-smoke.ps1.
    $Spec = (& $Installed service-spec --state-dir $State --binary $Installed) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) { throw "service-spec failed with exit code $LASTEXITCODE" }
    if ($Spec -notmatch 'sc\.exe create HooshiXAgent' -or $Spec -notmatch 'start= auto') {
        throw "Windows persistence spec does not describe the accepted HooshiXAgent service model: $Spec"
    }
    if ($Spec -match 'schtasks' -or $Spec -match 'ONLOGON') {
        throw "Windows persistence spec still describes the superseded logon Scheduled Task model: $Spec"
    }

    if ($env:HOOSHIX_AGENT_OLD_TEST_BINARY) {
        Copy-Item -Force -LiteralPath $env:HOOSHIX_AGENT_OLD_TEST_BINARY -Destination $Installed
    }
    else {
        $OldSource = Join-Path $Work 'old.go'
        @('package main', 'import "fmt"', 'func main() { fmt.Println("old-marker") }') | Set-Content -Encoding utf8 $OldSource
        go build -o $Installed $OldSource
    }

    & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence
    if (-not (Test-Path "$Installed.previous")) {
        throw 'previous Agent binary was not preserved'
    }

    $BeforeFailedRollbackHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installed).Hash
    $PreviousBeforeFaultHash = (Get-FileHash -Algorithm SHA256 -LiteralPath "$Installed.previous").Hash
    $env:HOOSHIX_INSTALLER_FAULT = 'before-rollback-replace'
    $Rejected = $false
    try { & (Join-Path $Stage 'Install-HooshiXAgent.ps1') -Prefix $Prefix -StateDir $State -NoPersistence -Rollback | Out-Null } catch { $Rejected = $true }
    finally { Remove-Item Env:HOOSHIX_INSTALLER_FAULT -ErrorAction SilentlyContinue }
    if (-not $Rejected) { throw 'fault-injected Windows rollback unexpectedly succeeded' }
    if (-not (Test-Path -LiteralPath $Installed) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $Installed).Hash -ne $BeforeFailedRollbackHash) {
        throw 'failed rollback removed or changed the current Agent binary'
    }
    if (-not (Test-Path -LiteralPath "$Installed.previous") -or (Get-FileHash -Algorithm SHA256 -LiteralPath "$Installed.previous").Hash -ne $PreviousBeforeFaultHash) {
        throw 'failed rollback consumed or changed the previous Agent binary'
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
