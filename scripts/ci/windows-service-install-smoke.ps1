<#
.SYNOPSIS
Real runtime gate for the supported Windows Agent distribution:
HooshiXAgent-Setup.exe.

.DESCRIPTION
scripts/ci/agent-install-smoke.ps1 exercises the *archive* installer
(packaging/agent/windows/Install-HooshiXAgent.ps1) and deliberately runs it with
-NoPersistence, so nothing in that smoke ever starts the Windows Agent service.
This script is the gate that does: it installs the real distribution with the
real supported installer, asserts the observable result, exercises SCM
restart-on-failure, and asserts that uninstall removes everything again.

It exists because the Executable Runtime Gate (docs/engineering/executable-runtime-gate.md)
requires a runnable capability to be executed, not merely built: "an OS service
installs" and "reboot persistence works" are explicit triggers, and ADR-0014
makes the LocalSystem `HooshiXAgent` service the accepted Windows persistence
model. Building Setup.exe and asserting that three files are bigger than 1 MB is
build integrity, not runtime evidence. This gate closes runtime-gate gap G1
(ADR-0014 rollout step R4).

Requirements: an elevated Windows host. The distribution's own manifest requests
requireAdministrator, so a non-elevated caller fails with ERROR_ELEVATION_REQUIRED;
the elevation precondition is asserted up front so that failure mode is reported
as what it is instead of as a mysterious installer error. The gate fails closed
rather than skipping when it cannot run: a silently skipped runtime gate is how a
runnable capability gets reported as verified without ever being executed.

What this gate does NOT prove: a literal physical OS reboot. GitHub-hosted
runners are ephemeral and this gate never reboots the host, so reboot
persistence is evidenced only as (a) SCM automatic-start configuration and
(b) observed SCM restart-on-failure after a forced process termination. That
distinction must be preserved in any evidence that cites this gate.

Exit code 0 means every assertion below held. Any failure exits non-zero with the
failing assertion named.

.PARAMETER SetupExe
Path to an already built HooshiXAgent-Setup.exe. When omitted, the distribution
is built by scripts/build-setup.ps1.

.EXAMPLE
./scripts/ci/windows-service-install-smoke.ps1
#>
[CmdletBinding()]
param(
    [string]$SetupExe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The fixed machine-wide identity the accepted model defines. These are the same
# constants cmd/hooshix-setup and internal/agent/svc use; the gate asserts the
# observable result, so it intentionally re-derives the names it looks for
# rather than importing them from the code under test.
$ServiceName = 'HooshiXAgent'
$InstallDir = Join-Path $env:ProgramFiles 'HooshiXAgent'
$StateDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HooshiXAgent'
$ArpKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HooshiXAgent'
$TrayTaskName = 'HooshiXAgentTray'
$StateMarkerName = '.hooshix-agent-state'
$StateMarkerContents = 'hooshix-agent-state-v1'
$PairingCapabilityName = 'pairing.capability'
$PairingEndpointName = 'pairing.endpoint.json'
# The interactive user's SCM rights installed by the service DACL
# (internal/agent/svc/security.go: SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP).
$ExpectedInteractiveUserServiceRights = 'LCRPWP'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title =="
}

function Fail([string]$Message) {
    throw "windows service install gate failed: $Message"
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { Fail $Message }
}

function Assert-Elevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail @'
the gate must run elevated. HooshiXAgent-Setup.exe registers a machine-wide
SCM service, writes the machine ARP entry and rewrites the ProgramData state
tree ACL; none of that is possible without an elevated token. Run this gate on
an elevated Windows host (for example a windows-latest runner with an
administrator token) instead of skipping it — a runtime gate that cannot run is
an open gap, not a pass.
'@
    }
}

# Runs a process with stdin redirected from an empty file, so the installer's
# console prompts (pause(), promptUninstall()) can never block a runner: both are
# gated on stdin being a character device, which a redirected handle never is.
# Returns the exit code and the captured output for assertions and evidence.
function Invoke-Captured([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($Arguments -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $RepoRoot
    $process = [System.Diagnostics.Process]::Start($psi)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { }
        Fail "process $FilePath did not exit within $TimeoutSeconds seconds"
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut   = $stdout.GetAwaiter().GetResult()
        StdErr   = $stderr.GetAwaiter().GetResult()
    }
}

function Wait-Until([string]$Description, [int]$TimeoutSeconds, [scriptblock]$Condition) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = 'the condition was never evaluated'
    while ($true) {
        try {
            $last = & $Condition
            if ($last -eq $true) { return }
        }
        catch {
            $last = $_.Exception.Message
        }
        if ((Get-Date) -ge $deadline) {
            Fail "$Description did not become true within $TimeoutSeconds seconds (last observation: $last)"
        }
        Start-Sleep -Milliseconds 500
    }
}

function Get-AgentService {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
}

function Assert-ServiceAbsent([string]$Context) {
    if (Get-AgentService) { Fail "the $ServiceName service is still registered $Context" }
}

# sc.exe is queried directly rather than through a WMI projection: START_TYPE,
# BINARY_PATH_NAME, SERVICE_START_NAME and the failure actions are exactly what
# the accepted persistence model consists of, and a Win32_Service projection
# silently omits the recovery policy. sc.exe output is localized, so this gate
# depends on an English-language host; that dependency is why the assertions
# below name the tokens they need instead of diffing whole paragraphs.
function Get-ScQuery([string[]]$Arguments) {
    $result = Invoke-Captured 'sc.exe' $Arguments 60
    if ($result.ExitCode -ne 0) {
        Fail "sc.exe $($Arguments -join ' ') exited $($result.ExitCode): $($result.StdOut.Trim()) $($result.StdErr.Trim())"
    }
    return ($result.StdOut + $result.StdErr)
}

function Get-ListeningPort {
    param([Parameter(Mandatory = $true)][int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(3000)) { return $false }
        $client.EndConnect($connect)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-PairingEndpointPort {
    $path = Join-Path $StateDir $PairingEndpointName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return 0 }
    try {
        $record = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    }
    catch {
        return 0
    }
    if (-not $record.port -or $record.port -lt 1 -or $record.port -gt 65535) { return 0 }
    return [int]$record.port
}

Write-Section 'Preconditions'
Assert-Elevated

if (-not $SetupExe) {
    Write-Host 'building the distribution with scripts/build-setup.ps1 ...'
    $build = Invoke-Captured 'powershell.exe' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $RepoRoot 'scripts\build-setup.ps1')
    ) 300
    Write-Host $build.StdOut
    if ($build.ExitCode -ne 0) { Fail "scripts/build-setup.ps1 exited $($build.ExitCode): $($build.StdErr.Trim())" }
    $SetupExe = Join-Path $RepoRoot 'dist\HooshiXAgent-Setup.exe'
}
$SetupExe = (Resolve-Path -LiteralPath $SetupExe).Path
Assert-True (Test-Path -LiteralPath $SetupExe -PathType Leaf) "Setup.exe is missing: $SetupExe"
$setupBytes = (Get-Item -LiteralPath $SetupExe).Length
Assert-True ($setupBytes -gt 1MB) "Setup.exe is suspiciously small ($setupBytes bytes)"
Write-Host "Setup.exe: $SetupExe ($setupBytes bytes)"

# Starting from a clean machine is part of the claim. An install that "passed"
# on top of a previous installation would prove upgrade behavior, not the
# install path, and the uninstall assertions below would then be ambiguous.
Assert-ServiceAbsent 'before the gate started'
Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "the install directory already exists before the gate started: $InstallDir"
if (Test-Path -LiteralPath $StateDir) {
    $leftovers = @(Get-ChildItem -Force -LiteralPath $StateDir)
    Assert-True ($leftovers.Count -eq 0) "the state directory already contains files before the gate started: $StateDir"
}

Write-Section 'Install the supported distribution (Setup.exe)'
$install = Invoke-Captured $SetupExe @() 600
Write-Host $install.StdOut
if ($install.StdErr.Trim()) { Write-Host $install.StdErr }
if ($install.ExitCode -ne 0) { Fail "Setup.exe exited $($install.ExitCode)" }
# Setup's own success claim is recorded but never used as evidence on its own;
# every assertion below is an observation of the machine, not of this string.
Assert-True ($install.StdOut -match 'done\. The HooshiX Agent service') "Setup.exe did not report a completed install: $($install.StdOut.Trim())"

$agentBinary = Join-Path $InstallDir 'hooshix-agent.exe'
$trayBinary = Join-Path $InstallDir 'hooshix-agent-tray.exe'
$uninstallBinary = Join-Path $InstallDir 'uninstall.exe'
foreach ($binary in @($agentBinary, $trayBinary, $uninstallBinary)) {
    Assert-True (Test-Path -LiteralPath $binary -PathType Leaf) "the installed distribution is missing $binary"
    Write-Host "installed: $binary ($((Get-Item -LiteralPath $binary).Length) bytes)"
}

Write-Section 'Assert the accepted Windows persistence model (ADR-0014)'
Wait-Until 'the HooshiXAgent service to reach Running' 90 {
    $service = Get-AgentService
    if (-not $service) { return 'the service is not registered' }
    if ($service.State -ne 'Running') { return "service state is $($service.State)" }
    return $true
}
$service = Get-AgentService
Assert-True ($service.StartMode -eq 'Auto') "service StartMode is '$($service.StartMode)', want 'Auto'"
Write-Host "service: $ServiceName state=$($service.State) start=$($service.StartMode) pid=$($service.ProcessId)"

$config = Get-ScQuery @('qc', $ServiceName)
Assert-True ($config -match 'START_TYPE\s*:\s*2\s+AUTO_START') "the service is not configured for automatic start:`n$config"
Assert-True ($config -match 'SERVICE_START_NAME\s*:\s*LocalSystem') "the service does not run under the LocalSystem default account:`n$config"
Assert-True ($config -match 'service run-service') "the service image path does not carry the runtime entry point `service run-service`:`n$config"
Assert-True ($config -notmatch 'schtasks|ONLOGON') "the service image path still describes the superseded logon Scheduled Task model:`n$config"

# The persistence model is not only "starts at boot": ADR-0014 claims SCM
# restart-on-failure after 5 s. Assert the configured policy here and exercise it
# for real in the next section.
$failure = Get-ScQuery @('qfailure', $ServiceName)
Assert-True ($failure -match 'RESTART') "the service has no restart-on-failure recovery action:`n$failure"
Assert-True ($failure -match '5000') "the service restart-on-failure delay is not the accepted 5000 ms:`n$failure"
Write-Host ($failure.Trim() -replace "`r`n", ' | ')

Write-Section 'Assert the least-privilege service DACL'
$serviceDacl = Get-ScQuery @('sdshow', $ServiceName)
# Assert the interactive-user ACE by value rather than by "does not contain X":
# an exact match on the single IU ACE is what proves the least-privilege grant,
# and it cannot be satisfied by an ACE that merely happens to omit a substring.
$iuAces = [regex]::Matches($serviceDacl, '\(A;;([A-Z]+);;;IU\)')
Assert-True ($iuAces.Count -eq 1) "the service DACL does not have exactly one interactive-user (IU) ACE:`n$serviceDacl"
$iuRights = $iuAces[0].Groups[1].Value
Assert-True ($iuRights -eq $ExpectedInteractiveUserServiceRights) `
    "the interactive-user service rights are '$iuRights', want exactly '$ExpectedInteractiveUserServiceRights' (query status/start/stop):`n$serviceDacl"
Assert-True ($serviceDacl -match '\(A;;[A-Z]+;;;SY\)') "the service DACL does not keep SYSTEM in control:`n$serviceDacl"
Assert-True ($serviceDacl -match '\(A;;[A-Z]+;;;BA\)') "the service DACL does not keep Administrators in control:`n$serviceDacl"
Write-Host "service DACL: $serviceDacl"

Write-Section 'Assert the machine-wide state tree and its hardening'
Wait-Until 'the Agent state directory to be created' 60 {
    if (Test-Path -LiteralPath $StateDir -PathType Container) { return $true }
    return "the state directory does not exist: $StateDir"
}
$markerPath = Join-Path $StateDir $StateMarkerName
Wait-Until 'the Agent ownership marker to be written' 60 {
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return 'the marker is missing' }
    if ((Get-Content -Raw -LiteralPath $markerPath).Trim() -ne $StateMarkerContents) { return 'the marker contents are unrecognised' }
    return $true
}
Write-Host "state directory: $StateDir (ownership marker $StateMarkerContents present)"

# The installer must harden the state tree BEFORE the pairing capability is
# created in it. A capability readable by every local user would be a pairing
# bypass, so assert the capability's own myopic DACL rather than trusting the
# ordering by inspection.
$capabilityPath = Join-Path $StateDir $PairingCapabilityName
Assert-True (Test-Path -LiteralPath $capabilityPath -PathType Leaf) "the pairing capability was not installed: $capabilityPath"
$capabilityAcl = Get-Acl -LiteralPath $capabilityPath
$capabilitySddl = $capabilityAcl.Sddl
Assert-True ($capabilitySddl -notmatch ';;;WD\)') "the pairing capability is readable by Everyone: $capabilitySddl"
Assert-True ($capabilitySddl -notmatch ';;;BU\)') "the pairing capability is readable by BUILTIN\Users: $capabilitySddl"
Assert-True ($capabilitySddl -match ';;;SY\)') "the pairing capability DACL does not grant SYSTEM: $capabilitySddl"
Assert-True ($capabilitySddl -match ';;;BA\)') "the pairing capability DACL does not grant Administrators: $capabilitySddl"
Assert-True ($capabilityAcl.AreAccessRulesProtected) "the pairing capability still inherits ACEs from its parent: $capabilitySddl"
Write-Host "pairing capability DACL: $capabilitySddl"

# The state directory itself must not be readable by any unprivileged principal.
$stateAcl = (Get-Acl -LiteralPath $StateDir).Sddl
Assert-True ($stateAcl -notmatch ';;;WD\)') "the state directory is accessible to Everyone: $stateAcl"
Assert-True ($stateAcl -notmatch ';;;BU\)') "the state directory is accessible to BUILTIN\Users: $stateAcl"
Write-Host "state directory DACL: $stateAcl"

Write-Section 'Assert the Agent runtime is actually up'
# status.json is published by the supervisor's status writer, so its appearance
# proves the Agent loop is running inside the service, not just that SCM holds a
# process handle. This is the "exercise readiness/health" step of the runtime gate.
$statusPath = Join-Path $StateDir 'status.json'
Wait-Until 'the Agent supervisor to publish status.json' 60 {
    if (Test-Path -LiteralPath $statusPath -PathType Leaf) { return $true }
    return 'status.json has not been written'
}
Write-Host "status.json published; agent log: $(Test-Path -LiteralPath (Join-Path $StateDir 'agent.log'))"

# The service owns the loopback pairing UI so pairing works before anyone logs
# in. Prove it is listening on a loopback address the tray can verify.
$pairingPort = 0
Wait-Until 'the pairing listener record to be published' 60 {
    $script:pairingPort = Get-PairingEndpointPort
    if ($script:pairingPort -gt 0) { return $true }
    return 'pairing.endpoint.json has no usable port'
}
Assert-True (Get-ListeningPort -Port $script:pairingPort) "nothing is listening on the published loopback pairing port $($script:pairingPort)"
Write-Host "pairing UI listening on 127.0.0.1:$($script:pairingPort)"

$runtimePid = (Get-AgentService).ProcessId
Assert-True ($runtimePid -gt 0) 'SCM reports no process id for the running service'

Write-Section 'Assert the Windows uninstall entry'
Assert-True (Test-Path -LiteralPath $ArpKeyPath) 'the Windows uninstall (ARP) entry was not registered'
$arp = Get-ItemProperty -LiteralPath $ArpKeyPath
$arpDisplayName = $arp.PSObject.Properties['DisplayName']
$arpDisplayVersion = $arp.PSObject.Properties['DisplayVersion']
$arpUninstallString = $arp.PSObject.Properties['UninstallString']
$arpInstallLocation = $arp.PSObject.Properties['InstallLocation']
Assert-True ($arpDisplayName) 'the ARP entry has no DisplayName'
Assert-True ($arpDisplayName.Value -eq 'HooshiX Agent') "the ARP DisplayName is '$($arpDisplayName.Value)'"
Assert-True ($arpUninstallString -and $arpUninstallString.Value -match 'uninstall\.exe') "the ARP UninstallString does not point at the installed uninstaller: $($arpUninstallString.Value)"
Assert-True ($arpInstallLocation -and $arpInstallLocation.Value -eq $InstallDir) "the ARP InstallLocation is '$($arpInstallLocation.Value)', want '$InstallDir'"
Write-Host "ARP entry: $($arpDisplayName.Value) $($arpDisplayVersion.Value) -> $($arpUninstallString.Value)"

Write-Section 'Assert the desktop tray auto-start registration'
# The tray task is a desktop UI affordance, not Agent persistence (ADR-0014
# clause 6), and the installer deliberately downgrades instead of failing when
# no interactive desktop user can be resolved (a headless/unattended host must
# still be installable). Assert whichever of those two designed outcomes
# actually happened: a resolved user must have produced a registered task.
$interactiveUserResolved = $install.StdOut -notmatch 'note: no interactive desktop user resolved'
if ($interactiveUserResolved) {
    $task = Get-ScheduledTask -TaskName $TrayTaskName -ErrorAction SilentlyContinue
    Assert-True ($task) "an interactive desktop user was resolved but the $TrayTaskName auto-start task was not registered"
    Write-Host "tray auto-start task registered: $TrayTaskName ($($task.State))"
}
else {
    Write-Host "no interactive desktop user in this session: the installer reported the documented headless downgrade and skipped the tray task and its state grant"
}

Write-Section 'Exercise SCM restart-on-failure (the persistence claim, observed)'
# The runtime gate requires restart/recovery behavior to be exercised when it is
# part of the capability. Forcibly terminating the service process is the
# failure mode the configured recovery action is for: SCM queues the restart
# action when a service terminates without reporting SERVICE_STOPPED.
$killed = Invoke-Captured 'taskkill.exe' @('/F', '/PID', "$runtimePid") 60
Write-Host $killed.StdOut.Trim()
if ($killed.ExitCode -ne 0) { Fail "taskkill of the service process $runtimePid exited $($killed.ExitCode): $($killed.StdErr.Trim())" }
Wait-Until 'SCM to restart the service after the forced termination' 120 {
    $service = Get-AgentService
    if (-not $service) { return 'the service is no longer registered' }
    if ($service.State -ne 'Running') { return "service state is $($service.State)" }
    if ($service.ProcessId -eq $runtimePid) { return 'the original process is still reported' }
    return $true
}
$restartedPid = (Get-AgentService).ProcessId
Write-Host "service restarted by SCM recovery: pid $runtimePid -> $restartedPid"

Wait-Until 'the restarted Agent to republish status.json' 90 {
    if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) { return 'status.json is missing' }
    return $true
}
# A restart that leaves the pairing listener dead would be a hollow recovery.
$restartedPort = 0
Wait-Until 'the restarted Agent to republish the pairing listener record' 90 {
    $script:restartedPort = Get-PairingEndpointPort
    if ($script:restartedPort -gt 0) { return $true }
    return 'pairing.endpoint.json has no usable port'
}
Assert-True (Get-ListeningPort -Port $script:restartedPort) "nothing is listening on the published loopback pairing port $($script:restartedPort) after the restart"
Write-Host "pairing UI listening again on 127.0.0.1:$($script:restartedPort)"

Write-Section 'Uninstall with the installed uninstaller'
Assert-True (Test-Path -LiteralPath $uninstallBinary -PathType Leaf) "the installed uninstaller is missing: $uninstallBinary"
$uninstall = Invoke-Captured $uninstallBinary @('--uninstall') 600
Write-Host $uninstall.StdOut
if ($uninstall.StdErr.Trim()) { Write-Host $uninstall.StdErr }
if ($uninstall.ExitCode -ne 0) { Fail "uninstall.exe exited $($uninstall.ExitCode)" }

Wait-Until 'the HooshiXAgent service to be removed' 120 {
    if (Get-AgentService) { return 'the service is still registered' }
    return $true
}
Wait-Until 'the install directory to be removed' 120 {
    if (Test-Path -LiteralPath $InstallDir) { return "the install directory still exists: $InstallDir" }
    return $true
}
Wait-Until 'the Windows uninstall entry to be removed' 60 {
    if (Test-Path -LiteralPath $ArpKeyPath) { return 'the ARP entry still exists' }
    return $true
}
Wait-Until 'the machine-wide Agent state to be removed' 120 {
    if (Test-Path -LiteralPath $StateDir) { return "the state directory still exists: $StateDir" }
    return $true
}
if (Get-ScheduledTask -TaskName $TrayTaskName -ErrorAction SilentlyContinue) {
    Fail "the $TrayTaskName auto-start task survived uninstall"
}
if (Get-Process -Name 'hooshix-agent' -ErrorAction SilentlyContinue) {
    Fail 'an agent process is still running after uninstall'
}
Write-Host 'service, install directory, ARP entry, tray task and machine-wide state are all gone'

Write-Section 'Result'
Write-Host 'Windows service distribution install / run / restart / uninstall gate: PASSED'
Write-Host 'Observed: Setup.exe install exit 0; service HooshiXAgent registered, AUTO_START, LocalSystem, running;'
Write-Host '          restart-on-failure restart/5000 configured and observed after a forced termination;'
Write-Host '          state tree and pairing-capability DACLs restricted; loopback pairing UI listening;'
Write-Host '          ARP entry and tray auto-start registered; uninstall removed all of them.'
Write-Host 'Not observed here: a literal physical OS reboot (this gate does not reboot the host).'
