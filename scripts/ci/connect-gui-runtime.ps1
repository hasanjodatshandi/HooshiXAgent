<#
.SYNOPSIS
Real runtime gate for HooshiX Connect: the Windows GUI executable that turns a
Panel-issued connect bundle into a loopback Connector session.

.DESCRIPTION
Everything else in CI proves the GUI can be built. scripts/build-connect.ps1
asserts the PE subsystem and the linked resources, go test ./... executes
internal/connectgui (the state machine the window renders) and
internal/connectgui/bundlestore.go (the saved-bundle file policy), and
scripts/ci/windows-service-install-smoke.ps1 installs the Agent distribution.
None of them ever starts hooshix-connect.exe, which is why the Executable Runtime
Gate recorded the GUI process as gap G2: an operator-facing capability reported as
verified while no automation had ever run it.

This gate launches the real, shipped-form artifact (built by
scripts/build-connect.ps1: subsystem 2, no console) and asserts what the operator
can observe, through Win32 rather than through any internal state:

  S1  a first run with no saved bundle opens the paste window, says so, and
      writes nothing to disk;
  S2  pressing Connect with nothing pasted is refused, and a malformed bundle is
      refused on the status line, before any loopback port is bound;
  S3  a valid bundle binds the loopback listener, clears the credential from the
      edit, writes hooshix-connect.cfg beside the executable, and collapses the
      window to the compact shape that has no paste area;
  S4  a client that dials the tunnel and dies is reported while the listener
      stays up;
  S5  Disconnect releases the loopback port and says so;
  S6  reconnecting needs no re-paste, and closing the window ends the session and
      exits the process;
  S7  the next run starts compact from the stored file and connects from it,
      which proves the app can read what the app wrote;
  S8  a stored file this Windows account cannot open leaves the paste area up and
      explains itself once, instead of hiding the only way to connect.

The credential is a fixture that points at a closed loopback port, so no network
and no real grant is involved: its gateway is
wss://127.0.0.1:1/connector/v1/connect, which refuses a dial immediately. The
listener, the flow failure, the saved file and the window shape are still the real
code paths.

The gate never touches the machine state the Agent owns. It runs the executable
from a throwaway directory because the saved bundle lives beside the executable:
the file it writes is created, asserted and destroyed inside that directory, and
the build output stays clean.

It fails closed and never skips. It needs an interactive window station and
desktop: a Win32 GUI cannot be observed on Session 0, and a window that never
appears is reported as the precondition failure it is. Server Core and headless
service accounts do not qualify.

What this gate does NOT prove: that a remote desktop session reaches a target.
mstsc, the Agent's rdp endpoint and the target's own single-session licence
arbitration are human paths, evidenced in
docs/engineering/executable-runtime-gate.md and docs/runtime/remote-desktop.md.
This gate also does not read pixels: it asserts control geometry and text, so the
STATIC clipping defect found by capture on 2026-10-12 is guarded by
TestHintTextFitsItsStatic, not here.

Exit code 0 means every assertion below held. Any failure exits non-zero with the
failing assertion named.

.PARAMETER ConnectExe
Path to an already built hooshix-connect.exe. When omitted, the artifact is built
by scripts/build-connect.ps1.

.EXAMPLE
./scripts/ci/connect-gui-runtime.ps1 -ConnectExe dist\hooshix-connect.exe
#>
[CmdletBinding()]
param(
    [string]$ConnectExe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The window class, the control ids and the message box class, re-derived from
# cmd/hooshix-connect/main_windows.go on purpose: the gate observes the product
# from outside, so it must not import the code under test.
$WindowClass = 'HooshiXConnectWindow'
$DialogClass = '#32770'
$DialogBodyId = 65535
$BundleFileName = 'hooshix-connect.cfg'
$IdCaption = 101
$IdBundle = 102
$IdConnect = 103
$IdDisconnect = 104
$IdOpenRdp = 105
$IdStatus = 106
$IdMessage = 107
$IdHint = 108
$IdReveal = 109

# The loopback endpoint connector.DefaultConfig() fixes for a bundle, which never
# overrides the listen address.
$TunnelPort = 13389

# The two authored client heights at 96 DPI: main_windows.go sets clientHeight to
# hintTop + hintHeight + 6, and the compact shape lifts every row under the paste
# area by compactLift.
$FullClientHeightDip = 364
$CompactClientHeightDip = 258

$WmClose = 0x0010
$WmPaste = 0x0302
$BmClick = 0x00F5

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:Workspace = $null
$script:appProcess = $null
$script:ExePath = ''

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title =="
}

function Fail([string]$Message) {
    throw "connect GUI runtime gate failed: $Message"
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { Fail $Message }
}

function Assert-Equals([string]$Expected, [string]$Actual, [string]$What) {
    if ($Actual -ne $Expected) { Fail "$What is '$Actual', want '$Expected'" }
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
        Start-Sleep -Milliseconds 100
    }
}

# The app is system DPI aware: its manifest declares dpiAware true and it scales
# the authored layout from GetDpiForSystem. An observer that is not DPI aware
# receives virtualized rectangles from it, so on a 150% desktop it would measure a
# 96-DPI window and every geometry assertion below would describe the observer
# instead of the app. SetProcessDpiAwarenessContext(-2) is the Win10 1607+ way to
# match the app; SetProcessDPI is its older equivalent. Neither is trusted for its
# own sake: Assert-DpiContext below compares the process system DPI with the DPI
# the window itself reports, and a mismatch is the virtualization this prevents.
Add-Type -Namespace HxGate -Name Win -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumWindowProc callback, IntPtr extra);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowProc callback, IntPtr extra);
public delegate bool EnumWindowProc(IntPtr hwnd, IntPtr extra);
[DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hwnd);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hwnd, System.Text.StringBuilder className, int maxCount);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
[DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr hwnd);
[DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
[DllImport("user32.dll")] public static extern uint GetDpiForSystem();
[DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hwnd);
[DllImport("user32.dll")] public static extern bool SetProcessDPI();
[DllImport("user32.dll", SetLastError=true)] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
[DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);

[StructLayout(LayoutKind.Sequential)] public struct RECT { public int left; public int top; public int right; public int bottom; }

public static string TextOf(IntPtr hwnd) {
    if (hwnd == IntPtr.Zero) { return string.Empty; }
    const int capacity = 4096;
    IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal((capacity + 1) * 2);
    try {
        // WM_GETTEXT is sent straight to the control. GetWindowText must not be
        // used here: across a process boundary it reads the window-text cache, and
        // an edit the target pasted into has an empty cache, so a real credential
        // would look like nothing and the assertion that the app cleared it would
        // pass while proving nothing.
        IntPtr copied = SendMessageW(hwnd, 0x000D, (IntPtr)capacity, buffer);
        int length = copied.ToInt32();
        if (length <= 0) { return string.Empty; }
        return System.Runtime.InteropServices.Marshal.PtrToStringUni(buffer, length);
    }
    finally {
        System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
    }
}

public static void ClearText(IntPtr hwnd) {
    const int capacity = 2;
    IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(capacity * 2);
    try {
        System.Runtime.InteropServices.Marshal.WriteInt32(buffer, 0);
        SendMessageW(hwnd, 0x000C, IntPtr.Zero, buffer);
    }
    finally {
        System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
    }
}

public static IntPtr ChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumWindowProc callback = delegate (IntPtr hwnd, IntPtr extra) {
        if (GetDlgCtrlID(hwnd) == id) { found = hwnd; return false; }
        return true;
    };
    EnumChildWindows(parent, callback, IntPtr.Zero);
    System.GC.KeepAlive(callback);
    return found;
}

public static int ClientHeight(IntPtr hwnd) {
    RECT rect;
    if (!GetClientRect(hwnd, out rect)) { return -1; }
    return rect.bottom - rect.top;
}

public static System.Collections.Generic.List<IntPtr> TopWindows(uint processId, string className) {
    System.Collections.Generic.List<IntPtr> matches = new System.Collections.Generic.List<IntPtr>();
    EnumWindowProc callback = delegate (IntPtr hwnd, IntPtr extra) {
        uint pid;
        GetWindowThreadProcessId(hwnd, out pid);
        if (pid != processId) { return true; }
        System.Text.StringBuilder builder = new System.Text.StringBuilder(256);
        GetClassNameW(hwnd, builder, builder.Capacity);
        if (builder.ToString() == className) { matches.Add(hwnd); }
        return true;
    };
    EnumWindows(callback, IntPtr.Zero);
    System.GC.KeepAlive(callback);
    return matches;
}
'@

function Get-Control([IntPtr]$Window, [int]$Id) {
    $control = [HxGate.Win]::ChildById($Window, $Id)
    if ($control -eq [IntPtr]::Zero) { Fail "the window has no control with id $Id" }
    return $control
}

function Get-ControlText([IntPtr]$Window, [int]$Id) {
    return [HxGate.Win]::TextOf((Get-Control $Window $Id))
}

function Get-StatusText([IntPtr]$Window) { return Get-ControlText $Window $IdStatus }
function Get-MessageText([IntPtr]$Window) { return Get-ControlText $Window $IdMessage }

function Test-ControlShown([IntPtr]$Window, [int]$Id) {
    return [HxGate.Win]::IsWindowVisible((Get-Control $Window $Id))
}

function Assert-Shown([IntPtr]$Window, [int]$Id, [string]$What) {
    Assert-True (Test-ControlShown $Window $Id) "$What is hidden, and this shape must show it"
}

function Assert-Hidden([IntPtr]$Window, [int]$Id, [string]$What) {
    Assert-True (-not (Test-ControlShown $Window $Id)) "$What is visible, and this shape must not show it"
}

function Assert-Button([IntPtr]$Window, [int]$Id, [bool]$Enabled, [string]$What) {
    $live = [HxGate.Win]::IsWindowEnabled((Get-Control $Window $Id))
    if ($live -ne $Enabled) {
        Fail "$What is $(if ($live) { 'enabled' } else { 'disabled' }), but $(if ($Enabled) { 'live' } else { 'idle' }) is the correct state for this status"
    }
}

# The window's own DPI, which is what the app scaled its layout by. The client
# height must then match the authored DIP times that factor; a few pixels of
# tolerance because Win32 rounds each control separately.
function Assert-Height([IntPtr]$Window, [int]$ExpectedDip, [string]$What) {
    $observed = [HxGate.Win]::ClientHeight($Window)
    Assert-True ($observed -gt 0) "the client area of $What could not be measured"
    $dpi = [HxGate.Win]::GetDpiForWindow($Window)
    $expected = [int][Math]::Round($ExpectedDip * ($dpi / 96))
    if ([Math]::Abs($observed - $expected) -gt 4) {
        Fail "$What has a client height of $observed px, want $expected px ($ExpectedDip DIP at $dpi DPI)"
    }
    Write-Host "$What client height: $observed px ($ExpectedDip DIP at $dpi DPI)"
}

function Assert-DpiContext([IntPtr]$Window) {
    $systemDpi = [HxGate.Win]::GetDpiForSystem()
    $windowDpi = [HxGate.Win]::GetDpiForWindow($Window)
    Assert-True ($systemDpi -eq $windowDpi) "this gate reads the desktop as $systemDpi DPI while the app's window reports ${windowDpi}: the observer is DPI virtualized, so geometry measured here would not describe the app"
    Write-Host "DPI context: system $systemDpi, window $windowDpi"
}

function Invoke-Click([IntPtr]$Window, [int]$Id) {
    Assert-Button $Window $Id $true "control $Id"
    [void][HxGate.Win]::PostMessageW((Get-Control $Window $Id), $BmClick, [IntPtr]::Zero, [IntPtr]::Zero)
}

# A cross-process WM_SETTEXT on an edit does replace its contents, but the app
# reads the control through its own buffer, so the gate types the way an operator
# does: the clipboard, then WM_PASTE. WM_PASTE inserts at the selection, so the
# box is emptied first, and the readback goes through WM_GETTEXT because the
# window-text cache an outside GetWindowText would see is not the edit buffer.
function Set-PastedBundle([IntPtr]$Window, [string]$Bundle) {
    $edit = Get-Control $Window $IdBundle
    Assert-Shown $Window $IdBundle 'the paste area'
    # Each attempt re-clips, empties the box and pastes once, then reads the edit
    # back. A cross-process SendMessageW is not guaranteed to act: if the target
    # thread is not pumping at that instant the call returns and the control has
    # done nothing, which reads as an empty box rather than as a lost message.
    # Bounded retry turns that into either the exact bundle or a named failure,
    # and re-clipping means a clipboard another process claimed between attempts
    # cannot make the gate paste something else.
    $read = ''
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        Set-Clipboard -Value $Bundle
        [HxGate.Win]::ClearText($edit)
        [void][HxGate.Win]::SendMessageW($edit, $WmPaste, [IntPtr]::Zero, [IntPtr]::Zero)
        $read = [HxGate.Win]::TextOf($edit)
        if ($read -eq $Bundle) { return }
        Start-Sleep -Milliseconds 500
    }
    Fail "the bundle did not reach the edit control after 10 paste attempts (it holds '$read')"
}

function Get-LoopbackListener([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(3000)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Assert-PortBound([int]$Port) {
    Wait-Until "the tunnel listener on 127.0.0.1:$Port to accept a client" 20 {
        if (Get-LoopbackListener $Port) { return $true }
        return "nothing accepts on 127.0.0.1:$Port"
    }
    Write-Host "tunnel listener accepts on 127.0.0.1:$Port"
}

function Assert-PortReleased([int]$Port) {
    Wait-Until "the tunnel listener on 127.0.0.1:$Port to be released" 20 {
        if (-not (Get-LoopbackListener $Port)) { return $true }
        return "127.0.0.1:$Port still accepts"
    }
    Write-Host "tunnel listener released on 127.0.0.1:$Port"
}

function Assert-StatusListening([IntPtr]$Window, [string]$When) {
    Wait-Until "${When}: the status line to report the listening tunnel" 25 {
        $status = Get-StatusText $Window
        if ($status -eq "Status: listening on 127.0.0.1:$TunnelPort (tcp)") { return $true }
        return "the status line is '$status' / $(Get-MessageText $Window)"
    }
    Write-Host "$When status line: $(Get-StatusText $Window)"
}

# The dial is held briefly and then closed by the gate. A client that connects and
# dies is the event the status line has to report, and TcpClient can report success
# against a socket the app closes immediately, so the wait for the report is what
# carries the assertion.
function Invoke-TunnelDial([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { Fail "the tunnel listener on port $Port never accepted a client" }
        $client.EndConnect($async)
        Start-Sleep -Milliseconds 400
    }
    finally {
        $client.Close()
    }
}

function Get-WrittenFiles {
    if (-not (Test-Path -LiteralPath $script:Workspace)) { return @() }
    # Leaf names, and only from the workspace root. The store's whole contract is that
    # hooshix-connect.cfg lives beside hooshix-connect.exe, so the root listing is the
    # complete set, and directories are included because the app must not create any.
    # Names are never produced by trimming the workspace prefix off FullName: on a
    # GitHub Windows runner $env:TEMP is the 8.3 form (C:\Users\RUNNER~1\AppData\Local\Temp)
    # while Get-ChildItem reports long FullName values, so that slice is short by the
    # width difference and the first hosted run of this gate read a file the app had
    # just written as '39\hooshix-connect.cfg', then reported it as missing.
    return @(Get-ChildItem -Force -LiteralPath $script:Workspace |
        Where-Object { $_.Extension -ne '.exe' } |
        ForEach-Object { if ($_.PSIsContainer) { $_.Name + '\' } else { $_.Name } })
}

function Assert-FilesAre([string[]]$Expected, [string]$When) {
    $observed = @(Get-WrittenFiles)
    $missing = @($Expected | Where-Object { $observed -notcontains $_ })
    $extra = @($observed | Where-Object { $Expected -notcontains $_ })
    Assert-True ($missing.Count -eq 0) "$When wrote no $($missing -join ', ') (files present: '$($observed -join "', '")')"
    # A half-published bundle file or a leftover temporary is a real defect: the
    # store publishes by rename precisely so an interrupted write is unobservable.
    Assert-True ($extra.Count -eq 0) "$When left unexpected files: $($extra -join ', ')"
    Write-Host "$When files beside the exe: '$($observed -join "', '")'"
}

function Read-BundleFile {
    $path = Join-Path $script:Workspace $BundleFileName
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "the saved bundle file is missing: $path"
    return Get-Content -Raw -LiteralPath $path
}

function Set-ForgedBundleFile([string]$Payload) {
    $lines = @(
        '# HooshiX Connect saved bundle.',
        'version=1',
        ('saved_at=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
        ('bundle=' + $Payload)
    )
    # Written directly, not through the store: this is the file an operator gets by
    # copying hooshix-connect.cfg from another machine or account, and the app has
    # to survive a file it did not write itself.
    Set-Content -LiteralPath (Join-Path $script:Workspace $BundleFileName) -Value ($lines -join "`r`n") -Encoding Ascii
}

function Get-AppDialog {
    if ($null -eq $script:appProcess) { return $null }
    $boxes = [HxGate.Win]::TopWindows([uint32]$script:appProcess.Id, $DialogClass)
    if ($boxes.Count -eq 0) { return $null }
    return [pscustomobject]@{
        Handle = $boxes[0]
        Text   = [HxGate.Win]::TextOf((Get-Control $boxes[0] $DialogBodyId))
    }
}

function Assert-Dialog([string]$ExpectedFragment, [string]$When) {
    Wait-Until "${When}: the app to report the refusal in a dialog" 20 {
        $dialog = Get-AppDialog
        if ($null -eq $dialog) { return 'no dialog yet' }
        if ($dialog.Text -notlike "*$ExpectedFragment*") { return "the dialog says: $($dialog.Text)" }
        return $true
    }
    $dialog = Get-AppDialog
    Write-Host "${When}: dialog reported: $($dialog.Text)"
    # Dismissing it is what the operator does. The message loop is blocked until
    # the box is answered, so every later assertion depends on this step.
    [void][HxGate.Win]::PostMessageW($dialog.Handle, $WmClose, [IntPtr]::Zero, [IntPtr]::Zero)
    Wait-Until "${When}: the dialog to close" 20 {
        if ($null -eq (Get-AppDialog)) { return $true }
        return 'the dialog is still up'
    }
}

function Assert-NoDialog([string]$When) {
    $dialog = Get-AppDialog
    if ($null -ne $dialog) { Fail "${When}: the app raised a dialog nobody asked for: $($dialog.Text)" }
}

function Stop-ConnectApp([string]$When) {
    if ($null -eq $script:appProcess) { return }
    $process = $script:appProcess
    $script:appProcess = $null
    $windows = [HxGate.Win]::TopWindows([uint32]$process.Id, $WindowClass)
    if ($windows.Count -gt 0) {
        # The designed exit is the window closing: that runs the app's own
        # teardown, which releases the loopback port before it quits the loop.
        [void][HxGate.Win]::PostMessageW($windows[0], $WmClose, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    if (-not $process.WaitForExit(20000)) {
        try { $process.Kill() } catch { }
        Fail "${When}: the app was still running 20 s after its window closed and had to be killed"
    }
    Write-Host "${When}: process $($process.Id) exited with code $($process.ExitCode)"
}

function Get-ShownMainWindow([uint32]$ProcessId) {
    # EnumWindows reports the frame as soon as CreateWindowExW returns, which is
    # before the app has created a single control: the frame is built without
    # WS_VISIBLE and shown only after its children exist and the shape is applied.
    # Taking the first match therefore races the app's own startup, and on the
    # runner that race read as "the window has no control with id 106" seconds
    # after a window had supposedly been found. A visible frame is the app saying
    # it is done building, so the gate only ever returns those.
    return @([HxGate.Win]::TopWindows($ProcessId, $WindowClass) |
        Where-Object { [HxGate.Win]::IsWindowVisible($_) })
}

function Start-ConnectApp([string]$When) {
    Stop-ConnectApp "$When (previous instance)"
    $script:appProcess = Start-Process -FilePath $script:ExePath -PassThru -WorkingDirectory $script:Workspace
    $process = $script:appProcess
    Write-Host "${When}: started pid $($process.Id) from $script:ExePath"
    Wait-Until "${When}: the HooshiX Connect window to appear" 30 {
        if ($process.HasExited) { return "the process exited with code $($process.ExitCode)" }
        $windows = [HxGate.Win]::TopWindows([uint32]$process.Id, $WindowClass)
        if ($windows.Count -eq 0) {
            $boxes = [HxGate.Win]::TopWindows([uint32]$process.Id, $DialogClass)
            if ($boxes.Count -gt 0) {
                # A modal box from a process that never reached its message loop is
                # the app's own startup failure report: built with -H windowsgui it
                # has no console to say it in.
                return "the app showed a startup dialog instead of a window: $([HxGate.Win]::TextOf((Get-Control $boxes[0] $DialogBodyId)))"
            }
            return 'no window yet'
        }
        # @() at the call site, not in the function: PowerShell unrolls the array a
        # function returns, so one visible window arrives as a bare IntPtr with no
        # Count property and zero arrive as $null.
        if (@(Get-ShownMainWindow ([uint32]$process.Id)).Count -gt 0) { return $true }
        return 'the frame exists but the app has not shown it yet'
    }
    $shown = @(Get-ShownMainWindow ([uint32]$process.Id))
    Assert-True ($shown.Count -gt 0) "${When}: the window stopped being visible before the gate could read it"
    $window = $shown[0]
    Assert-DpiContext $window
    return $window
}

Write-Section 'Preconditions'
if ($env:OS -ne 'Windows_NT') { Fail 'this gate only runs on Windows: the app under test is a Win32 message loop' }

$aware = [HxGate.Win]::SetProcessDpiAwarenessContext([IntPtr]::new(-2))
if (-not $aware) { $aware = [HxGate.Win]::SetProcessDPI() }
Write-Host "DPI awareness requested: $(if ($aware) { 'accepted' } else { 'refused, checked against the window DPI below' })"
Write-Host "session name: '$([System.Environment]::GetEnvironmentVariable('SESSIONNAME'))'"

if (-not $ConnectExe) {
    Write-Host 'building the artifact with scripts/build-connect.ps1 ...'
    & (Join-Path $RepoRoot 'scripts\build-connect.ps1')
    Assert-True ($LASTEXITCODE -eq 0) "scripts/build-connect.ps1 exited $LASTEXITCODE"
    $ConnectExe = Join-Path $RepoRoot 'dist\hooshix-connect.exe'
}
$builtPath = (Resolve-Path -LiteralPath $ConnectExe).Path
$exeBytes = (Get-Item -LiteralPath $builtPath).Length
Assert-True ($exeBytes -gt 1MB) "hooshix-connect.exe is suspiciously small ($exeBytes bytes): $builtPath"
Write-Host "artifact: $builtPath ($exeBytes bytes, sha256 $((Get-FileHash -Algorithm SHA256 -LiteralPath $builtPath).Hash.ToLowerInvariant()))"

# A leftover instance would be driven by mistake: the gate finds its window by
# class and its saved bundle by directory, and either could belong to the other.
$leftover = @(Get-Process -Name 'hooshix-connect' -ErrorAction SilentlyContinue)
$leftoverNote = if ($leftover.Count -gt 0) { " (pid $($leftover[0].Id))" } else { '' }
Assert-True ($leftover.Count -eq 0) "a hooshix-connect process is already running$leftoverNote; the gate cannot tell its window from the one it starts"

# The tunnel port belongs to the app under test. If anything else holds it, the
# bind and release assertions below would be about that other process.
Assert-True (-not (Get-LoopbackListener $TunnelPort)) "something already listens on 127.0.0.1:$TunnelPort; the gate needs the loopback tunnel port to itself"

# Start from a clean directory: the saved bundle lives beside the executable, so
# its absence at S1 and its presence at S3 are the evidence, and a file left over
# from an earlier run would fake a pass.
$script:Workspace = Join-Path $env:TEMP ('hooshix-connect-gate-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
New-Item -ItemType Directory -Force $script:Workspace | Out-Null
Copy-Item -LiteralPath $builtPath -Destination (Join-Path $script:Workspace 'hooshix-connect.exe')
$script:ExePath = Join-Path $script:Workspace 'hooshix-connect.exe'
Assert-FilesAre @() 'before the first run'

# The credential is a fixture. It satisfies the connector contract exactly (wss
# scheme, the /connector/v1/connect path, identifier-shaped ids, a 32..512
# non-whitespace token) because a bundle the parser rejects would exercise the
# wrong path; its gateway is a closed loopback port, so every dial the app attempts
# is refused on the spot and the gate never reaches a network or a live grant.
$FixtureToken = 'gatefixturesealedneverissued0123456789abcdef'
$fixturePayload = '{"gateway":"wss://127.0.0.1:1/connector/v1/connect","grant_id":"gate-grant-0001","token_id":"gate-token-0001","token":"' +
    $FixtureToken + '","protocol":"tcp","max_connections":4}'
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fixturePayload))
$bundle = 'hx1.' + (($encoded -replace '\+', '-') -replace '/', '_' -replace '=', '')
Write-Host "fixture bundle: $($bundle.Length) characters, gateway wss://127.0.0.1:1 (always refused)"

try {
    Write-Section 'S1 a first run with no saved bundle opens the paste window and writes nothing'
    $window = Start-ConnectApp 'S1'
    Assert-Equals 'Status: idle' (Get-StatusText $window) 'the status line'
    Assert-Equals 'paste a connect bundle and press Connect' (Get-MessageText $window) 'the instruction line'
    Assert-Shown $window $IdCaption 'the paste caption'
    Assert-Shown $window $IdBundle 'the paste area'
    Assert-Hidden $window $IdReveal 'the saved-bundle button'
    Assert-Height $window $FullClientHeightDip 'the paste window'
    $hint = Get-ControlText $window $IdHint
    Assert-True ($hint -like 'One Remote Desktop client at a time*') "the hint of the paste window is '$hint'"
    Assert-Button $window $IdConnect $true 'Connect'
    Assert-Button $window $IdDisconnect $false 'Disconnect'
    Assert-Button $window $IdOpenRdp $false 'Open Remote Desktop'
    Assert-True (-not (Get-LoopbackListener $TunnelPort)) 'S1: the loopback tunnel port is bound before anything was connected'
    Assert-FilesAre @() 'a first run with no saved bundle'
    Assert-NoDialog 'S1'

    Write-Section 'S2 an empty paste and a malformed bundle are both refused, with no listener'
    Invoke-Click $window $IdConnect
    Assert-Dialog 'paste the connect bundle the Panel issued first' 'S2 with nothing pasted'
    Assert-True (-not (Get-LoopbackListener $TunnelPort)) 'S2: a refused Connect still bound the loopback port'
    Assert-FilesAre @() 'a refused Connect'

    Set-PastedBundle $window 'hx1.!!!'
    Invoke-Click $window $IdConnect
    Wait-Until 'S2: the status line to report the rejected bundle' 20 {
        $status = Get-StatusText $window
        if ($status -eq 'Status: failed') { return $true }
        return "the status line is '$status'"
    }
    $rejected = Get-MessageText $window
    Assert-True ($rejected -like '*is not valid base64url*') "the message line does not name the parse failure: '$rejected'"
    Write-Host "rejected bundle reported on the status line: $rejected"
    Assert-True (-not (Get-LoopbackListener $TunnelPort)) 'S2: a malformed bundle bound the loopback port'
    Assert-FilesAre @() 'a malformed bundle'
    Assert-NoDialog 'S2'
    Assert-Button $window $IdConnect $true 'Connect, after its own failure'

    Write-Section 'S3 a valid bundle binds the tunnel, clears the edit, saves the cfg, and collapses the window'
    Set-PastedBundle $window $bundle
    Invoke-Click $window $IdConnect
    Assert-StatusListening $window 'S3'
    $ready = Get-MessageText $window
    Assert-True ($ready -like "tunnel ready*127.0.0.1:$TunnelPort*") "the instruction line does not publish the tunnel address: '$ready'"

    # The bearer credential leaves the window on a successful Connect, so it stops
    # sitting in a text box the operator leaves open or records.
    Assert-Equals '' (Get-ControlText $window $IdBundle) 'the edit control after a successful Connect'

    $cfg = Read-BundleFile
    Assert-FilesAre @($BundleFileName) 'a successful Connect'
    Assert-True ($cfg -match '(?m)^version=1$') "the saved bundle file does not declare version 1:`n$cfg"
    Assert-True ($cfg -match '(?m)^saved_at=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') "the saved bundle file has no readable saved_at:`n$cfg"
    Assert-True ($cfg -match '(?m)^bundle=[A-Za-z0-9+/=]+$') 'the saved bundle file holds no sealed payload'
    # The whole point of sealing: this file is a credential store that must not
    # read like one.
    Assert-True ($cfg -notlike '*hx1.*') 'the saved bundle file contains the plaintext bundle prefix'
    Assert-True ($cfg -notlike "*$FixtureToken*") 'the saved bundle file contains the fixture token'
    Write-Host "saved bundle file: $((Get-Item (Join-Path $script:Workspace $BundleFileName)).Length) bytes, sealed payload only"

    Assert-Hidden $window $IdBundle 'the paste area after the bundle was saved'
    Assert-Hidden $window $IdCaption 'the paste caption after the bundle was saved'
    Assert-Shown $window $IdReveal 'the saved-bundle button'
    Assert-Height $window $CompactClientHeightDip 'the compact window'
    $reveal = Get-ControlText $window $IdReveal
    Assert-True ($reveal -match 'last saved \d{4}-\d{2}-\d{2}') "the saved-bundle button does not name the date it runs from: '$reveal'"
    Write-Host "saved-bundle button: $reveal"
    Assert-True ((Get-ControlText $window $IdHint) -like 'The bundle is saved beside hooshix-connect.exe*') 'the compact hint does not explain the saved bundle'
    Assert-Button $window $IdConnect $false 'Connect, while the tunnel is up'
    Assert-Button $window $IdDisconnect $true 'Disconnect, while the tunnel is up'
    Assert-Button $window $IdOpenRdp $true 'Open Remote Desktop, for a tcp tunnel with no client'
    Assert-NoDialog 'S3'

    # The listener probe is last: dialing the port ends a flow, and the flow report
    # changes the message line the assertions above read.
    Assert-PortBound $TunnelPort

    Write-Section 'S4 a client that dials and dies is reported while the listener stays up'
    Invoke-TunnelDial $TunnelPort
    Wait-Until 'S4: the dead client to reach the message line' 25 {
        $message = Get-MessageText $window
        if ($message -like '*Last client ended*') { return $true }
        return "the message line is '$message'"
    }
    $flow = Get-MessageText $window
    Write-Host "flow failure reported: $flow"
    # The gateway here is a closed port, so the honest report is a dial failure.
    Assert-True ($flow -like '*dial connector gateway*') "the flow report does not name the gateway dial failure: '$flow'"
    Assert-Equals "Status: listening on 127.0.0.1:$TunnelPort (tcp)" (Get-StatusText $window) 'the status line after a failed flow'
    Assert-PortBound $TunnelPort
    Assert-Button $window $IdOpenRdp $true 'Open Remote Desktop, once the dead client is gone'
    Assert-NoDialog 'S4'

    Write-Section 'S5 Disconnect releases the loopback port and says so'
    Invoke-Click $window $IdDisconnect
    Wait-Until 'S5: the status line to report the stopped session' 25 {
        $status = Get-StatusText $window
        if ($status -eq 'Status: stopped') { return $true }
        return "the status line is '$status'"
    }
    $stopped = Get-MessageText $window
    Assert-True ($stopped -like '*press Connect to open another tunnel*') "the stopped session does not say how to reconnect: '$stopped'"
    Write-Host "stopped session: $(Get-StatusText $window) / $stopped"
    Assert-PortReleased $TunnelPort
    Assert-Button $window $IdConnect $true 'Connect, after Disconnect'
    Assert-Button $window $IdDisconnect $false 'Disconnect, after Disconnect'
    Assert-Button $window $IdOpenRdp $false 'Open Remote Desktop, after Disconnect'
    Assert-NoDialog 'S5'

    Write-Section 'S6 reconnect needs no re-paste, and closing the window ends the session'
    # The edit is empty and the paste area is hidden: this Connect can only come
    # from the bundle the app is still holding.
    Assert-Equals '' (Get-ControlText $window $IdBundle) 'the edit control before the reconnect'
    Invoke-Click $window $IdConnect
    Assert-StatusListening $window 'S6'
    Assert-PortBound $TunnelPort
    Write-Host 'reconnected from the remembered bundle with nothing pasted'

    [void][HxGate.Win]::PostMessageW($window, $WmClose, [IntPtr]::Zero, [IntPtr]::Zero)
    Wait-Until 'S6: the process to exit when its window closed' 25 {
        if ($script:appProcess.HasExited) { return $true }
        return 'the process is still running'
    }
    Write-Host "process $($script:appProcess.Id) exited with code $($script:appProcess.ExitCode)"
    $script:appProcess = $null
    Assert-PortReleased $TunnelPort
    Assert-FilesAre @($BundleFileName) 'the exit'

    Write-Section 'S7 the next run starts compact from the stored file and connects from it'
    $window = Start-ConnectApp 'S7'
    Assert-Equals 'Status: idle' (Get-StatusText $window) 'the status line of a run that woke up with a saved bundle'
    Assert-Equals 'press Connect to open the tunnel with the saved bundle' (Get-MessageText $window) 'the instruction line of a run that woke up with a saved bundle'
    Assert-Hidden $window $IdBundle 'the paste area of a run that woke up with a saved bundle'
    Assert-Hidden $window $IdCaption 'the paste caption of a run that woke up with a saved bundle'
    Assert-Shown $window $IdReveal 'the saved-bundle button'
    Assert-Height $window $CompactClientHeightDip 'the window of a run that woke up with a saved bundle'
    Assert-Button $window $IdConnect $true 'Connect, on a window holding a stored bundle'
    Assert-NoDialog 'S7'

    Invoke-Click $window $IdConnect
    Assert-StatusListening $window 'S7'
    Assert-PortBound $TunnelPort
    Write-Host 'the stored bundle opened the tunnel on its own, with nothing pasted'
    Stop-ConnectApp 'S7'

    Write-Section 'S8 a stored file this account cannot open leaves the paste area up and explains itself'
    Set-ForgedBundleFile ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('this blob was not sealed for this user')))
    $window = Start-ConnectApp 'S8'
    Assert-Equals 'Status: idle' (Get-StatusText $window) 'the status line of a run holding an unreadable store'
    Assert-Equals 'paste a connect bundle and press Connect' (Get-MessageText $window) 'the instruction line of a run holding an unreadable store'
    # The failure must not cost the operator the only way to connect.
    Assert-Shown $window $IdBundle 'the paste area of a run holding an unreadable store'
    Assert-Hidden $window $IdReveal 'the saved-bundle button of a run holding an unreadable store'
    Assert-Height $window $FullClientHeightDip 'the window of a run holding an unreadable store'
    Assert-Dialog 'cannot use a saved bundle' 'S8 with an unreadable store'
    Assert-FilesAre @($BundleFileName) 'a run that could not open its store'

    Set-PastedBundle $window $bundle
    Invoke-Click $window $IdConnect
    Assert-StatusListening $window 'S8'
    Assert-PortBound $TunnelPort
    Assert-Equals '' (Get-ControlText $window $IdBundle) 'the edit control after S8 connected'
    # The unreadable file is replaced by the bundle that just worked, so the next
    # run is not stuck on a credential this machine cannot open.
    $resealed = Read-BundleFile
    Assert-True ($resealed -notlike '*this blob was not sealed*') 'S8: the unreadable store survived a bundle that worked'
    Assert-True ($resealed -notlike "*$FixtureToken*") 'S8: the resealed file contains the fixture token'
    Assert-NoDialog 'S8'
    Stop-ConnectApp 'S8'

    Write-Section 'Cleanup'
    Assert-True (-not (Get-LoopbackListener $TunnelPort)) 'the gate finished with the loopback tunnel port still bound'
    if (Test-Path -LiteralPath (Join-Path $RepoRoot "dist\$BundleFileName")) {
        Fail "the gate left a saved bundle file in the build output: dist\$BundleFileName"
    }
    Write-Host 'build output untouched: dist holds no saved bundle file'

    Write-Section 'Result'
    Write-Host 'HooshiX Connect GUI runtime gate: PASSED'
    Write-Host 'Observed: the shipped hooshix-connect.exe opened its window, refused an empty paste and a'
    Write-Host '          malformed bundle without binding a port, bound 127.0.0.1:13389 from a valid bundle,'
    Write-Host '          cleared the credential from the edit, wrote a sealed hooshix-connect.cfg beside'
    Write-Host '          itself, collapsed to the compact shape, reported a dead client while staying up,'
    Write-Host '          released the port on Disconnect, reconnected with no re-paste, exited when its'
    Write-Host '          window closed, started compact from the stored file and connected from it, and'
    Write-Host '          fell back to the paste window when the stored file could not be opened.'
    Write-Host 'Not observed here: a remote desktop session reaching a target, and rendered pixels. Both are'
    Write-Host '          recorded as limits in docs/engineering/executable-runtime-gate.md.'
}
finally {
    try {
        if ($null -ne $script:appProcess) { Stop-ConnectApp 'teardown' }
    }
    catch {
        Write-Host "teardown: the app could not be closed cleanly: $($_.Exception.Message)"
    }
    if ($script:Workspace -and (Test-Path -LiteralPath $script:Workspace)) {
        # The workspace holds the sealed credential. It is the directory this gate
        # created and named for itself, so removing it is that credential's whole
        # lifetime on the machine.
        Remove-Item -Recurse -Force -LiteralPath $script:Workspace
        Write-Host "workdir removed: $($script:Workspace)"
    }
}
