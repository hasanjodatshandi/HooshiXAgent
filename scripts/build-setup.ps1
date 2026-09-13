# Build the HooshiX desktop distribution: agent binary, tray binary, and the
# self-contained Setup.exe with both embedded.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\build-setup.ps1
# Output: dist\HooshiXAgent-Setup.exe (plus dist\hooshix-agent.exe, dist\hooshix-agent-tray.exe)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo "dist"
$payload = Join-Path $repo "cmd\hooshix-setup\payload"
$trayResource = Join-Path $repo "cmd\hooshix-agent-tray\rsrc_windows_amd64.syso"
$setupResource = Join-Path $repo "cmd\hooshix-setup\rsrc_windows_amd64.syso"

New-Item -ItemType Directory -Force $dist | Out-Null
New-Item -ItemType Directory -Force $payload | Out-Null

# GOFLAGS ensures the module cache path works from any shell.
$env:GOFLAGS = ""

Write-Host "== building agent =="
go build -trimpath -ldflags "-s -w" -o "$dist\hooshix-agent.exe" ./cmd/agent
if ($LASTEXITCODE -ne 0) { throw "agent build failed" }

Write-Host "== building tray =="
# Reproducibly regenerate the tray icon resource (multi-size ICO from the
# brand PNG) before building so clean checkouts get the branded icon.
$logo = Join-Path $repo "assests\logo.png"
$ico = Join-Path $repo "cmd\hooshix-agent-tray\hooshix.ico"
if (-not (Test-Path $logo)) { throw "brand logo missing: $logo" }
$makeIco = Join-Path $repo "scripts\make-ico.ps1"
try {
if (Test-Path $makeIco) {
  powershell -NoProfile -ExecutionPolicy Bypass -File $makeIco -Source $logo -Destination $ico
  if ($LASTEXITCODE -ne 0) { throw "icon generation failed" }
} elseif (-not (Test-Path $ico)) {
  throw "tray icon missing: $ico (scripts\make-ico.ps1 not found)"
}
# Resolve rsrc.exe (embeds the icon/manifest resources) from GOPATH or PATH
# so the build works on any machine, not just one specific user profile.
function Find-Rsrc {
    $fromPath = Get-Command rsrc.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $goPath = (go env GOPATH).Trim()
    if ($goPath) {
        $candidate = Join-Path ($goPath -split ';' | Select-Object -First 1) "bin\rsrc.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    throw "rsrc.exe not found. Install it with: go install github.com/akavel/rsrc@v0.10.2"
}
$rsrc = Find-Rsrc
$version = if ($env:HOOSHIX_VERSION) { $env:HOOSHIX_VERSION } else { 'dev' }

function Sign-Binary([string]$Path) {
    if (-not $env:HOOSHIX_SIGN_CERT_PATH) { return }
    $signTool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if (-not $signTool) { throw "signtool.exe not found but HOOSHIX_SIGN_CERT_PATH is set" }
    $arguments = @('sign', '/fd', 'SHA256', '/f', $env:HOOSHIX_SIGN_CERT_PATH)
    if ($env:HOOSHIX_SIGN_CERT_PASSWORD) { $arguments += @('/p', $env:HOOSHIX_SIGN_CERT_PASSWORD) }
    if ($env:HOOSHIX_SIGN_TIMESTAMP_URL) { $arguments += @('/tr', $env:HOOSHIX_SIGN_TIMESTAMP_URL, '/td', 'SHA256') }
    $arguments += $Path
    & $signTool @arguments
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $Path" }
}

    & $rsrc -arch amd64 -ico $ico -o $trayResource
    if ($LASTEXITCODE -ne 0) { throw "tray rsrc failed" }
    go build -trimpath -ldflags "-s -w -H windowsgui" -o "$dist\hooshix-agent-tray.exe" ./cmd/hooshix-agent-tray
    if ($LASTEXITCODE -ne 0) { throw "tray build failed" }
    Sign-Binary "$dist\hooshix-agent.exe"
    Sign-Binary "$dist\hooshix-agent-tray.exe"

    # Copy payloads for embed.
    Copy-Item "$dist\hooshix-agent.exe" "$payload\hooshix-agent.exe" -Force
    Copy-Item "$dist\hooshix-agent-tray.exe" "$payload\hooshix-agent-tray.exe" -Force

    Write-Host "== building setup (embedded payload + UAC manifest) =="
    # The UAC manifest syso must sit in the package directory itself: the Go
    # linker only links *.syso files from the package dir, not payload/.
    $manifest = Join-Path $repo "cmd\hooshix-setup\app.manifest"
    & $rsrc -manifest $manifest -o $setupResource
    if ($LASTEXITCODE -ne 0) { throw "rsrc failed" }

    go build -trimpath -ldflags "-s -w -X main.setupVersion=$version" -o "$dist\HooshiXAgent-Setup.exe" ./cmd/hooshix-setup
    if ($LASTEXITCODE -ne 0) { throw "setup build failed" }
    Sign-Binary "$dist\HooshiXAgent-Setup.exe"
}
finally {
    Remove-Item $trayResource, $setupResource, $ico -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "done: $dist\HooshiXAgent-Setup.exe"
