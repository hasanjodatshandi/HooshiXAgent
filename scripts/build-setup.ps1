# Build the HooshiX desktop distribution: agent binary, tray binary, and the
# self-contained Setup.exe with both embedded.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\build-setup.ps1
# Output: dist\HooshiXAgent-Setup.exe (plus dist\hooshix-agent.exe, dist\hooshix-agent-tray.exe)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo "dist"
$payload = Join-Path $repo "cmd\hooshix-setup\payload"

New-Item -ItemType Directory -Force $dist | Out-Null
New-Item -ItemType Directory -Force $payload | Out-Null

# GOFLAGS ensures the module cache path works from any shell.
$env:GOFLAGS = ""

Write-Host "== building agent =="
go build -trimpath -ldflags "-s -w" -o "$dist\hooshix-agent.exe" ./cmd/agent
if ($LASTEXITCODE -ne 0) { throw "agent build failed" }

Write-Host "== building tray =="
go build -trimpath -ldflags "-s -w -H windowsgui" -o "$dist\hooshix-agent-tray.exe" ./cmd/hooshix-agent-tray
if ($LASTEXITCODE -ne 0) { throw "tray build failed" }

# Copy payloads for embed.
Copy-Item "$dist\hooshix-agent.exe" "$payload\hooshix-agent.exe" -Force
Copy-Item "$dist\hooshix-agent-tray.exe" "$payload\hooshix-agent-tray.exe" -Force

Write-Host "== building setup (embedded payload + UAC manifest) =="
$manifest = Join-Path $repo "cmd\hooshix-setup\app.manifest"
& "C:\Users\Coder\go\bin\rsrc.exe" -manifest $manifest -o "$payload\setup.syso"
if ($LASTEXITCODE -ne 0) { throw "rsrc failed" }

go build -trimpath -ldflags "-s -w" -o "$dist\HooshiXAgent-Setup.exe" ./cmd/hooshix-setup
if ($LASTEXITCODE -ne 0) { throw "setup build failed" }

Write-Host ""
Write-Host "done: $dist\HooshiXAgent-Setup.exe"
