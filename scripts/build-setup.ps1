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
$version = if ($env:HOOSHIX_VERSION) { $env:HOOSHIX_VERSION } else { 'dev' }

# The distribution payload must be the released Windows package, not merely a
# build of the same source: cmd/hooshix-setup embeds these binaries and installs
# them as the machine-wide Agent. The target and flags below are therefore
# pinned to match scripts/release/build-release.sh's windows/amd64 package
# exactly — same GOOS/GOARCH, CGO_ENABLED=0 (the module is pure Go, so no C
# toolchain participates), -trimpath, and the same agent.Version linker value.
# Setup.exe ships only the amd64 package, which is also the package the release
# workflow's Windows job ties the embedded payload to through
# HOOSHIX_RELEASE_SHA256SUMS (verified below).
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$agentLdflags = "-s -w -X github.com/hasanjodatshandi/HooshiXAgent/internal/agent.Version=$version"

Write-Host "== building agent =="
go build -trimpath -ldflags $agentLdflags -o "$dist\hooshix-agent.exe" ./cmd/agent
if ($LASTEXITCODE -ne 0) { throw "agent build failed" }

Write-Host "== building tray =="
# Reproducibly regenerate the tray icon resource (multi-size ICO from the
# brand PNG) before building so clean checkouts get the branded icon.
$logo = Join-Path $repo "assets\logo.png"
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
# Status-tinted variants (green/yellow/red) let the tray icon show tunnel
# health at a glance. Tinting is deterministic from the base ICO; outputs
# land in internal/tray for go:embed and are also committed so a clean
# checkout without Python still builds.
$tintScript = Join-Path $repo "scripts\tint_ico.py"
if (Test-Path $tintScript) {
  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) {
    & $python.Source $tintScript $ico `
      --green (Join-Path $repo "internal\tray\hooshix-green.ico") `
      --yellow (Join-Path $repo "internal\tray\hooshix-yellow.ico") `
      --red (Join-Path $repo "internal\tray\hooshix-red.ico")
    if ($LASTEXITCODE -ne 0) { throw "icon tinting failed" }
  }
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

# Authenticode signing is intentionally NOT wired here. This script used to
# consult HOOSHIX_SIGN_CERT_PATH and silently return when it was unset, which
# made "signed release" look implemented while every published binary was
# unsigned. The accepted-risk record for the unsigned MVP lives in
# docs/runtime/packaging-and-operations.md ("Authenticode signing status");
# when a code-signing certificate exists, add the signing step there and to
# .github/workflows/release.yml together with the secrets it needs, so the
# release path fails loudly instead of silently skipping.
    & $rsrc -arch amd64 -ico $ico -o $trayResource
    if ($LASTEXITCODE -ne 0) { throw "tray rsrc failed" }
    go build -trimpath -ldflags "-s -w -H windowsgui -X github.com/hasanjodatshandi/HooshiXAgent/internal/agent.Version=$version" -o "$dist\hooshix-agent-tray.exe" ./cmd/hooshix-agent-tray
    if ($LASTEXITCODE -ne 0) { throw "tray build failed" }

    # Copy payloads for embed.
    Copy-Item "$dist\hooshix-agent.exe" "$payload\hooshix-agent.exe" -Force
    Copy-Item "$dist\hooshix-agent-tray.exe" "$payload\hooshix-agent-tray.exe" -Force

    # The embedded payload manifest. Setup verifies every embedded binary
    # against it before touching C:\Program Files. When the release pipeline's
    # SHA256SUMS is supplied (HOOSHIX_RELEASE_SHA256SUMS), the payload must
    # first match the released agent binaries exactly: that is what ties a
    # locally built Setup.exe to the attested release inputs.
    #
    # Only hooshix-agent.exe has a released counterpart: the tray ships
    # exclusively inside Setup.exe and is not a release package of its own, so
    # the released Windows archive's manifest carries an entry for the Agent
    # binary only. That entry is mandatory and fail-closed. Any further entry
    # the supplied manifest does carry is verified as well. The tray is not left
    # unverified by this: Setup still checks it against the embedded manifest
    # written below from the bytes this build actually produced.
    $releaseChecksums = $env:HOOSHIX_RELEASE_SHA256SUMS
    if ($releaseChecksums) {
        if (-not (Test-Path -LiteralPath $releaseChecksums -PathType Leaf)) {
            throw "HOOSHIX_RELEASE_SHA256SUMS not found: $releaseChecksums"
        }
        foreach ($name in @('hooshix-agent.exe', 'hooshix-agent-tray.exe')) {
            $expected = $null
            foreach ($line in (Get-Content -LiteralPath $releaseChecksums)) {
                $parts = $line.Trim() -split '\s+', 2
                if ($parts.Count -ne 2) { continue }
                $entry = $parts[1].Trim().TrimStart('*')
                if ($entry -ieq $name -or $entry -ieq "./$name") { $expected = $parts[0].Trim().ToLowerInvariant(); break }
            }
            if (-not $expected) {
                if ($name -eq 'hooshix-agent.exe') {
                    throw "release SHA256SUMS $releaseChecksums has no entry for $name; a Setup.exe whose Agent payload cannot be tied to the released binary must not be published"
                }
                Write-Host "no release SHA256SUMS entry for $name (not a released package of its own); it stays covered by the embedded payload manifest"
                continue
            }
            $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dist $name)).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "payload $name does not match the release SHA256SUMS ($expected vs $actual)"
            }
            Write-Host "payload $name matches the release SHA256SUMS"
        }
    }
    $manifestLines = @()
    foreach ($name in @('hooshix-agent.exe', 'hooshix-agent-tray.exe')) {
        $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path "$payload" $name)).Hash.ToLowerInvariant()
        $manifestLines += "$digest  $name"
    }
    Set-Content -LiteralPath (Join-Path $payload 'SHA256SUMS') -Value $manifestLines -Encoding ascii

    Write-Host "== building setup (embedded payload + UAC manifest) =="
    # The UAC manifest syso must sit in the package directory itself: the Go
    # linker only links *.syso files from the package dir, not payload/.
    $manifest = Join-Path $repo "cmd\hooshix-setup\app.manifest"
    & $rsrc -manifest $manifest -o $setupResource
    if ($LASTEXITCODE -ne 0) { throw "rsrc failed" }

    # hooshix_release_payload selects the real //go:embed payload (see
    # cmd\hooshix-setup\payload_embed.go). Without the tag the package builds
    # against the non-release stub so a clean checkout still compiles; the
    # distribution must always be built with the tag or Setup.exe would ship
    # without its Agent/tray payload.
    go build -tags hooshix_release_payload -trimpath -ldflags "-s -w -X main.setupVersion=$version" -o "$dist\HooshiXAgent-Setup.exe" ./cmd/hooshix-setup
    if ($LASTEXITCODE -ne 0) { throw "setup build failed" }

    # The embedded payload must actually be inside the built Setup.exe. Size is
    # the cheap, toolchain-independent proxy: the two product binaries alone are
    # far larger than the setup binary's own code.
    $setupInfo = Get-Item "$dist\HooshiXAgent-Setup.exe"
    $payloadBytes = (Get-Item "$dist\hooshix-agent.exe").Length + (Get-Item "$dist\hooshix-agent-tray.exe").Length
    if ($setupInfo.Length -le $payloadBytes) {
        throw "Setup.exe ($($setupInfo.Length) bytes) does not embed the payload ($payloadBytes bytes): was it built with -tags hooshix_release_payload?"
    }
}
finally {
    Remove-Item $trayResource, $setupResource, $ico -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "done: $dist\HooshiXAgent-Setup.exe"
