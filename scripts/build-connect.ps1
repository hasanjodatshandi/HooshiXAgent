# Build HooshiX Connect: the Windows GUI that turns a Panel-issued connect
# bundle into a loopback Connector session. The Panel serves the result from
# /download/hooshix-connect.exe, so the printed SHA-256 is the operator's proof
# that the file on the server is the file this build produced.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\build-connect.ps1
# Output: dist\hooshix-connect.exe

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo "dist"
$exe = Join-Path $dist "hooshix-connect.exe"
$manifest = Join-Path $repo "cmd\hooshix-connect\app.manifest"
$resource = Join-Path $repo "cmd\hooshix-connect\rsrc_windows_amd64.syso"
$ico = Join-Path $repo "cmd\hooshix-connect\hooshix.ico"
$logo = Join-Path $repo "assets\logo.png"

New-Item -ItemType Directory -Force $dist | Out-Null
if (-not (Test-Path $logo)) { throw "brand logo missing: $logo" }
if (-not (Test-Path $manifest)) { throw "application manifest missing: $manifest" }

# Pure Go, no C toolchain, pinned to the same flags the other Windows binaries
# use so the distribution is reproducible across machines.
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

# rsrc.exe (icon + manifest resource compiler) resolved from PATH or GOPATH so
# the build works on any machine, not one specific user profile.
function Find-Rsrc {
    $fromPath = Get-Command rsrc.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $goPath = (go env GOPATH).Trim()
    if ($goPath) {
        $candidate = Join-Path (($goPath -split ';')[0]) "bin\rsrc.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    throw "rsrc.exe not found. Install it with: go install github.com/akavel/rsrc@v0.10.2"
}

# Read the PE subsystem (2 = Windows GUI, 3 = console). A console build would pop
# a black window behind the form, which is exactly what -H windowsgui prevents.
function Get-PESubsystem([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $pe = [System.BitConverter]::ToInt32($bytes, 0x3C) # e_lfanew
    if ($pe -lt 0 -or $pe + 92 -ge $bytes.Length) { throw "not a PE image: $Path" }
    if ([System.BitConverter]::ToInt32($bytes, $pe) -ne 0x00004550) { throw "missing PE signature: $Path" }
    # "PE\0\0" (4) + COFF header (20) puts the optional header at pe+24; Subsystem
    # is at +68 of a PE32+ optional header, which every Go amd64 binary uses.
    return [System.BitConverter]::ToUInt16($bytes, $pe + 24 + 68)
}

# Report whether the image carries an .rsrc section, i.e. whether the icon and
# manifest resources actually got linked in.
function Test-PEHasResourceSection([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $pe = [System.BitConverter]::ToInt32($bytes, 0x3C)
    $sections = [System.BitConverter]::ToUInt16($bytes, $pe + 4 + 2)
    $optionalSize = [System.BitConverter]::ToUInt16($bytes, $pe + 4 + 16)
    $table = $pe + 4 + 20 + $optionalSize
    for ($index = 0; $index -lt $sections; $index++) {
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $table + 40 * $index, 8).TrimEnd([char]0)
        if ($name -eq ".rsrc") { return $true }
    }
    return $false
}

try {
    $makeIco = Join-Path $repo "scripts\make-ico.ps1"
    if (-not (Test-Path $makeIco)) { throw "icon generator missing: $makeIco" }
    powershell -NoProfile -ExecutionPolicy Bypass -File $makeIco -Source $logo -Destination $ico
    if ($LASTEXITCODE -ne 0) { throw "icon generation failed" }

    $rsrc = Find-Rsrc
    & $rsrc -arch amd64 -ico $ico -manifest $manifest -o $resource
    if ($LASTEXITCODE -ne 0) { throw "rsrc failed" }

    Write-Host "== building hooshix-connect =="
    go build -trimpath -ldflags "-s -w -H windowsgui" -o $exe ./cmd/hooshix-connect
    if ($LASTEXITCODE -ne 0) { throw "connect build failed" }

    # The .syso is deleted below, so a rebuild that silently lost it would still
    # "succeed" and ship an unbranded, unthemed, DPI-unaware window.
    if (-not (Test-PEHasResourceSection $exe)) {
        throw "hooshix-connect.exe has no .rsrc section: the icon/manifest resource was not linked"
    }
    $subsystem = Get-PESubsystem $exe
    if ($subsystem -ne 2) {
        throw "hooshix-connect.exe subsystem is $subsystem, want 2 (Windows GUI): build with -H windowsgui"
    }
}
finally {
    Remove-Item $resource, $ico -Force -ErrorAction SilentlyContinue
}

$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
Write-Host ""
Write-Host "done: $exe ($((Get-Item $exe).Length) bytes)"
Write-Host "sha256: $digest"
