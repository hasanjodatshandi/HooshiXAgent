#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in python3 docker go git sha256sum tar zip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required R-6 tool missing: $tool" >&2; exit 1; }
done

# All third-party workflow actions must be immutable 40-hex pins with a reviewed version comment.
if grep -R -n -E 'uses:[[:space:]]+[^./][^@[:space:]]+@(v[0-9]+|main|master|[0-9]+\.[0-9]+)' .github/workflows; then
  echo "mutable GitHub Action reference found" >&2
  exit 1
fi
python3 - <<'PY'
from pathlib import Path
import re, sys
bad=[]
for path in sorted(Path('.github/workflows').glob('*.y*ml')):
    for n,line in enumerate(path.read_text().splitlines(),1):
        m=re.search(r'uses:\s*([^\s]+)@([^\s#]+)(?:\s+#\s*(v[^\s]+))?', line)
        if not m or m.group(1).startswith('./'):
            continue
        if not re.fullmatch(r'[0-9a-f]{40}', m.group(2)) or not m.group(3):
            bad.append(f'{path}:{n}:{line.strip()}')
if bad:
    print('non-immutable or undocumented action pins:', *bad, sep='\n', file=sys.stderr)
    raise SystemExit(1)
PY

# Every module the build links must be disclosed in THIRD_PARTY_NOTICES. go.mod
# is the authority, so this check is derived from `go list -m all` rather than
# from a hand-maintained list that would silently fall behind.
python3 - <<'PY'
from pathlib import Path
import subprocess, sys

notices = Path('THIRD_PARTY_NOTICES').read_text(encoding='utf-8')
listing = subprocess.run(['go', 'list', '-m', 'all'], check=True, capture_output=True, text=True).stdout
modules = [line.split()[0] for line in listing.splitlines() if line.strip()]
if len(modules) < 2:
    raise SystemExit('go list -m all reported no dependencies to check')
required = modules[1:]  # modules[0] is this module itself
missing = [module for module in required if module not in notices]
if missing:
    print('THIRD_PARTY_NOTICES is missing module dependencies:', *missing, sep='\n', file=sys.stderr)
    raise SystemExit(1)
print(f'THIRD_PARTY_NOTICES covers {len(required)} Go module dependencies')
PY

# External runtime/build image references must retain tag readability plus immutable digest identity.
grep -Eq '^FROM golang:1\.27\.0-alpine3\.24@sha256:[0-9a-f]{64} AS build$' deploy/gateway/Dockerfile
grep -Eq '^FROM alpine:3\.24\.1@sha256:[0-9a-f]{64}$' deploy/gateway/Dockerfile
grep -Eq '^[[:space:]]*image: caddy:2\.11\.4-alpine@sha256:[0-9a-f]{64}$' deploy/gateway/docker-compose.yml
grep -Eq "^SYFT_IMAGE='anchore/syft:v[0-9.]+@sha256:[0-9a-f]{64}'$" scripts/release/supply-chain-artifacts.sh
grep -Eq "^TRIVY_IMAGE='aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64}'$" scripts/release/supply-chain-artifacts.sh

# Release policy must accept verified exact-main evidence and reject unverified commits.
work="$(mktemp -d)"
cleanup(){ rm -rf "$work"; }
trap cleanup EXIT
verified_sha='1111111111111111111111111111111111111111'
unverified_sha='2222222222222222222222222222222222222222'
cat >"$work/verified.json" <<JSON
{"workflow_runs":[{"id":77,"head_sha":"$verified_sha","head_branch":"main","event":"push","status":"completed","conclusion":"success","created_at":"2026-08-30T00:00:00Z"}],"jobs":{"77":{"jobs":[{"name":"AG-8 final security / resilience / release gate","conclusion":"success"}]}}}
JSON
python3 scripts/release/verify-release-commit.py --sha "$verified_sha" --repo hasanjodatshandi/HooshiXAgent --fixture "$work/verified.json" >/dev/null
if python3 scripts/release/verify-release-commit.py --sha "$unverified_sha" --repo hasanjodatshandi/HooshiXAgent --fixture "$work/verified.json" >/dev/null 2>&1; then
  echo "unverified release commit unexpectedly passed policy" >&2
  exit 1
fi
cat >"$work/failed-final-gate.json" <<JSON
{"workflow_runs":[{"id":78,"head_sha":"$verified_sha","head_branch":"main","event":"push","status":"completed","conclusion":"success","created_at":"2026-08-30T00:00:01Z"}],"jobs":{"78":{"jobs":[{"name":"AG-8 final security / resilience / release gate","conclusion":"failure"}]}}}
JSON
if python3 scripts/release/verify-release-commit.py --sha "$verified_sha" --repo hasanjodatshandi/HooshiXAgent --fixture "$work/failed-final-gate.json" >/dev/null 2>&1; then
  echo "commit with failed final release gate unexpectedly passed policy" >&2
  exit 1
fi

# Workflow privilege split is structural: build is read-only; publish alone owns write/OIDC/attestation permissions.
python3 - <<'PY'
from pathlib import Path
text=Path('.github/workflows/release.yml').read_text()
required=[
    'permissions:\n  contents: read',
    'policy:',
    'build:',
    'attest:',
    'publish:',
    'actions: read',
    'contents: write',
    'id-token: write',
    'attestations: write',
    'artifact-metadata: write',
    'verify-release-commit.py',
    'supply-chain-artifacts.sh',
    'workflow_dispatch:',
    'release_version:',
    "if: github.event_name == 'push'",
    'attestations: read',
]
for item in required:
    if item not in text:
        raise SystemExit(f'release workflow missing required hardening fragment: {item}')
build=text.split('\n  build:',1)[1].split('\n  attest:',1)[0]
attest=text.split('\n  attest:',1)[1].split('\n  publish:',1)[0]
publish=text.split('\n  publish:',1)[1]
if any(token in build for token in ['contents: write','id-token: write','attestations: write','artifact-metadata: write']):
    raise SystemExit('build job contains elevated release privileges')
if 'contents: write' in attest:
    raise SystemExit('attestation job contains publication privilege')
for token in ['id-token: write','attestations: write','artifact-metadata: write']:
    if token not in attest:
        raise SystemExit(f'attestation job missing required privilege: {token}')
if 'contents: write' not in publish or "if: github.event_name == 'push'" not in publish:
    raise SystemExit('publish job is not tag-push-only with contents write')
if any(token in publish for token in ['id-token: write','attestations: write','artifact-metadata: write']):
    raise SystemExit('publish job contains attestation minting privileges')
PY

# The supported Windows distribution is HooshiXAgent-Setup.exe (ADR-0014), and it
# must be published exactly like every other artifact: built from the verified
# commit by a Windows job, tied to the released Agent binary, included in the
# release checksum manifest (which is what puts it inside the SBOM scan and the
# Artifact Attestations), and required by attest/publish so an installer that
# cannot be built blocks publication instead of silently shipping without it.
python3 - <<'PY'
from pathlib import Path
import sys

workflow = Path('.github/workflows/release.yml').read_text()
required = [
    'windows-setup:',
    'runs-on: windows-latest',
    'scripts/build-setup.ps1',
    'HOOSHIX_RELEASE_SHA256SUMS',
    'HOOSHIX_VERSION',
    'dist/HooshiXAgent-Setup.exe',
    'release-setup-${{ needs.policy.outputs.release_sha }}',
]
for item in required:
    if item not in workflow:
        raise SystemExit(f'release workflow does not build, upload or verify the supported Windows installer: {item}')

setup_job = workflow.split('\n  windows-setup:', 1)[1].split('\n  finalize:', 1)[0]
if '-File scripts/build-setup.ps1' not in setup_job:
    raise SystemExit('the Windows installer job does not invoke scripts/build-setup.ps1')

finalize_job = workflow.split('\n  finalize:', 1)[1].split('\n  attest:', 1)[0]
if 'supply-chain-artifacts.sh' not in finalize_job:
    raise SystemExit('the finalize job does not run the SBOM/vulnerability scan over the complete candidate')

for job, body in (
    ('attest', workflow.split('\n  attest:', 1)[1].split('\n  publish:', 1)[0]),
    ('publish', workflow.split('\n  publish:', 1)[1]),
):
    needs_block = body.split('steps:', 1)[0]
    if 'windows-setup' not in needs_block:
        raise SystemExit(f'the {job} job does not depend on the Windows installer job, so an unbuildable installer would not block publication')

scan = Path('scripts/release/supply-chain-artifacts.sh').read_text()
if "-name '*.exe'" not in scan:
    raise SystemExit('the SBOM/vulnerability scan does not cover the .exe release artifact')
print('release workflow publishes the supported Windows installer under the same checksum/SBOM/attestation rules as the archives')
PY

release_dir="$work/release"
bash scripts/release/build-release.sh v0.0.0-r6 "$release_dir"
docker build --pull=false -t hooshix-gateway:r6-scan -f deploy/gateway/Dockerfile . >/dev/null
docker save hooshix-gateway:r6-scan -o "$work/gateway-image.tar"
bash scripts/release/supply-chain-artifacts.sh "$release_dir" "$work/gateway-image.tar" v0.0.0-r6
find "$release_dir" -maxdepth 1 -type f -name '*.spdx.json' | grep -q .

echo "R-6 release/supply-chain gate: PASSED — exact-commit release policy, privilege split, immutable Actions/images, Syft SBOMs and Trivy final artifact/image vulnerability scans passed."