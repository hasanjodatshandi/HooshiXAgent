#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

command -v go >/dev/null 2>&1 || { echo "required RA-6 tool missing: go" >&2; exit 1; }

# Filesystem trust and path traversal are concurrency-sensitive. Repeat the focused
# adversarial suite under the race detector, then preserve the existing Unix package smoke.
go test -race -count=10 ./internal/agent ./internal/gateway -run '^TestRA6'
bash scripts/ci/agent-install-smoke.sh

# Native Windows execution is a separate blocking CI matrix leg. Cross-compilation here
# prevents platform helper drift from reaching that runner unnoticed.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
GOOS=windows GOARCH=amd64 go test -c -o "$work/agent-windows.test" ./internal/agent
GOOS=windows GOARCH=amd64 go test -c -o "$work/gateway-windows.test" ./internal/gateway

echo "RA-6 filesystem and installer hardening gate: PASSED - no-follow regular-file metadata/state reads, parent path validation, Unix permission enforcement and Unix package safety passed; Windows helpers cross-compiled."
