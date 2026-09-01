#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

command -v go >/dev/null 2>&1 || { echo "required RA-5 tool missing: go" >&2; exit 1; }

# Focused RA-5 acceptance is deliberately repeated under the race detector: transaction
# rollback/recovery and lock ownership are concurrency-sensitive state guarantees.
go test -race -count=10 ./internal/agent -run '^TestRA5'
go test -race -count=5 ./internal/agent -run '^TestConcurrentConfigMutationPreservesEveryEndpoint$'

# Linux CI cannot execute DPAPI/macOS binaries, but compile the exact Agent package for
# both platforms here. The normal agent-platform matrix executes the full test suite natively.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
GOOS=windows GOARCH=amd64 go test -c -o "$work/agent-windows.test" ./internal/agent
GOOS=darwin GOARCH=amd64 go test -c -o "$work/agent-darwin.test" ./internal/agent

echo "RA-5 Agent state transaction hardening gate: PASSED - config/secret rollback and crash recovery, read-only diagnostics, terminal permanent failures, credential redaction, stale-lock ownership and concurrent mutation checks passed."
