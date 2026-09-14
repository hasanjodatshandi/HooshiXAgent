#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mapfile -t runnable_files < <(grep -RIl --include='*.go' --exclude-dir='.git' '^package main$' . 2>/dev/null | sort || true)
if ((${#runnable_files[@]} == 0)); then
  echo "Executable Runtime Gate: Not applicable — current repository state introduces no runnable product capability."
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "required runtime-gate tool not found: go" >&2
  exit 1
fi

source "$repo_root/scripts/ci/test-guard.sh"

unexpected=()
for file in "${runnable_files[@]}"; do
  case "$file" in
    ./cmd/gateway/*.go|./cmd/agent/*.go) ;;
    # Windows-only product executables: their runtime procedures run on
    # windows-latest runners (build setup distribution + service/tray
    # lifecycle), not in this Unix gate. They are allowlisted here so the
    # gate reflects the approved executable set without weakening the
    # Unix-side runtime assertions.
    ./cmd/hooshix-agent-tray/*.go|./cmd/hooshix-setup/*.go) ;;
    *) unexpected+=("$file") ;;
  esac
done
if ((${#unexpected[@]} != 0)); then
  echo "runnable capability lacks an approved executable runtime procedure:" >&2
  printf '  %s\n' "${unexpected[@]}" >&2
  exit 1
fi

runtime_dir="$(mktemp -d)"
trap 'rm -rf "$runtime_dir"' EXIT

gateway_binary="$runtime_dir/hooshix-gateway${bin_suffix}"
agent_binary="$runtime_dir/hooshix-agent${bin_suffix}"
go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
  fail_if_no_tests ./internal/gateway -run 'TestExternalProcessRuntimeGate|TestExecutableRefusesPlaintextStartup'

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  fail_if_no_tests ./tests/integration -run TestRealAgentGatewayRuntime

echo "Executable Runtime Gate: PASSED — real Gateway and Edge Agent processes exercised over TLS/WSS with authenticated tunnel ingress, Agent state persistence/reconnect, and plaintext-startup rejection."
