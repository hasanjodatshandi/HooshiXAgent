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

unexpected=()
for file in "${runnable_files[@]}"; do
  case "$file" in
    ./cmd/gateway/*.go|./cmd/agent/*.go) ;;
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

gateway_binary="$runtime_dir/hooshix-gateway"
agent_binary="$runtime_dir/hooshix-agent"
go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
  go test -count=1 -run 'TestExternalProcessRuntimeGate|TestExecutableRefusesPlaintextStartup' ./internal/gateway

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  go test -count=1 -run TestRealAgentGatewayRuntime ./internal/runtimegate

echo "Executable Runtime Gate: PASSED — real Gateway and Edge Agent processes exercised over TLS/WSS with authenticated tunnel ingress, Agent state persistence/reconnect, and plaintext-startup rejection."
