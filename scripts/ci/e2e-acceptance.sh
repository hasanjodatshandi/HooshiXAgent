#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v go >/dev/null 2>&1; then
  echo "required E2E tool not found: go" >&2
  exit 1
fi

source "$repo_root/scripts/ci/test-guard.sh"

runtime_dir="$(mktemp -d)"
trap 'rm -rf "$runtime_dir"' EXIT

gateway_binary="$runtime_dir/hooshix-gateway${bin_suffix}"
agent_binary="$runtime_dir/hooshix-agent${bin_suffix}"

go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  fail_if_no_tests ./tests/integration -run 'TestAgentGatewayEndToEndAcceptance|TestAgentGatewayLargeRequestStreaming|TestAgentGatewayAuthorizationExpiryFailClosed|TestAgentGatewayEndToEndSecurityNegatives'

echo "Agent↔Gateway E2E Acceptance: PASSED — real Agent/Gateway binaries, validated external contract metadata, stable test hostname, public tunnel path, restart/reconnect recovery, large-body streaming, authorization-expiry fail-closed behavior, offline/error behavior and security negatives were exercised."
