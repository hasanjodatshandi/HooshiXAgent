#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v go >/dev/null 2>&1; then
  echo "required live-metadata tool not found: go" >&2
  exit 1
fi

runtime_dir="$(mktemp -d)"
trap 'rm -rf "$runtime_dir"' EXIT

gateway_binary="$runtime_dir/hooshix-gateway"
agent_binary="$runtime_dir/hooshix-agent"

go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  go test -count=1 -run 'TestAgentGatewayLiveMetadataRouteStaleRecovery|TestAgentGatewayLiveMetadataRevocationTerminatesSession' ./internal/runtimegate

echo "RA-3 live metadata lifecycle gate: PASSED - real Gateway/Agent binaries applied atomic route generations, failed closed on stale authority, recovered on a newer generation, and terminated an existing session after live revocation without Gateway restart."
