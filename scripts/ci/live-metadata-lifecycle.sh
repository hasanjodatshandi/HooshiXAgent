#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v go >/dev/null 2>&1; then
  echo "required live-metadata tool not found: go" >&2
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
  fail_if_no_tests ./tests/integration -run 'TestAgentGatewayLiveMetadataRouteStaleRecovery|TestAgentGatewayLiveMetadataRevocationTerminatesSession'

echo "RA-3 live metadata lifecycle gate: PASSED - real Gateway/Agent binaries applied atomic route generations, failed closed on stale authority, recovered on a newer generation, and terminated an existing session after live revocation without Gateway restart."
