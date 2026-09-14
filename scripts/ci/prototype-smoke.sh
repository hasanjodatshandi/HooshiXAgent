#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"

source "$ROOT/scripts/ci/test-guard.sh"

go build -o "$WORK/hooshix-agent${bin_suffix}" ./cmd/agent
go build -o "$WORK/hooshix-gateway${bin_suffix}" ./cmd/gateway

export HOOSHIX_AGENT_BINARY="$WORK/hooshix-agent${bin_suffix}"
export HOOSHIX_GATEWAY_BINARY="$WORK/hooshix-gateway${bin_suffix}"

fail_if_no_tests ./tests/integration -run '^TestFirstPrototypeSmoke$'