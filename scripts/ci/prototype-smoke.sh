#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"

go build -o "$WORK/hooshix-agent" ./cmd/agent
go build -o "$WORK/hooshix-gateway" ./cmd/gateway

export HOOSHIX_AGENT_BINARY="$WORK/hooshix-agent"
export HOOSHIX_GATEWAY_BINARY="$WORK/hooshix-gateway"

go test -count=1 -run '^TestFirstPrototypeSmoke$' -v ./internal/runtimegate