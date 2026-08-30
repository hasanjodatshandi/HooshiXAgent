#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

command -v go >/dev/null 2>&1 || { echo "required R-8 tool missing: go" >&2; exit 1; }

go test -count=1 ./internal/gateway ./internal/agent \
  -run 'Test(StatusExporterBackpressureDoesNotBlockCriticalCaller|StatusExporterAccountsFailures|GatewayWriterPrioritizesControlAndPreservesSingleWriter|AgentWriterPrioritizesControlAndPreservesSingleWriter|OperationalReadinessAndMetrics)$'

go test -race -count=10 ./internal/gateway ./internal/agent \
  -run 'Test(StatusExporterBackpressureDoesNotBlockCriticalCaller|GatewayWriterPrioritizesControlAndPreservesSingleWriter|AgentWriterPrioritizesControlAndPreservesSingleWriter)$'

echo "R-8 observability/writer-isolation gate: PASSED — blocked exporter load remained non-blocking with bounded drop/failure accounting; control frames preempt queued data at frame boundaries while one WebSocket writer preserves exact sequence order."