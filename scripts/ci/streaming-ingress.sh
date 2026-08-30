#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go test -count=1 ./internal/agent -run '^TestAgentQueueBackpressureAllowsBoundedStreaming$'
go test -count=1 ./internal/gateway -run '^Test(RequestStreamWriterBoundsChunkRetentionAndAccounting|GatewayStreamsRequestBeforeUploadCompletesAndAccountsTunnelBytes|GatewayStreamingUploadCancellationReleasesResources)$'
go test -count=1 ./internal/gateway -run '^$' -bench '^BenchmarkRequestStreamWriterBoundedRetention$' -benchtime=1x -benchmem

echo "R-4 streaming ingress gate: PASSED — backend progress before upload completion, cancellation cleanup, exact tunneled-byte accounting and bounded per-write retention benchmark passed."
