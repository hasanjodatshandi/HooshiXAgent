#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/ci/test-guard.sh"

fail_if_no_tests ./internal/agent -run '^TestAgentQueueBackpressureAllowsBoundedStreaming$'
fail_if_no_tests ./internal/gateway -run '^Test(RequestStreamWriterBoundsChunkRetentionAndAccounting|GatewayStreamsRequestBeforeUploadCompletesAndAccountsTunnelBytes|GatewayStreamingUploadCancellationReleasesResources)$'
go test -count=1 ./internal/gateway -run '^$' -bench '^BenchmarkRequestStreamWriterBoundedRetention$' -benchtime=1x -benchmem

echo "R-4 streaming ingress gate: PASSED — backend progress before upload completion, cancellation cleanup, exact tunneled-byte accounting and bounded per-write retention benchmark passed."
