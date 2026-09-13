#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/ci/test-guard.sh"

fail_if_no_tests ./internal/agent -run '^TestAgentPeerTerminalOwnsStreamAndSuppressesLocalTerminal$'
fail_if_no_tests ./internal/gateway -run '^Test(GatewayStreamQueueExhaustionIsIsolatedAcrossConcurrentStreams|HopByHopHeadersAreRemovedAcrossTunnel|TunneledResponseHeaderLimitFailsClosed|KnownLengthOversizedResponseFailsBeforeSuccessStatus|OversizedChunkedResponseAbortsInsteadOfCleanTruncation|ResponseHeaderLimitReaderRejectsBeforeUnboundedParsing)$'
go test -race -count=1 ./internal/agent ./internal/gateway -run '^Test(AgentPeerTerminalOwnsStreamAndSuppressesLocalTerminal|GatewayStreamQueueExhaustionIsIsolatedAcrossConcurrentStreams|OversizedChunkedResponseAbortsInsteadOfCleanTruncation)$'

echo "R-5 HTTP/stream isolation gate: PASSED — stream overload isolation, hop-by-hop filtering, response-header bounds, oversized response semantics and terminal ordering passed."