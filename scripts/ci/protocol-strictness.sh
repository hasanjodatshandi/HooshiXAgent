#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go test -count=1 ./internal/contractv1 -run 'Test(FrameRejectsMalformedAndOversizedInput|SequenceTrackerRejectsReplayAndReordering|SequenceTrackerRequiresFirstSequenceOneAndRejectsWrap|ProtocolSequenceGapRejected|ProtocolInvalidUTF8Rejected|ProtocolDuplicateJSONKeysRejected|StrictJSONRejectsNestedAndEscapedDuplicateKeys|ControlPayloadScopeAndStrictness)$'
go test -count=1 ./internal/agent -run '^TestAgentSequenceExhaustionTerminatesSession$'
go test -count=1 ./internal/gateway -run 'Test(GatewayRejectsAuthenticatedProtocolStrictnessViolations|GatewaySequenceExhaustionTerminatesSession)$'
GOMAXPROCS=2 go test -run='^$' -fuzz='^FuzzDecodeFrameStrictness$' -fuzztime=1s ./internal/contractv1
GOMAXPROCS=2 go test -run='^$' -fuzz='^FuzzValidateControlPayloadStrictness$' -fuzztime=1s ./internal/contractv1

echo "R-2 protocol strictness gate: PASSED — exact sequencing, wrap termination, strict UTF-8/duplicate-key parsing, authenticated negatives and fuzz smoke passed."
