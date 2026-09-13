#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# fail_if_no_tests RUN_ARGS... fails the gate when a focused -run selector
# matches zero tests (Go would otherwise exit 0 on an empty match set).
fail_if_no_tests() {
  local output
  output="$(go test -count=1 -v "$@" 2>&1 | tee /dev/stderr)"
  if ! grep -q -- '=== RUN ' <<<"$output"; then
    echo "focused gate matched zero tests: $*" >&2
    exit 1
  fi
}

fail_if_no_tests ./internal/contractv1 -run 'Test(FrameRejectsMalformedAndOversizedInput|SequenceTrackerRejectsReplayAndReordering|SequenceTrackerRequiresFirstSequenceOneAndRejectsWrap|ProtocolSequenceGapRejected|ProtocolInvalidUTF8Rejected|ProtocolDuplicateJSONKeysRejected|StrictJSONRejectsNestedAndEscapedDuplicateKeys|ControlPayloadScopeAndStrictness)$'
fail_if_no_tests ./internal/agent -run '^TestAgentSequenceExhaustionTerminatesSession$'
fail_if_no_tests ./internal/gateway -run 'Test(GatewayRejectsAuthenticatedProtocolStrictnessViolations|GatewaySequenceExhaustionTerminatesSession)$'
GOMAXPROCS=2 go test -run='^$' -fuzz='^FuzzDecodeFrameStrictness$' -fuzztime=1s ./internal/contractv1
GOMAXPROCS=2 go test -run='^$' -fuzz='^FuzzValidateControlPayloadStrictness$' -fuzztime=1s ./internal/contractv1

echo "R-2 protocol strictness gate: PASSED — exact sequencing, wrap termination, strict UTF-8/duplicate-key parsing, authenticated negatives and fuzz smoke passed."
