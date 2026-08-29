#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go test -count=1 -run '^(TestProtocolSequenceGapRejected|TestProtocolInvalidUTF8Rejected|TestProtocolDuplicateJSONKeysRejected|TestSequenceTrackerRequiresFirstSequenceOneAndRejectsWrap)$' ./internal/contractv1
go test -count=1 -run '^TestActiveSessionTerminatesWhenAuthorizationExpires$' ./internal/gateway

echo "R-0 audit regression closure: PASSED — authorization expiry plus all three protocol strictness findings are fixed and covered by normal regression tests."
