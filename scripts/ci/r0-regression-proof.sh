#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/ci/test-guard.sh"

fail_if_no_tests ./internal/contractv1 -run '^(TestProtocolSequenceGapRejected|TestProtocolInvalidUTF8Rejected|TestProtocolDuplicateJSONKeysRejected|TestSequenceTrackerRequiresFirstSequenceOneAndRejectsWrap)$'
fail_if_no_tests ./internal/gateway -run '^TestActiveSessionTerminatesWhenAuthorizationExpires$'

echo "R-0 audit regression closure: PASSED — authorization expiry plus all three protocol strictness findings are fixed and covered by normal regression tests."
