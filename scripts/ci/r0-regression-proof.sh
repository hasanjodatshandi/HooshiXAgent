#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

set +e
HOOSHIX_AUDIT_REGRESSION_PROOF=1 \
  go test -count=1 -run '^TestAuditRegression' ./internal/contractv1 ./internal/gateway >"$output" 2>&1
status=$?
set -e

if [[ $status -eq 0 ]]; then
  cat "$output" >&2
  echo "R-0 regression proof unexpectedly passed; one or more audited defects may already be fixed and this proof baseline must be updated." >&2
  exit 1
fi

expected=(
  TestAuditRegressionSequenceGapMustBeRejected
  TestAuditRegressionInvalidUTF8MustBeRejected
  TestAuditRegressionDuplicateJSONKeysMustBeRejected
  TestAuditRegressionExpiredAuthorizationMustTerminateActiveSession
)
for test_name in "${expected[@]}"; do
  if ! grep -q -- "--- FAIL: ${test_name}" "$output"; then
    cat "$output" >&2
    echo "R-0 regression proof did not reproduce expected failure: ${test_name}" >&2
    exit 1
  fi
done

for marker in \
  'AUDIT-R0 sequence gap accepted' \
  'AUDIT-R0 invalid UTF-8 control payload accepted' \
  'AUDIT-R0 duplicate JSON object keys accepted' \
  'AUDIT-R0 active Agent session survived authorization expires_at'
do
  if ! grep -q -- "$marker" "$output"; then
    cat "$output" >&2
    echo "R-0 regression proof missing expected diagnostic: $marker" >&2
    exit 1
  fi
done

echo "R-0 audit regression proof: PASSED — all four confirmed pre-fix defects were reproduced deterministically."