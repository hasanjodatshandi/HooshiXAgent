#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

set +e
HOOSHIX_AUDIT_REGRESSION_PROOF=1 \
  go test -count=1 -run '^TestAuditRegression' ./internal/contractv1 >"$output" 2>&1
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
  'AUDIT-R0 duplicate JSON object keys accepted'
do
  if ! grep -q -- "$marker" "$output"; then
    cat "$output" >&2
    echo "R-0 regression proof missing expected diagnostic: $marker" >&2
    exit 1
  fi
done

echo "R-0 audit regression proof: PASSED — the three still-unresolved protocol findings were reproduced deterministically; authorization expiry is now covered by the normal R-1 lifecycle tests."
