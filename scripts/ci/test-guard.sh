# Shared CI test-gate guard. Source this file in focused test gates:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/test-guard.sh"
#   fail_if_no_tests ./internal/gateway -run '^TestSomething$'
#
# fail_if_no_tests RUN_ARGS... runs `go test -count=1 -v` and fails when the
# selector matches zero tests. Go exits 0 for an empty match set, so a
# renamed test would otherwise turn a hardening gate into a no-op that
# silently passes.
fail_if_no_tests() {
  local output
  output="$(go test -count=1 -v "$@" 2>&1 | tee /dev/stderr)"
  if ! grep -q -- '=== RUN ' <<<"$output"; then
    echo "focused gate matched zero tests: $*" >&2
    exit 1
  fi
}
