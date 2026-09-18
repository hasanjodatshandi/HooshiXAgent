# Shared CI test-gate guard. Source this file in focused test gates:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/test-guard.sh"
#   fail_if_no_tests ./internal/gateway -run '^TestSomething$'
#
# fail_if_no_tests RUN_ARGS... runs `go test -count=1 -v` and fails when the
# selector matches zero tests. Go exits 0 for an empty match set, so a
# renamed test would otherwise turn a hardening gate into a no-op that
# silently passes.
#
# bin_suffix: CI gates build product binaries into temp dirs (e.g.
# "$work/hooshix-agent"). Windows requires an explicit .exe suffix for
# os/exec to find them; Unix must not add one. Callers append "${bin_suffix}"
# to built binary names so every gate script runs on both developer Windows
# machines and Linux CI runners.
#
# The host platform decides the suffix, not `go env GOOS`: the gate builds the
# binary and immediately executes it locally, so the machine running the gate
# is the correct signal. `go env GOOS` describes the *build target* instead,
# and on a Windows developer machine using Git Bash it can report a different
# value; trusting it would drop the .exe suffix and make os/exec fail to launch
# a perfectly valid Windows binary, producing a misleading gate failure.
bin_suffix=""
case "$(uname -s 2>/dev/null || true)" in
  MINGW* | MSYS* | CYGWIN*) bin_suffix=".exe" ;;
esac

fail_if_no_tests() {
  local output status=0
  # Reuse stderr's open descriptor instead of reopening /dev/stderr, which
  # is not portable through Windows/WSL pipes. Preserve the test exit code.
  output="$(go test -count=1 -v "$@" 2>&1)" || status=$?
  printf '%s\n' "$output" >&2
  if ((status != 0)); then
    return "$status"
  fi
  if ! grep -q -- '--- PASS:' <<<"$output"; then
    echo "focused gate executed no passing tests (empty selection or all skipped): $*" >&2
    return 1
  fi
}
