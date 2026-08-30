#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required for R-11 comprehensive test expansion checks" >&2
  exit 1
fi
case "$(go version)" in
  "go version go1.27."*|"go version go1.27 "*) ;;
  *) echo "Go 1.27.x is required for R-11; got: $(go version)" >&2; exit 1 ;;
esac

coverage_dir="${HOOSHIX_R11_COVERAGE_DIR:-}"
cleanup_coverage=false
if [[ -z "$coverage_dir" ]]; then
  coverage_dir="$(mktemp -d)"
  cleanup_coverage=true
fi
mkdir -p "$coverage_dir"
if [[ "$cleanup_coverage" == true ]]; then
  trap 'rm -rf "$coverage_dir"' EXIT
fi

scenario_re='Test(RunnerReconnectStormRemainsBounded|AgentQueueBackpressureAllowsBoundedStreaming|RequestStreamWriterSlowConsumerBackpressureIsBounded|GatewayStreamsRequestBeforeUploadCompletesAndAccountsTunnelBytes|GatewayStreamingUploadCancellationReleasesResources|GatewayConcurrentBurstWithinConfiguredBounds|StatusExporterBackpressureDoesNotBlockCriticalCaller)$'

echo "R-11 deterministic slow-path/reconnect/load scenarios"
go test -count=3 ./internal/agent ./internal/gateway -run "$scenario_re"

echo "R-11 selected race scenarios"
go test -race -count=1 ./internal/agent ./internal/gateway -run "$scenario_re"

run_fuzz() {
  local package="$1"
  local target="$2"
  echo "R-11 fuzz smoke: $package $target"
  go test -run '^$' -fuzz "^${target}$" -fuzztime=1s "$package"
}

run_fuzz ./internal/agent FuzzValidateLocalTarget
run_fuzz ./internal/contractv1 FuzzDecodeFrameStrictness
run_fuzz ./internal/contractv1 FuzzValidateControlPayloadStrictness
run_fuzz ./internal/contractv1 FuzzExternalMetadataRecordParsing
run_fuzz ./internal/contractv1 FuzzContractHostnameValidation
run_fuzz ./internal/gateway FuzzCanonicalHostname
run_fuzz ./internal/gateway FuzzSnapshotMetadataRecordParsing
run_fuzz ./internal/gateway FuzzTunneledHTTPResponseParsing

echo "R-11 informational coverage report"
go test -count=1 -coverprofile="$coverage_dir/coverage.out" ./internal/...
go tool cover -func="$coverage_dir/coverage.out" >"$coverage_dir/coverage.txt"
test -s "$coverage_dir/coverage.out"
test -s "$coverage_dir/coverage.txt"
tail -n 1 "$coverage_dir/coverage.txt"
cat >"$coverage_dir/README.txt" <<'EOF'
R-11 coverage is review evidence only. No repository pass/fail decision is based on a coverage percentage.
R-12 owns reproducible performance/capacity thresholds; R-14 owns final audit review.
EOF

echo "R-11 comprehensive test expansion gate: PASSED — security-sensitive fuzz targets, deterministic reconnect/slow-path/load scenarios, selected race checks and informational coverage reporting completed."
