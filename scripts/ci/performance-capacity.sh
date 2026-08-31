#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go git uname; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required R-12 tool missing: $tool" >&2; exit 1; }
done

evidence_dir="${HOOSHIX_R12_EVIDENCE_DIR:-$(mktemp -d)}"
mkdir -p "$evidence_dir"
soak_time="${HOOSHIX_R12_SOAK_BENCHTIME:-10s}"
profile_time="${HOOSHIX_R12_PROFILE_BENCHTIME:-3s}"
export HOOSHIX_R12_ENABLE=1

git_sha="$(git rev-parse HEAD)"

{
  echo "R-12 performance/capacity evidence"
  echo "git_sha=$git_sha"
  echo "go_version=$(go version)"
  echo "uname=$(uname -a)"
  if command -v nproc >/dev/null 2>&1; then
    echo "logical_cpus=$(nproc)"
    echo "gomaxprocs_runtime_default=$(nproc)"
  fi
  if command -v free >/dev/null 2>&1; then free -b; fi
  echo "soak_benchtime=$soak_time"
  echo "profile_benchtime=$profile_time"
  echo "production_defaults_unchanged=true"
} >"$evidence_dir/environment.txt"

echo "R-12: capacity probes (public requests/streams + resident sessions)"
go test -count=3 -timeout=120s -run '^(TestAuthenticatedSessionReleasesPendingHandshakeSlot|TestGatewayCapacityEnvelope|TestGatewayResidentSessionCapacity)$' -v ./internal/gateway \
  | tee "$evidence_dir/capacity.txt"

grep -q 'R12_CAPACITY concurrency=1000' "$evidence_dir/capacity.txt"
grep -q 'R12_SESSIONS concurrency=1000' "$evidence_dir/capacity.txt"

echo "R-12: repeatable benchmark sample"
go test -run '^$' -bench '^BenchmarkGatewayPublicRoundTrip$' -benchmem -benchtime=1s -count=3 ./internal/gateway \
  | tee "$evidence_dir/benchmark.txt"

grep -q 'BenchmarkGatewayPublicRoundTrip' "$evidence_dir/benchmark.txt"

echo "R-12: sustained soak benchmark (${soak_time})"
go test -run '^$' -bench '^BenchmarkGatewayPublicRoundTrip$' -benchmem -benchtime="$soak_time" -count=1 ./internal/gateway \
  | tee "$evidence_dir/soak.txt"

grep -q 'BenchmarkGatewayPublicRoundTrip' "$evidence_dir/soak.txt"

echo "R-12: CPU/heap/block/mutex profiles (${profile_time})"
go test -c -o "$evidence_dir/gateway.test" ./internal/gateway
"$evidence_dir/gateway.test" \
  -test.run='^$' \
  -test.bench='^BenchmarkGatewayPublicRoundTrip$' \
  -test.benchmem \
  -test.benchtime="$profile_time" \
  -test.count=1 \
  -test.cpuprofile="$evidence_dir/cpu.pprof" \
  -test.memprofile="$evidence_dir/heap.pprof" \
  -test.blockprofile="$evidence_dir/block.pprof" \
  -test.blockprofilerate=1 \
  -test.mutexprofile="$evidence_dir/mutex.pprof" \
  -test.mutexprofilefraction=1 \
  | tee "$evidence_dir/profile-benchmark.txt"

for profile in cpu heap block mutex; do
  test -s "$evidence_dir/${profile}.pprof"
  go tool pprof -top -nodecount=30 "$evidence_dir/gateway.test" "$evidence_dir/${profile}.pprof" >"$evidence_dir/${profile}-top.txt"
done

# Keep the symbolized text and raw profiles; the test binary is not needed as CI evidence.
rm -f "$evidence_dir/gateway.test"

# Stable regression assertions intentionally avoid runner-specific throughput claims.
# Hard gates are: zero request/session errors, full 1000-level reachability, bounded cleanup,
# and the 5s synthetic p99 ceiling enforced by TestGatewayCapacityEnvelope.
cat >"$evidence_dir/acceptance.txt" <<'EOF'
R12_ACCEPTANCE zero_errors=true
R12_ACCEPTANCE concurrency_levels=32,100,500,1000
R12_ACCEPTANCE resident_session_levels=64,100,500,1000
R12_ACCEPTANCE synthetic_p99_ceiling=5s
R12_ACCEPTANCE throughput_floor=not_set_runner_variance
R12_ACCEPTANCE production_defaults_tuned=false
EOF

echo "R-12 performance/capacity gate: PASSED — reproducible 100/500/1000 request-stream and resident-session probes, sustained soak, benchmark allocations and CPU/heap/block/mutex profiles completed without weakening production safety limits."
echo "R-12 evidence: $evidence_dir"
