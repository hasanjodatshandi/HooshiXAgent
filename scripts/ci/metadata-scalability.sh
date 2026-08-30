#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required R-7 tool missing: $tool" >&2; exit 1; }
done

go test -count=1 ./internal/contractv1 ./internal/gateway \
  -run 'Test(SnapshotDirectoryRejectsDuplicateAuthorizationIDs|SnapshotDirectoryRejectsCanonicalDuplicateHostRoutes|SnapshotMetadataRejectsMalformedAndDuplicateJSONMembers|SnapshotMetadataParsesStaticRecordsButEvaluatesTimeAtUse|SnapshotMetadataRevocationIndexEvaluatesEffectiveTimeAtUse|SnapshotMetadataRevocationIndexCollapsesEventsPerSubject|GatewayReadinessFailsClosedForUnusableSnapshot|OperationalReadinessAndMetrics)$'

go test ./internal/gateway -run '^$' \
  -bench '^BenchmarkSnapshotMetadataLargeLookup$' \
  -benchtime=200x -benchmem

echo "R-7 metadata scalability/determinism gate: PASSED — strict typed snapshot load, duplicate fail-closed behavior, indexed revocations, use-time validity and readiness semantics passed; large-index benchmark completed."