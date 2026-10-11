#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

fail_if_no_tests() {
  local output
  output="$(go test -count=1 -v "$@" 2>&1 | tee /dev/stderr)"
  if ! grep -q -- '=== RUN ' <<<"$output"; then
    echo "focused gate matched zero tests: $*" >&2
    exit 1
  fi
}

fail_if_no_tests ./internal/agent -run '^(TestAgentQueue|TestStreamInputBudgetMatchesTheAdmissionEnvelope|TestStreamQueueSlotsNeverBindBeforeTheByteBudget|TestStreamQueuesBufferTheirWholeByteBudgetWithoutAConsumer)'
fail_if_no_tests ./internal/gateway -run 'Test(DefaultResourceEnvelopeFitsDeploymentMemoryLimit|StreamQueueSlotArraysStayWithinTheDeploymentEnvelope|ByteBudgetAndIngressBufferFailClosedAndRelease|StreamQueueBudgetsBoundPerStreamSessionAndGlobal|StreamQueueFrameLimitReleasesRejectedReservation|StreamQueueSlotsFollowTheByteBudget|StreamQueueBuffersItsWholeByteBudgetWithoutAReader|GatewayRateAndConcurrencyLimitsFailClosed|GatewayResourceMetricsAreAggregateAndLowCardinality|ResourcePrimitivesStressDoNotGrowGoroutines)$'
go test -race -count=1 ./internal/agent ./internal/gateway -run 'Test(AgentQueue|StreamQueue|StreamInputBudget|GatewayRateAndConcurrencyLimitsFailClosed|ResourcePrimitivesStressDoNotGrowGoroutines)'

echo "R-3 resource/DoS gate: PASSED — byte budgets, global ingress/queue limits, rate/concurrency controls, aggregate saturation metrics and race-safe cleanup passed."
