#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go test -count=1 ./internal/agent -run '^TestAgentQueue'
go test -count=1 ./internal/gateway -run '^Test(DefaultResourceEnvelopeFitsDeploymentMemoryLimit|ByteBudgetAndIngressBufferFailClosedAndRelease|StreamQueueBudgetsBoundPerStreamSessionAndGlobal|StreamQueueFrameLimitReleasesRejectedReservation|GatewayRateAndConcurrencyLimitsFailClosed|GatewayResourceMetricsAreAggregateAndLowCardinality|ResourcePrimitivesStressDoNotGrowGoroutines)$'
go test -race -count=1 ./internal/agent ./internal/gateway -run 'Test(AgentQueue|StreamQueueBudgets|GatewayRateAndConcurrencyLimitsFailClosed|ResourcePrimitivesStressDoNotGrowGoroutines)'

echo "R-3 resource/DoS gate: PASSED — byte budgets, global ingress/queue limits, rate/concurrency controls, aggregate saturation metrics and race-safe cleanup passed."
