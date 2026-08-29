# HooshiXAgent Day-One Observability Standard

**Status:** Normative

When a critical path first becomes executable, its applicable observability must be introduced with that capability rather than deferred as cleanup.

## Required signals

Add as applicable:

- structured JSON logs;
- stable event names/codes;
- request, operation, and dependency metrics;
- saturation/resource metrics;
- traces/correlation where useful;
- health and readiness endpoints/signals;
- alert/SLO ownership when meaningful for the deployed capability.

## Data safety

Observability MUST NOT expose:

- passwords;
- enrollment codes;
- auth/session tokens;
- private keys;
- datastore credentials;
- full sensitive payloads.

Metric labels must remain bounded and low-cardinality.

Telemetry is evidence and operational signal; it MUST NOT become authentication, authorization, routing-policy, or business authority.

## Runtime-gate relationship

When a critical path becomes runnable, runtime verification should confirm applicable observability is emitted and usable without exposing secrets or creating unbounded-cardinality labels.
