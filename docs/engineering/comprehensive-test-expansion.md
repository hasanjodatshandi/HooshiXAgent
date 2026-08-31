# R-11 Comprehensive Test Expansion

R-11 expands automated test evidence for the existing Edge Agent, Tunnel Gateway, and shared protocol/contracts. It does not change product behavior, protocol contracts, deployment architecture, resource defaults, or the external Control Panel boundary.

## Fuzz surfaces

The R-11 gate runs bounded Go fuzz smoke for:

- protocol frame decoding and control-payload strictness;
- external authorization, route, revocation, and status record parsing;
- contract hostname validation and Gateway hostname lookup canonicalization;
- Agent loopback-only local-target validation; and
- tunneled HTTP response/header parsing and bounded response-body handling.

Successful fuzz parsing is checked against the invariants owned by the relevant parser. Invalid arbitrary input is allowed to be rejected; fuzz tests must not invent stronger semantics for invalid input than the product contract defines.

## Deterministic scenarios

The dedicated scenario suite covers:

- a bounded multi-Runner reconnect storm using deterministic one-millisecond retry bounds;
- Agent queue backpressure and release without byte-budget leaks;
- Gateway request-body progress before public upload completion;
- public-upload cancellation cleanup;
- a blocked tunnel consumer retaining at most one streaming chunk;
- an eight-request concurrent Gateway burst within existing configured limits; and
- a blocked telemetry sink remaining off critical request/session paths.

These are non-functional correctness scenarios, not a capacity claim. R-12 remains responsible for reproducible load/soak profiling, capacity envelopes, SLOs, and any evidence-based default tuning.

## Coverage reporting

CI generates `coverage.out`, `coverage.txt`, and a short README as an R-11 artifact. Coverage is reviewed as evidence of exercised code paths. No percentage threshold is used as a pass/fail gate because a single percentage does not establish security or behavioral completeness.

## Platform evidence

The existing Ubuntu, Windows, and macOS Agent platform jobs additionally run a bounded fuzz smoke of the local-target policy. Full networked Gateway runtime acceptance remains on supported Linux CI/runtime gates; R-11 does not claim identical container/network runtime support on all hosted operating systems.
