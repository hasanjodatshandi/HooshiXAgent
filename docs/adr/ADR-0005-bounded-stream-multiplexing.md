# ADR-0005: Bounded Tunnel Stream Multiplexing

Status: Accepted
Date: 2026-08-29

## Context:

The Tunnel Gateway and Edge Agent must carry multiple concurrent proxied flows without creating one independent tunnel-control relationship per public request. The approved architecture requires stream multiplexing and explicit resource bounds over the authenticated Agent transport.

## Decision:

An authenticated Agent↔Gateway session may carry multiple logical tunnel streams.

The protocol must distinguish session/control behavior from per-stream lifecycle and data behavior sufficiently to support:

- stream open;
- stream data transfer;
- stream close;
- stream failure/cancellation;
- heartbeat/liveness at the session level;
- bounded frame size, concurrent streams, queues, and related resources.

A session or transport failure invalidates its affected runtime streams. Concrete frame encoding, field layout, numeric limits, and exact message schemas are intentionally deferred to AG-3 and later implementation leaves.

Multiplexing does not authorize a target: routing authorization and local-target approval remain separate responsibilities.

## Alternatives:

- Unbounded concurrent streams: rejected because it violates the security/resource standard.
- Treat every public request as permission to choose a local target: rejected because stream creation and local-target authorization are separate trust decisions.
- Fix a concrete binary/text frame schema in AG-1: rejected as premature because concrete protocol contracts belong to AG-3.

## Consequences:

Agent and Gateway implementations must maintain explicit per-session and per-stream state with deterministic teardown and bounded resource use. Concrete protocol-schema work remains isolated to its planned leaf.

## Security impact:

Maximum frame size, maximum streams, bounded queues, malformed-frame rejection, authentication, replay protection, and timeout handling are mandatory. Stream identifiers or control messages cannot bypass routing authorization or the Agent local-target policy.

## Reliability/performance impact:

Multiplexing reduces the need for separate Agent transport establishment for each logical flow, but introduces per-session stream lifecycle and backpressure/resource-management requirements. All such resources must be bounded.

## Compatibility/migration impact:

Concrete AG-3 protocol schemas must retain the logical session/stream separation and version negotiation. A materially different non-multiplexed architecture requires a superseding ADR.

## Verification / fitness functions:

- Architecture documentation states that authenticated Agent sessions support multiple bounded logical streams.
- No AG-1 document fixes a concrete wire encoding that belongs to AG-3.
- Resource bounds and deterministic stream/session teardown remain mandatory.
- Stream multiplexing is not treated as routing or local-target authorization.

## Rollback/supersession:

Supersession requires a new accepted ADR and any required explicitly approved Durable Plan change.

## Related ADRs:

- ADR-0001 — Agent↔Gateway transport
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
