# ADR-0001: Agent↔Gateway Transport

Status: Accepted
Date: 2026-08-29

## Context:

HooshiXAgent requires an installable Edge Agent behind normal user/network boundaries to maintain a production tunnel to the server-side Tunnel Gateway without requiring inbound connectivity to the user's machine. The approved scope lock already fixes the primary Agent transport as outbound WSS/TLS on TCP 443.

## Decision:

The production Edge Agent initiates an outbound WebSocket Secure connection over TLS on TCP 443 toward the approved public edge/Gateway path.

The transport contract requires TLS certificate verification, authenticated session establishment, protocol-version negotiation, replay protection, heartbeat/liveness, bounded read/write/idle timeouts, bounded frames/streams/queues, malformed-input rejection, and no insecure production fallback.

The Gateway does not require an inbound connection to the Agent.

Concrete wire schemas and frame encoding are deferred to AG-3.

## Alternatives:

- Raw inbound connections to the Agent: rejected because they violate the approved outbound-only architecture.
- An insecure plaintext fallback: rejected because it violates the security standard.
- Replacing WSS/TLS with another primary transport: not selected; such a material change requires explicit user approval and an audited plan/ADR change.

## Consequences:

The Agent/Gateway architecture can operate through common outbound TCP 443 network paths. WebSocket/TLS framing and connection lifecycle become part of the security and runtime acceptance surface.

## Security impact:

TLS verification, authentication, replay resistance, protocol validation, resource bounds, and timeout enforcement are mandatory. Disabling TLS verification or providing an insecure production fallback is prohibited.

## Reliability/performance impact:

One authenticated transport session may carry multiple bounded logical streams. Reconnect, heartbeat, timeout, and resource-limit behavior must be finite and observable when implemented.

## Compatibility/migration impact:

Protocol version negotiation is required so later compatible evolution can be explicit. Any future primary-transport replacement requires a new accepted ADR and any required Durable Plan change.

## Verification / fitness functions:

- Architecture documentation states outbound WSS/TLS on TCP 443.
- No architecture path requires inbound Agent connectivity.
- Security documentation retains TLS verification, replay, timeout, frame/stream/resource bounds, and no insecure fallback.
- AG-3 concrete protocol work must remain compatible with this transport decision.

## Rollback/supersession:

Supersession requires a new accepted ADR plus any required explicitly approved Durable Plan change. Until then, this ADR is current authority.

## Related ADRs:

- ADR-0005 — bounded tunnel stream multiplexing
