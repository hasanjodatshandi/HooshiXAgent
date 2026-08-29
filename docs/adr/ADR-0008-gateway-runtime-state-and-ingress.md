# ADR-0008: Gateway Runtime State and Ingress Model

Status: Accepted
Date: 2026-08-29

## Context:

AG-4 introduces the first runnable Tunnel Gateway. Existing architecture already requires a server-side data plane, externally supplied routing/authorization metadata, Caddy as the public edge/TLS component, outbound Agent WSS/TLS, bounded multiplexing, and no Control Panel persistence inside this repository.

The Gateway therefore needs an explicit runtime-state and ingress model that can be implemented and exercised without changing durable ownership boundaries.

## Decision:

The AG-4 Gateway is stateless with respect to Control Panel business state.

It owns only ephemeral in-memory runtime state for:

- authenticated Agent sessions;
- active logical streams;
- bounded per-session sequence/resource state;
- short-lived request correlation and traffic counters.

Externally authoritative device/session authorization, endpoint route assignment, and revocation records are consumed through a narrow `MetadataSource` interface. The production executable includes a validated read-only snapshot-directory adapter so the real Gateway can be exercised independently before a live Control Panel integration transport exists. That adapter is not a durable business system of record and exposes no CRUD surface.

Gateway status/traffic outputs are emitted through a `StatusSink` interface. The executable provides a JSON-lines sink for operational integration/testing; those signals are telemetry/integration outputs and never authorization or routing authority.

The runnable Gateway exposes one HTTPS server. `/agent/v1/connect` upgrades to the already-approved protocol-v1 WebSocket session; public HTTP requests on other hosts/paths are ingress requests. In production, Caddy remains the approved public edge/TLS component and may forward approved traffic to this HTTPS Gateway listener. The Gateway executable itself requires a TLS certificate/key and has no plaintext production mode.

Public HTTP ingress is serialized as opaque HTTP bytes into a protocol-v1 logical stream. The Gateway supplies only the externally assigned `local_endpoint_id`; it never supplies a raw Agent target. The Agent remains responsible for resolving that opaque ID to an approved local loopback target in AG-5.

## Alternatives:

- Add a Gateway database for routes/sessions: rejected because it violates the external Control Panel ownership boundary and is unnecessary for AG-4 runtime state.
- Implement Control Panel CRUD/API calls inside the Gateway: rejected because AG-4 only consumes the established external contract.
- Add a plaintext Gateway listener for convenience: rejected because it would create an insecure production fallback.
- Make the public caller choose a local target: rejected because it violates ADR-0006 and the SSRF/local-target policy.

## Consequences:

Gateway restart intentionally loses active sessions/streams because they are ephemeral. Durable endpoint/device assignments remain external. Full process-restart recovery acceptance is reserved for the later plan leaves that explicitly require restart/recovery evidence. Runtime horizontal-scaling coordination is not introduced in AG-4; any future shared session/routing coordination mechanism is a material scaling decision requiring the applicable ADR/plan process.

## Security impact:

The Gateway must enforce TLS, strict protocol-v1 parsing, Ed25519 challenge verification, token digest validation, replay sequencing, bounded handshakes/sessions/streams/queues/request sizes, finite deadlines, no raw-target authority, and fail-closed external metadata validation.

## Reliability/performance impact:

In-memory state keeps the AG-4 data plane simple and removes database availability from the active stream path. A process restart closes active tunnels; reconnect/recovery is expected and tested. Exact multi-instance coordination is deferred and not silently implemented.

## Compatibility/migration impact:

Later Control Panel integration transports may implement the same `MetadataSource`/`StatusSink` boundaries without changing protocol v1. Replacing ephemeral state with distributed coordination or introducing a datastore requires explicit architecture review.

## Verification / fitness functions:

- Real Gateway executable refuses startup without TLS certificate/key.
- WSS Agent authentication succeeds with valid external metadata and fails closed with invalid credentials.
- Public ingress resolves only externally supplied route metadata and a live authenticated session.
- Concurrent requests use distinct bounded logical streams over one Agent session.
- Agent session disconnect/reconnect removes stale runtime state and restores routing after successful re-authentication.
- No Control Panel persistence/CRUD or raw local target is introduced.

## Rollback/supersession:

Supersession requires a new Accepted ADR and any required Durable Plan change.

## Related ADRs:

- ADR-0001 — Agent↔Gateway transport
- ADR-0003 — external Control Panel integration boundary
- ADR-0004 — Caddy/TLS and domain edge ownership
- ADR-0005 — bounded tunnel stream multiplexing
- ADR-0006 — routing ownership
- ADR-0007 — protocol v1 framing and JSON control encoding
