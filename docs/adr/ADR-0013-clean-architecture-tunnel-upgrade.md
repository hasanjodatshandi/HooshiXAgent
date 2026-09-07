# ADR-0013: Clean Architecture Layering for the Tunnel Upgrade

Status: Accepted
Date: 2026-09-06

## Context

The user-approved Tunnel Implementation Plan (docs/Tunnel-Implementation-Plan/) upgrades HooshiXAgent into a production-grade edge connector through five phases: Reliability (connection health states, heartbeat health reporting, graceful shutdown), Protocol (session resume, versioned protocol evolution), High Availability (multiple tunnel connections with failover), Security (key rotation, session validation), and Operations (expanded metrics).

The user additionally mandated that the final architecture follow Clean Architecture for the entire project, not only new components. The current implementation is organized as product packages (`internal/agent`, `internal/gateway`, `internal/contractv1`) with logic that mixes domain rules, application orchestration, and infrastructure adapters inside each package.

The accepted ADR-0001..0012 boundaries (outbound WSS/TLS, per-device Ed25519 locality, external Control Panel boundary, Caddy edge, bounded multiplexing, routing ownership, protocol-v1 framing, ephemeral Gateway state, Agent local state, packaging/release trust, On-Demand TLS, live metadata projection) all remain in force; this ADR adds an internal layering discipline without changing any of those trust, transport, or ownership decisions.

## Decision

The repository will adopt an explicit Clean Architecture dependency rule across the Go implementation:

```text
adapters (network, OS/filesystem, platform secret stores, processes)
        ↓ depends on
application (use-case orchestration: session lifecycle, reconnect,
             failover, health, key rotation, metrics collection)
        ↓ depends on
domain (pure policy/invariants: tunnel state machines, protocol
        contract semantics, resource budgets, routing policy)
```

The dependency direction is strictly inward. Domain code imports no network, filesystem, or OS implementation packages. Application code may import domain code and defines the ports (small consumer-side interfaces) it needs. Adapter code implements those ports and wires concrete implementations (coder/websocket, net/http, os files, DPAPI/file secret stores, slog, Prometheus text output).

Layering is realized within the existing product boundaries as:

- `internal/contractv1` stays the shared protocol-contract reference (unchanged authority per ADR-0007);
- each product (Agent, Gateway) keeps its own `domain` (state machines, policies), `application` (orchestration), and `adapters` (transport, storage, telemetry), with composition at the `cmd` boundary;
- existing hardening, bounds, fail-closed semantics, and resource limits move with their components and remain mandatory;
- the Tunnel Implementation Plan phases are implemented inside this layering:
  - Phase 1: explicit Agent/Gateway connection health state machines (domain), health orchestration and HEALTH_REPORT heartbeat extension (application/protocol), graceful Agent shutdown;
  - Phase 2: session resume support with versioned protocol evolution per the ADR-0007 compatibility rules;
  - Phase 3: multiple concurrent tunnel connections per Agent with failover, bounded by explicit limits;
  - Phase 4: key rotation support and session validation hardening under the ADR-0002 key-locality boundary;
  - Phase 5: operational metrics (active_tunnels, reconnect_total, bytes_sent, bytes_received, latency, stream_count) exported through bounded low-cardinality telemetry only.

All existing security, runtime, CI, and acceptance gates remain blocking; none may be weakened.

## Alternatives

- Keep the current package-centric layout and add the phases without layering: rejected by the explicit user requirement that the whole project conform to Clean Architecture.
- A full rewrite into `pkg/domain`, `pkg/usecase`, `pkg/infra`: rejected because it breaks the existing architecture-fitness boundaries, imports churn across every gate, and the product-boundary tests reference the current layout; incremental in-place layering preserves them.
- Apply Clean Architecture only to new phase components: rejected because the user explicitly required the final project to conform, not only new parts.

## Consequences

The implementation gains explicit domain models for tunnel lifecycle, health, resume, failover, and rotation that are testable without real sockets or files. Application orchestration becomes independently testable through ports. Infrastructure specifics (websocket library, DPAPI, file snapshots) are confined to adapters and wiring.

Refactoring must be incremental and gate-preserving: each phase lands as a coherent change with the full existing verification chain (go-quality, security, runtime gate, E2E, hardening gates) re-run and passing. Public behavior, protocol wire compatibility, and resource defaults must not regress.

## Security impact

No trust boundary changes. Private keys remain local (ADR-0002); the Gateway remains enforcement-only with ephemeral state (ADR-0008); routing authority and loopback-only targets remain unchanged (ADR-0006, security standard); telemetry remains non-authoritative and low-cardinality. Key rotation must not weaken the existing Ed25519 handshake or replay protections; resume must not create a bypass around authentication or revocation.

## Reliability/performance impact

Health states and failover are bounded by explicit limits in the existing style; multiple tunnel connections multiply handshake load, so per-device tunnel counts and rates must be explicitly bounded and reuse existing admission-control patterns. Metrics collection must stay asynchronous/bounded per the R-8 model.

## Compatibility/migration impact

Protocol v1 wire compatibility is preserved; new messages (resume, health report) extend the v1 control set only where the ADR-0007 strictness rules permit, with strict validation and version rejection retained. Any wire-incompatible change requires a new protocol version and ADR. On-disk Agent state formats remain versioned; incompatible format changes require explicit migration handling.

## Verification / fitness functions

- Domain packages have no infrastructure imports (enforced by architecture fitness tests).
- All existing CI gates pass after each phase: go-quality, security, runtime gate, E2E acceptance, and the hardening gate chain.
- Connection state machine transitions are unit-tested for legal and illegal transitions.
- Heartbeat HEALTH_REPORT flows from Agent to Gateway and is exposed in bounded aggregate metrics only.
- Session resume reconnects without re-authenticating identity when the Gateway still holds a valid session, and fails closed otherwise.
- Multi-tunnel failover keeps public routing available through a surviving connection and remains within bounded connection counts.
- Key rotation replaces the device key under operator action without leaking the private key and without breaking existing sessions until their natural expiry.
- Operational metrics cover active_tunnels, reconnect_total, bytes_sent, bytes_received, latency, stream_count with no secrets and bounded labels.

## Rollback/supersession

Each phase is a separate commit/PR-scope on this branch; a phase can be reverted independently while keeping earlier phases. Full rollback returns to the pre-ADR-0013 package layout. Supersession requires a new Accepted ADR.

## Related ADRs

- ADR-0001 — Agent↔Gateway transport
- ADR-0002 — per-device Ed25519 identity and key locality
- ADR-0005 — bounded tunnel stream multiplexing
- ADR-0006 — routing ownership
- ADR-0007 — protocol v1 framing and JSON control encoding
- ADR-0008 — Gateway runtime state and ingress model
- ADR-0009 — Edge Agent local state, secret storage and runtime model
