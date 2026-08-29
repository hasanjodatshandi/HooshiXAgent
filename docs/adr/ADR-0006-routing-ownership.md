# ADR-0006: Routing Ownership Across Control Panel, Gateway, and Agent

Status: Accepted
Date: 2026-08-29

## Context:

A public request must reach an approved local service through an authenticated Agent session without allowing public input or Gateway control messages to select arbitrary local network targets. Durable endpoint/device assignments belong to the external HooshiX Control Panel, while runtime tunnel routing belongs to HooshiXAgent.

## Decision:

Routing ownership is split as follows:

1. The external HooshiX Control Panel owns durable public-endpoint lifecycle and durable endpoint/device assignment state.
2. The Tunnel Gateway consumes externally supplied, validated endpoint/session routing metadata and owns runtime routing/enforcement for active tunnel traffic.
3. The Edge Agent owns the final locally approved endpoint-to-target mapping and enforces the repository local-target/SSRF policy before dialing a local service.

A public requester cannot provide a raw local target. The Gateway cannot override the Agent's local-target allowlist by supplying an arbitrary address. The Gateway does not directly own or query a Control Panel database as routing authority.

Concrete integration contract fields and synchronization/revocation message shapes are deferred to AG-3.

## Alternatives:

- Let public input select the Agent target directly: rejected because it violates the SSRF/local-target policy.
- Let the Gateway own durable endpoint-management state: rejected because it violates the external Control Panel boundary.
- Let the Gateway push arbitrary local addresses to the Agent: rejected because it bypasses local authorization and SSRF controls.

## Consequences:

Routing has three explicit trust/ownership layers: durable external assignment, Gateway runtime enforcement, and Agent local-target approval. Implementations must preserve identifiers and validation across these boundaries without collapsing them into shared persistence.

## Security impact:

The split prevents public/Gateway metadata from becoming unrestricted SSRF authority. Externally supplied routing metadata must be validated, authorization/revocation must be enforced, and the Agent must independently enforce its local target policy.

## Reliability/performance impact:

Gateway runtime routing state must handle active session loss and invalid/revoked metadata without becoming durable business authority. Exact cache/synchronization mechanics and limits are later-leaf implementation details.

## Compatibility/migration impact:

AG-3 contract definitions must preserve the ownership split. Moving durable routing ownership into the Gateway, or allowing remote raw-target selection, requires an explicitly approved architecture change and superseding ADR.

## Verification / fitness functions:

- Architecture documentation assigns durable endpoint/device mapping ownership to the external Control Panel.
- Gateway responsibility is runtime routing from validated external metadata only.
- Agent responsibility includes final local approved target mapping and SSRF enforcement.
- No raw local address can be selected by a public caller or injected by Gateway as overriding authority.
- No direct Control Panel database dependency is introduced.

## Rollback/supersession:

Supersession requires a new accepted ADR and any required explicitly approved Durable Plan change.

## Related ADRs:

- ADR-0003 — external Control Panel integration boundary
- ADR-0004 — Caddy/TLS and domain edge ownership
- ADR-0005 — bounded tunnel stream multiplexing
