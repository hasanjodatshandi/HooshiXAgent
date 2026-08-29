# ADR-0003: External HooshiX Control Panel Integration Boundary

Status: Accepted
Date: 2026-08-29

## Context:

HooshiXAgent owns only the Edge Agent, Tunnel Gateway, and minimum shared/integration contracts required for their operation. User/account/device-management/public-endpoint-management/quota/control APIs and UI belong to a separate HooshiX Control Panel project.

The Agent and Gateway still require externally supplied authorization and routing information, so the integration boundary must be explicit without importing Control Panel business logic or persistence into this repository.

## Decision:

The HooshiX Control Panel is an external system and remains outside this repository and Durable Plan.

HooshiXAgent may integrate with it only through explicit language-neutral contracts required for runtime operation. At the architecture level those inputs/signals are limited to:

- device/session credential or authorization inputs;
- endpoint assignment and routing metadata;
- revocation/disable/status signals;
- bounded status/usage/traffic signals where required for operation.

Concrete contract shapes and test fixtures are deferred to AG-3.

The Gateway must not read or own the Control Panel database. The Agent must not embed Control Panel server/business logic. HooshiXBrain remains unrelated to Control Panel ownership.

## Alternatives:

- Implement the Control Panel inside HooshiXAgent: rejected because it violates the current project scope.
- Let the Gateway read a Control Panel database directly: rejected because it couples the data plane to external persistence ownership and violates the approved boundary.
- Move Control Panel ownership into HooshiXBrain: rejected because it violates the explicit product boundaries.

## Consequences:

Agent/Gateway development can proceed against explicit contracts and later mocks/stubs without implementing Control Panel business features. Cross-project compatibility becomes an explicit contract concern rather than a shared-database concern.

## Security impact:

Externally supplied metadata is untrusted at the transport/integration boundary until validated. Authorization inputs must be scoped and replay-resistant where applicable. Secrets and private keys must not cross this boundary except as explicitly allowed public/credential material; the Agent private key never does.

## Reliability/performance impact:

Runtime components must handle unavailable, stale, revoked, or invalid external metadata according to later concrete contract semantics without treating telemetry or caches as business authority.

## Compatibility/migration impact:

The language-neutral contract introduced in AG-3 must be versioned/validated so the external project can evolve without direct database coupling. Adding Control Panel implementation to this repository requires an explicit scope change, audited replan, and applicable ADRs.

## Verification / fitness functions:

- No users, tenants, quotas, billing, Control Panel persistence, Control Panel APIs, or Control Panel UI are implemented in HooshiXAgent.
- Gateway architecture has no direct Control Panel database dependency.
- The integration boundary is described only in operational contract categories required by Agent/Gateway.
- HooshiXBrain is not assigned Control Panel ownership.

## Rollback/supersession:

Supersession requires an explicit user-approved scope/architecture change, audited Durable Plan change where required, and a new accepted ADR.

## Related ADRs:

- ADR-0002 — per-device Ed25519 identity and key locality
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
