# ADR-0004: Caddy/TLS and Domain Edge Ownership

Status: Accepted
Date: 2026-08-29

## Context:

The approved MVP architecture requires a public edge/TLS component while keeping the Tunnel Gateway focused on tunnel/data-plane responsibilities. The project scope also keeps durable public-endpoint lifecycle under the external HooshiX Control Panel.

## Decision:

Caddy is the approved MVP public edge/TLS component.

Caddy owns public TLS termination/certificate handling at the deployed edge and forwards approved traffic toward the Tunnel Gateway. The Agent-facing production path remains WSS/TLS on TCP 443 with certificate verification and no insecure fallback.

Durable public endpoint naming and lifecycle are owned externally by the HooshiX Control Panel and supplied to the Gateway through the explicit integration contract. The Gateway uses validated runtime routing metadata but does not become the durable endpoint-management authority.

Exact DNS-provider automation, deployment packaging, certificate operations/runbooks, and production topology details are deferred to later approved deployment/operations work.

## Alternatives:

- Make the Gateway the durable endpoint-management/control-plane owner: rejected because it violates the external Control Panel boundary.
- Provide a plaintext production edge path: rejected because it violates the security standard.
- Replace Caddy with a different MVP edge component: not selected; such a material architecture change requires explicit approval and a superseding ADR.

## Consequences:

Public TLS concerns remain separated from Gateway business/data-plane ownership. Endpoint lifecycle stays external while runtime route consumption stays in the Gateway.

## Security impact:

Production TLS must remain verified. No insecure fallback is allowed. Edge forwarding and Gateway integration must preserve authentication, routing authorization, and bounded-resource controls.

## Reliability/performance impact:

The public edge becomes an explicit deployment dependency. Health, timeout, forwarding, and certificate operational behavior must be verified when the deployment becomes executable.

## Compatibility/migration impact:

Future edge replacement or materially different domain/TLS ownership requires a new accepted ADR and any required Durable Plan change. Concrete external endpoint metadata contract fields remain AG-3 work.

## Verification / fitness functions:

- Architecture documentation identifies Caddy as the MVP public edge/TLS component.
- Agent production transport remains WSS/TLS over TCP 443.
- Gateway is not assigned durable public-endpoint lifecycle ownership.
- No DNS-provider automation or deployment implementation is introduced by AG-1.

## Rollback/supersession:

Supersession requires a new accepted ADR and any required explicitly approved plan change.

## Related ADRs:

- ADR-0001 — Agent↔Gateway transport
- ADR-0003 — external Control Panel integration boundary
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
