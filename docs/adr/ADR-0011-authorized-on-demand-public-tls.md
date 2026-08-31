# ADR-0011: Authorized On-Demand Public TLS for Dynamic Hostnames

Status: Accepted
Date: 2026-08-31

## Context

The external endpoint contract permits many independently assigned `public_hostname` values, and the Gateway already performs runtime route lookup by canonical public hostname. The current packaged Caddy deployment, however, names only one `HOOSHIX_PUBLIC_HOST` in its site address. That deployment shape cannot represent the already accepted multi-endpoint routing model without either continuously rewriting Caddy configuration or adopting a dynamic certificate strategy.

ADR-0004 keeps Caddy as the public TLS edge and leaves concrete DNS/certificate operations to later approved work. ADR-0003 and ADR-0006 keep durable public-endpoint lifecycle outside this repository while allowing the Gateway to enforce validated runtime routing metadata.

Caddy supports On-Demand TLS for hostnames that are not known at process start. Caddy's production guidance requires an authorization/permission decision to prevent arbitrary certificate issuance and resource abuse.

## Decision

Caddy remains the HooshiXAgent public edge/TLS component.

The approved production multi-host strategy is **restricted On-Demand TLS** for dynamic public hostnames. On-Demand TLS MUST NOT be enabled as an unrestricted catch-all.

Certificate authorization is derived from the same externally authoritative endpoint lifecycle that supplies `endpoint-route-assignment` records. The production permission decision is owned outside HooshiXAgent by the external HooshiX Control Panel integration boundary; HooshiXAgent does not implement endpoint CRUD, domain ownership verification, account policy, or Control Panel persistence.

The permission integration has these minimum semantics:

1. Caddy asks whether the requested TLS server name/domain is currently approved for certificate management through the documented `on_demand_tls { ask <endpoint> }` HTTP permission mechanism. RA-0 deliberately chooses this documented production-facing shortcut rather than depending on the separately exposed `tls.permission` module namespace while that namespace is still marked experimental.
2. The permission endpoint performs an exact lookup using the same canonical hostname semantics as Gateway routing (ASCII contract hostname, case-insensitive, no trailing-dot distinction). It must not authorize based only on DNS resolution, caller IP, a suffix match, or the fact that the hostname reaches this Caddy instance.
3. Success is fail-closed and explicit: the HTTP permission endpoint returns `200 OK` only for an allowed hostname; any other response, redirect, error, timeout, unavailable authority, malformed input, unknown hostname, disabled endpoint, expired assignment, or unverified domain ownership denies the operation.
4. The permission path must be low-latency and bounded. It must not perform recursive DNS discovery or an unbounded scan as part of the decision.
5. TLS certificate authorization is **not** routing authorization. After TLS succeeds, every public HTTP request is still routed only when the Gateway has a currently valid `endpoint-route-assignment` for the Host value and an eligible authenticated Agent session.
6. Caddy certificate state remains in its persistent `/data` storage and Caddy continues to own certificate issuance, renewal, and TLS termination.
7. Public operational paths such as Gateway `/readyz` and `/metrics` remain non-public regardless of hostname/certificate state.

The packaged deployment may retain an explicit static-host mode for deterministic development/tests or constrained installations, but the production capability for independently managed multiple public hostnames is the restricted On-Demand TLS model above.

RA-4 owns the concrete Caddy/Compose implementation and real multi-host public-edge acceptance. This ADR does not implement it.

## Alternatives

### Unrestricted On-Demand TLS

Rejected. Any Internet client could cause certificate-management attempts for attacker-selected names, consuming local/CA resources and creating avoidable abuse and rate-limit exposure.

### Controlled wildcard certificate as the only production model

Not selected as the primary model. A wildcard would efficiently cover one operator-controlled suffix, but it constrains the external `public_hostname` model to that namespace and requires DNS-01/provider credential operations. It does not cover arbitrary externally approved customer domains. A future optional wildcard optimization may be added only if it preserves the permission/routing trust model and is separately approved where material.

### Regenerate/reload Caddy configuration for every endpoint change

Rejected as the primary model. It creates a second live routing/configuration synchronization path beside Gateway metadata, couples endpoint churn to Caddy reload operations, and increases the number of states that must be atomically reconciled.

### Move durable endpoint/domain ownership into Gateway

Rejected. It violates ADR-0003 and ADR-0006. Gateway remains a consumer/enforcer of validated runtime metadata, not the durable endpoint-management authority.

### Replace Caddy

Rejected. No evidence requires changing the accepted edge component.

## Consequences

New approved hostnames do not require a Caddy process restart or a per-host Caddyfile edit before first use. Their first TLS handshake may incur certificate issuance latency.

The external domain-permission authority becomes an availability dependency for first-time/on-demand certificate operations. Permission-authority failure denies new certificate operations rather than widening authorization. Previously cached valid certificates may still allow TLS handshakes, but Gateway route authorization remains independently required for every request.

The Control Panel project must eventually expose or supply a Caddy-compatible, bounded domain-permission integration as part of its own implementation. Deterministic HooshiXAgent tests may use a mock permission authority; that mock is not Control Panel product implementation.

## Security impact

- Certificate issuance is deny-by-default for unknown/unapproved names.
- DNS pointing at the Caddy host is not sufficient authorization.
- Domain ownership/account policy stays outside this repository.
- Gateway Host routing remains a second independent authorization boundary after TLS.
- No insecure TLS fallback is introduced.
- Caddy-to-Gateway verified TLS remains mandatory.
- ACME production testing must avoid unnecessary issuance/rate-limit consumption; staging/test issuers are used where applicable.

## Reliability/performance impact

Certificate acquisition is deferred to the first qualifying TLS handshake for a hostname. Permission checks must have finite deadlines and fast indexed lookup behavior. Existing cached certificates remove that first-handshake cost for subsequent connections.

The design avoids per-endpoint Caddy reload churn and keeps the normal data path as Caddy -> verified HTTPS -> Gateway.

## Compatibility/migration impact

The existing single-host deployment remains a compatible static mode until RA-4 implements the new production multi-host edge. Existing external `endpoint-route-assignment.public_hostname` records do not change shape because the TLS decision consumes the same durable hostname authority rather than creating a second endpoint model.

A future edge replacement, unrestricted certificate policy, or change that moves durable domain ownership into HooshiXAgent requires a superseding ADR and applicable Durable Plan approval.

## Verification / fitness functions

RA-4 must prove:

- two distinct approved public hostnames can be served simultaneously through the real Caddy edge;
- an unknown/unapproved hostname cannot obtain on-demand certificate authorization;
- TLS authorization does not bypass Gateway route validation;
- public `/readyz` and `/metrics` remain unavailable;
- Caddy-to-Gateway certificate verification remains enabled;
- no Control Panel CRUD/database/business implementation is introduced here.

## Rollback/supersession

Before RA-4 deployment changes, rollback is documentation-only. After RA-4, the deployment may temporarily return to the explicitly supported static-host mode while preserving Caddy/TLS/Gateway trust boundaries. Supersession requires a new Accepted ADR and applicable Durable Plan change.

## Related ADRs

- ADR-0003 — external Control Panel integration boundary
- ADR-0004 — Caddy/TLS and domain edge ownership
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
- ADR-0008 — Gateway runtime state and ingress model
- ADR-0010 — packaging, deployment and release trust
- ADR-0012 — live external metadata snapshot projection

## External implementation reference

The selected capability follows Caddy's documented production On-Demand TLS model, which requires a permission decision for dynamically managed hostnames. Current Caddy documentation specifies that the `ask` endpoint receives the requested domain and authorizes certificate management only on a successful HTTP response. The Caddyfile global-option documentation is the implementation reference for RA-4: `https://caddyserver.com/docs/automatic-https#on-demand-tls` and `https://caddyserver.com/docs/caddyfile/options#on-demand-tls`.
