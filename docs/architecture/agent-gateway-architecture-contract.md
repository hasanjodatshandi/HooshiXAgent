# HooshiXAgent Edge Agent + Tunnel Gateway Architecture Contract

**Status:** Normative
**Durable Plan leaf:** `AG-1 — Edge Agent + Tunnel Gateway Architecture Contract`
**Project:** `hooshix-agent`

This document freezes the architecture boundaries originally approved in AG-1. Decision-time statements about work belonging to later AG leaves are retained as provenance rather than rewritten.

**R-13 current-state note:** AG-2 through AG-9 and hardening R-0 through R-12 have since been implemented without changing the ownership/trust model frozen here. Current runtime limits, failure semantics, deployment posture and capacity evidence are summarized in `docs/engineering/current-state.md`. Historical ADR text remains unchanged.

## 1. Product boundary

HooshiXAgent contains exactly these product/runtime responsibilities:

```text
HooshiXAgent
├── Edge Agent
├── Tunnel Gateway
└── shared/language-neutral contracts required for Agent↔Gateway operation
    and the minimum external Control Panel integration boundary
```

The separate **HooshiX Control Panel** is an external project. It is not a service, package, database, API, UI, or business-logic subsystem of this repository.

HooshiXBrain is also separate from this product boundary and does not own HooshiX Control Panel or Tunnel Gateway responsibilities.

## 2. Edge Agent responsibilities

The Edge Agent is the installable process running on the user's machine. Its architecture responsibilities are limited to:

- create and use a unique per-device Ed25519 identity;
- keep the device private key on the device and consume only externally issued/scoped authorization material;
- establish an **outbound-only WSS/TLS connection on TCP 443** toward the Tunnel Gateway path;
- authenticate the device/session and participate in protocol-version negotiation, replay-resistant session establishment, heartbeat/liveness, and bounded reconnect behavior;
- maintain only locally approved endpoint-to-target mappings;
- connect tunnel streams only to an approved local target under the repository SSRF/local-target policy;
- proxy stream bytes between the approved local service and the authenticated Gateway session;
- expose local status/diagnostic signals required by later approved leaves without becoming Control Panel business authority.

The Agent does **not** implement account, tenant, enrollment-management, public-endpoint-management, quota, billing, dashboard, or Control Panel API logic.

## 3. Tunnel Gateway responsibilities

The Tunnel Gateway is the server-side data-plane process. Its architecture responsibilities are limited to:

- accept authenticated Agent sessions through the production WSS/TLS TCP 443 path;
- enforce protocol version, authentication, replay protection, frame/stream/resource bounds, heartbeat, timeouts, and malformed-input rejection;
- maintain runtime Agent-session and stream state needed for tunnel operation;
- multiplex multiple bounded logical streams over authenticated Agent sessions;
- accept public ingress routed through the approved MVP edge/TLS layer;
- resolve an authorized public endpoint to externally supplied, validated routing/session metadata;
- route public traffic to the corresponding authenticated Agent session and logical stream;
- emit bounded status/usage/traffic signals through the later-defined external contract without owning Control Panel business state.

The Gateway does **not** own Control Panel persistence, users, tenants, enrollment management, endpoint CRUD, quotas, billing, or the durable system of record for externally managed endpoint/device assignments.

## 4. External HooshiX Control Panel boundary

The external HooshiX Control Panel owns control-plane business responsibilities, including:

- users/accounts and their authentication/session business logic;
- tenants/organizations/memberships where that product requires them;
- device enrollment-management and device-management CRUD;
- public endpoint lifecycle/management;
- quotas, plans, billing, and commercial policy;
- Control Panel APIs and UI;
- durable control-plane persistence.

HooshiXAgent may consume only the minimum external information necessary for Agent/Gateway operation. The later AG-3 leaf is responsible for defining the concrete language-neutral contract shapes. At the architecture level, that boundary is limited to:

- device/session credential or authorization inputs;
- endpoint assignment and routing metadata;
- revocation/disable/status signals;
- bounded status/usage/traffic signals where required for operation.

The Gateway MUST NOT couple directly to a Control Panel database. The Agent MUST NOT embed Control Panel server/business logic.

## 5. Agent↔Gateway transport and protocol scope

The production Agent transport is fixed as:

```text
Edge Agent ── outbound WSS/TLS over TCP 443 ──> public edge ──> Tunnel Gateway
```

The protocol scope includes only what is necessary for tunnel operation:

- authenticated session establishment;
- protocol-version negotiation;
- replay-resistant authorization/session use;
- heartbeat/liveness;
- logical stream open, data, close, and failure semantics;
- bounded stream/frame/resource behavior;
- endpoint/session identifiers required to bind a stream to an authorized route;
- revocation/disable handling required to stop authorization;
- bounded operational/status signals required by the Agent/Gateway runtime.

AG-1 intentionally does **not** define concrete wire schemas, frame encoding, field numbers, or language-specific API models. Those concrete contracts belong to AG-3.

There is no insecure production transport fallback.

## 6. Tunnel and endpoint runtime semantics

The architecture freezes these runtime ownership rules:

1. The Agent initiates the network connection; the Gateway never requires an inbound connection to the user's machine.
2. A public requester addresses a public endpoint; the requester cannot select a raw local Agent target.
3. The external Control Panel owns durable public-endpoint/device assignment state.
4. The Gateway consumes validated external routing/session metadata and owns only runtime routing/enforcement for active tunnel traffic.
5. The Agent owns the final local approved endpoint-to-target mapping and may dial only targets allowed by the local-target policy.
6. Gateway instructions or public input cannot override the local-target/SSRF policy with an arbitrary address.
7. Multiple logical streams may share an authenticated Agent session, subject to explicit bounds.
8. Session loss closes or invalidates affected runtime streams; reconnect/recovery behavior must remain bounded. Exact retry/backoff values are implementation details for later approved leaves.

## 7. Security and trust boundaries

### Device identity

- Each install has a unique Ed25519 identity.
- The device private key never leaves the device.
- Shared fleet-wide private keys are prohibited.
- OS-specific secure-storage implementation details are deferred to the Edge Agent implementation leaf.

### Authorization material

- Externally issued enrollment/authorization material must be short-lived, scoped, replay-resistant, and one-time where the external contract specifies one-time use.
- Logs, telemetry, evidence, and diagnostics must not expose secrets or private keys.

### Local target / SSRF

The MVP local-target allowlist remains:

```text
127.0.0.0/8
::1
localhost
```

Arbitrary LAN, link-local, metadata, multicast/broadcast, file URLs, arbitrary schemes, named pipes, and Unix sockets remain denied unless a later explicitly approved plan/ADR changes that policy.

### Protocol/resource safety

The runtime design must preserve explicit bounds for frames, streams, queues, connection/handshake rates, timeouts, retries, and telemetry. Exact numeric limits are not selected in AG-1 unless already fixed by a later approved specification.

## 8. Domain and TLS edge strategy

For the MVP architecture:

- Caddy is the approved public edge/TLS component;
- public TLS termination/certificate handling is an edge responsibility;
- the Agent-facing production path remains WSS/TLS on TCP 443 with certificate verification and no insecure fallback;
- the Gateway receives only traffic forwarded through the approved edge path in deployed MVP topology;
- durable public endpoint naming/lifecycle remains owned by the external Control Panel and is supplied to the Gateway through the explicit integration contract;
- exact DNS provider automation, deployment packaging, and operational certificate workflows belong to later approved deployment/operations leaves.

No Kubernetes, service mesh, Redis, NATS, Kafka, or new datastore is introduced by AG-1.

## 9. Shared contract ownership

Shared code/contracts in this repository may describe only Agent/Gateway tunnel operation and the minimum external Control Panel boundary required for it.

Allowed contract ownership:

- Agent↔Gateway tunnel/session protocol definitions;
- endpoint/session/routing identifiers required at runtime;
- external metadata interfaces/stubs required to decouple Gateway from Control Panel implementation;
- security/version/error semantics shared by Agent and Gateway.

Disallowed contract ownership:

- user/tenant CRUD models;
- billing/plan/quota business APIs;
- Control Panel database schemas;
- dashboard/UI models;
- Control Panel authentication/session business implementation.

Concrete contract implementation is AG-3 work, not AG-1 work.

## 10. MVP scope

The architectural MVP is a Go Edge Agent plus Go Tunnel Gateway that can, in later approved leaves, use externally authorized device/endpoint metadata to expose an approved local loopback service through an authenticated outbound tunnel and public edge.

AG-1 freezes the ownership and trust model needed to enable that implementation. It does not create executables, repositories/packages, protocol schemas, deployment artifacts, or runtime services.

## 11. Non-goals

AG-1 and HooshiXAgent explicitly do not own:

- implementation of the HooshiX Control Panel;
- users, tenants, account authorization, quotas, plans, billing, or commercial policy;
- Control Panel persistence or direct database integration;
- Control Panel APIs or dashboard/UI;
- Kubernetes or distributed coordination infrastructure;
- a new datastore;
- arbitrary LAN/public-to-local target selection;
- inbound Agent connectivity from the Gateway;
- an insecure non-TLS production fallback;
- concrete AG-3 wire schema design;
- AG-4/AG-5 runtime implementation;
- AG-7 deployment/packaging implementation.

## 12. Architecture decision records

The decisions frozen by this contract are recorded in:

- `ADR-0001` — Agent↔Gateway transport;
- `ADR-0002` — per-device Ed25519 identity and key locality;
- `ADR-0003` — external Control Panel integration boundary;
- `ADR-0004` — Caddy/TLS/domain edge ownership;
- `ADR-0005` — bounded tunnel stream multiplexing;
- `ADR-0006` — routing ownership across Control Panel, Gateway, and Agent.

The Decision Register is `docs/adr/decision-register.md`.

## 13. AG-1 acceptance mapping

| Durable Plan requirement | Frozen by this contract |
| --- | --- |
| Edge Agent responsibilities | Sections 2, 6, 7 |
| Tunnel Gateway responsibilities | Sections 3, 6, 7 |
| External Control Panel boundary | Sections 4, 9, 11 |
| Shared Agent↔Gateway protocol scope | Sections 5, 9 |
| MVP/non-goals | Sections 10 and 11 |
| No users/tenants/quotas/control-panel persistence | Sections 4, 9, 11 |
| Control Panel external only | Sections 1 and 4 |
| Agent/Gateway responsibilities unambiguous | Sections 2 and 3 |
| HooshiXBrain unrelated to Control Panel ownership | Section 1 |
