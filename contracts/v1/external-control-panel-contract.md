# External HooshiX Control Panel Integration Contract v1

**Status:** Normative

This contract defines only the information boundary consumed/emitted by HooshiXAgent. The HooshiX Control Panel remains a separate external product and durable system of record.

## 1. Integration model

HooshiXAgent runtime code may receive validated copies of four contract record types:

1. `device-session-authorization` — authorizes one device/session credential and provides the device Ed25519 public key plus a digest of the short-lived session token;
2. `endpoint-route-assignment` — maps an externally managed public endpoint to a device and opaque Agent-local `local_endpoint_id`;
3. `revocation-signal` — disables/revokes an authorization, route assignment, or device;
4. `gateway-status-signal` — bounded operational/traffic status emitted from the Gateway toward the external system.

RA-0 selects a live transport/projection model around the first three externally authoritative record types without changing their business meaning: complete immutable generations are published under a read-only filesystem projection, and one atomically published current-generation manifest identifies the generation that the Gateway may validate and activate. The Gateway does not query or own a Control Panel database. The exact manifest schema/runtime implementation belongs to RA-3 and must conform to ADR-0012.

The existing flat read-only snapshot remains a static/test/migration compatibility input. It does not provide a live revocation/update guarantee and must not be described as such.

Public TLS for dynamically assigned `public_hostname` values remains Caddy's edge responsibility. RA-0 selects restricted On-Demand TLS for the production multi-host path. The external endpoint/domain lifecycle authority must provide the bounded HTTP permission decision required by Caddy before certificate management is allowed for a previously unknown hostname; `200 OK` means allowed and every other result denies. That permission decision is a read-only integration boundary, not endpoint CRUD or durable state inside HooshiXAgent, and must conform to ADR-0011. Deterministic HooshiXAgent tests may use a mock permission authority.

## 2. Device session authorization

The authorization record contains runtime authorization inputs only:

- opaque `authorization_id`;
- opaque `device_id`;
- Ed25519 `device_public_key`;
- opaque `token_id`;
- SHA-256 digest of the short-lived opaque session token;
- issuance/validity timestamps;
- disabled state.

The raw session token is presented by the Agent during the tunnel handshake and matched against the digest. The external authorization record never contains the device private key.

This record is not a device CRUD model and does not carry user, tenant, plan, billing, or quota state.

## 3. Endpoint route assignment

The route assignment contains:

- opaque `assignment_id`;
- opaque `endpoint_id`;
- externally managed `public_hostname`;
- `device_id`;
- opaque `local_endpoint_id`;
- enabled/validity state.

`local_endpoint_id` identifies an Agent-local mapping. It is **not** an IP address, URL, scheme, file path, named pipe, Unix socket, or arbitrary target selected remotely.

The Gateway uses the assignment only for active runtime routing. It does not become the durable endpoint-management authority.

TLS certificate permission for a hostname and Gateway routing authorization are separate decisions. A successful Caddy certificate permission decision never authorizes a Gateway route by itself; each public request still requires a currently valid route assignment and eligible authenticated Agent session.

## 4. Revocation

Revocation signals identify the externally authoritative subject and effective time. The Gateway indexes revocations and stops relying on effectively revoked authorization/routing state according to its bounded session/request lifecycle.

Under ADR-0012, revocation changes published after process startup become visible through complete validated live generations rather than requiring a Gateway restart. The implementation does not claim instantaneous revocation: the maximum observation/termination delay remains bounded by the configured projection refresh interval plus the applicable request/session revalidation lifecycle.

Revocation is not implemented as local Control Panel CRUD or persistence.

## 5. Gateway status / traffic signal

Status signals are bounded runtime observations. They may report session/route lifecycle and per-event traffic deltas up to the contract limit.

Status signals are telemetry/integration outputs only. They are not authentication, authorization, routing, quota, billing, or business authority.

## 6. Failure and freshness rules

Consumers must fail closed when a record is:

- malformed or has unknown fields;
- an unsupported contract version;
- disabled;
- not yet valid or expired;
- mismatched to the device/session/assignment being processed;
- revoked by an effective revocation signal.

Caches or fixtures cannot silently extend an expired authorization.

An authenticated Agent session must not remain authorized beyond the `expires_at` of the authorization that established it. The Gateway must re-evaluate authorization freshness on a bounded session lifecycle interval and terminate the session fail closed once that authorization is expired, invalid, unavailable, disabled, mismatched, or effectively revoked.

For live projection generations:

- a candidate generation is activated only as one fully validated atomic unit;
- lower/replayed revisions and same-revision/different-content publication are rejected;
- a malformed/incomplete candidate cannot partially mutate active runtime authority;
- the last validated generation may be used only while it remains within both its external freshness deadline and the Gateway's local maximum accepted snapshot age;
- if no fresh validated generation remains, Gateway readiness, new Agent authorization, and new public routing fail closed; existing sessions fail closed through the bounded authorization revalidation lifecycle;
- recovery to a newer valid generation may restore readiness without process restart.

For dynamic public TLS permission:

- unknown, disabled, expired, unverified, malformed, unavailable, or timed-out hostname permission fails closed;
- merely resolving or pointing DNS at the HooshiX Caddy edge does not authorize certificate management;
- certificate permission does not replace Gateway route authorization.

## 7. Explicit exclusions

This contract does not define or implement:

- Control Panel HTTP/gRPC CRUD APIs;
- users/accounts or their sessions;
- tenants/organizations/memberships;
- device-management or enrollment-management CRUD;
- public endpoint-management CRUD;
- quotas, plans, billing, or commercial policy;
- Control Panel database schemas or migrations;
- dashboard/UI models;
- direct Gateway access to a Control Panel database;
- Redis, NATS, Kafka, Kubernetes, or another synchronization datastore/broker.

Fixtures under `contracts/v1/fixtures/` are deterministic stand-ins for the external source so Agent/Gateway contract work can be tested independently.
