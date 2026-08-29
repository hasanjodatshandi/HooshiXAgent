# External HooshiX Control Panel Integration Contract v1

**Status:** Normative

This contract defines only the information boundary consumed/emitted by HooshiXAgent. The HooshiX Control Panel remains a separate external product and durable system of record.

## 1. Integration model

HooshiXAgent runtime code may receive validated copies of four contract record types:

1. `device-session-authorization` — authorizes one device/session credential and provides the device Ed25519 public key plus a digest of the short-lived session token;
2. `endpoint-route-assignment` — maps an externally managed public endpoint to a device and opaque Agent-local `local_endpoint_id`;
3. `revocation-signal` — disables/revokes an authorization, route assignment, or device;
4. `gateway-status-signal` — bounded operational/traffic status emitted from the Gateway toward the external system.

The concrete transport used to exchange these records is deliberately **not** defined in AG-3. A later runtime leaf may implement an adapter, but the adapter must consume these shapes rather than directly coupling the Gateway to a Control Panel database.

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

## 4. Revocation

Revocation signals identify the externally authoritative subject and effective time. A later Gateway runtime implementation must stop relying on revoked authorization/routing state according to its bounded shutdown/session lifecycle.

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

## 7. Explicit exclusions

AG-3 does not define or implement:

- Control Panel HTTP/gRPC CRUD APIs;
- users/accounts or their sessions;
- tenants/organizations/memberships;
- device-management or enrollment-management CRUD;
- public endpoint-management CRUD;
- quotas, plans, billing, or commercial policy;
- Control Panel database schemas or migrations;
- dashboard/UI models;
- direct Gateway access to a Control Panel database.

Fixtures under `contracts/v1/fixtures/` are deterministic stand-ins for the external source so Agent/Gateway contract work can be tested independently.
