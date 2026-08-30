# Tunnel Gateway Runtime — AG-4

**Status:** Current AG-4 runtime contract

The Gateway executable is `cmd/gateway`.

## Runtime boundary

The process owns only ephemeral data-plane state:

- authenticated Agent sessions;
- protocol-v1 sequence/liveness state;
- bounded active logical streams;
- short-lived ingress correlation and traffic counters.

It does not own Control Panel users, tenants, endpoint CRUD, quota/billing logic, persistence, or a Control Panel database.

## Startup

The executable requires all of:

```text
-listen <host:port>
-tls-cert <certificate.pem>
-tls-key <private-key.pem>
-metadata-dir <read-only-snapshot-directory>
```

There is no plaintext production startup mode. The HTTP server enforces TLS >= 1.2.

The AG-4 snapshot adapter exists so the real Gateway can run before a live external Control Panel integration transport is available. It is read-only and non-authoritative.

Snapshot layout:

```text
metadata/
├── authorizations/
│   └── *.json
├── routes/
│   └── *.json
└── revocations/
    └── *.json
```

Records must conform to `contracts/v1/external/` and are revalidated for validity/revocation at use time.

## Routes

- `GET /healthz` — process health only; never authorization authority.
- `/agent/v1/connect` — protocol-v1 WebSocket upgrade for authenticated Agent sessions.
- all other paths — public HTTP ingress resolved by the request Host against validated external route metadata.

The public request cannot provide a raw Agent-local target. The Gateway sends only the external `local_endpoint_id` to the Agent.

## Default resource bounds

```text
agent sessions              1024
pending Agent handshakes     128
streams per Agent session     64
queued inbound frames/stream  16
request body                 8 MiB
response body               32 MiB
request headers             32 KiB
handshake timeout            10 s
read timeout                 15 s
write timeout                10 s
heartbeat interval           15 s
idle timeout                 45 s
shutdown timeout             10 s
```

Protocol-v1 frame bounds remain authoritative from ADR-0007: 64 KiB control payload and 1 MiB data payload.

## Session/authentication behavior

The Gateway:

1. accepts a binary WebSocket session over TLS;
2. validates `client_hello` and external authorization metadata;
3. compares the supplied short-lived token against the external SHA-256 digest using constant-time comparison;
4. sends a fresh challenge/session ID;
5. verifies the Ed25519 challenge signature with the externally supplied device public key;
6. registers one current in-memory session per device;
7. replaces stale session state on a successfully authenticated reconnect;
8. arms a local deadline for the establishing authorization `expires_at`, immediately removes an expired/invalid session from routing, and independently revalidates authorization freshness/revocation on each bounded heartbeat;
9. enforces protocol sequence replay/order checks, heartbeat and resource bounds.

Invalid TLS, token, signature, authorization freshness, protocol framing, replay/order, stream state or resource usage fails closed. Expired or effectively revoked session authorization is signaled with `session_revoked` before closure when the reason is authoritative; transient/unclassified metadata failures close the session without falsely asserting permanent revocation, allowing the Agent reconnect policy to retry safely.

## Public ingress and multiplexing

A valid public Host resolves to an external endpoint-route assignment. If its device has no authenticated session, ingress returns `503`.

The Gateway allocates a non-zero stream ID, sends `stream_open` with only endpoint/assignment/local-endpoint/request identifiers, serializes the public HTTP request as opaque stream bytes, and streams the Agent response back as HTTP.

Multiple requests may use separate bounded streams over one Agent session.

## Status/traffic output

The executable emits versioned JSON-lines `GatewayStatusSignal` records to stdout for session lifecycle and traffic-delta integration. These records are telemetry/integration outputs only and are never authentication, authorization, routing, quota, or billing authority.

## Executable Runtime Gate

`scripts/ci/runtime-gate.sh` builds the real Gateway binary and executes it as a separate process with:

- a generated trusted test certificate;
- a deterministic external metadata snapshot;
- an authenticated protocol-v1 test peer for the Gateway-specific runtime check;
- a real local HTTP service;
- a real HTTPS public request through the Gateway/tunnel;
- TLS/plaintext-startup negative verification.

The Gateway-specific runtime check remains in place. Integrated real Agent↔Gateway acceptance, including restart/reconnect behavior, is defined separately by AG-6 in `docs/runtime/agent-gateway-e2e-acceptance.md`.


## AG-7 deployment and operations

The initial deployment package is now `deploy/gateway/`: Docker Compose runs only the Tunnel Gateway and Caddy public edge. Caddy owns public TLS and forwards to the Gateway over certificate-verified HTTPS using a deployment-local CA; the Gateway itself remains TLS-only and is not published directly on a host port.

The internal Gateway listener also exposes `/readyz` and low-cardinality aggregate `/metrics` in addition to `/healthz`. Caddy blocks `/readyz` and `/metrics` on the public edge. Packaging, diagnostics, certificate bootstrap and release provenance are documented in `docs/runtime/packaging-and-operations.md`.

## R-3 bounded resource model

Gateway resource safety uses both count and byte budgets. The default Agent→Gateway queue limits are 2 MiB per stream, 8 MiB per authenticated session and 32 MiB globally; a payload must reserve all applicable budgets before it is copied into a queue. Public request headers and bodies are now written directly into bounded 32 KiB tunnel chunks; the Gateway no longer retains the full accepted request before forwarding. The global ingress byte budget is reserved only while a chunk is synchronously forwarded, and public ingress remains capped at 32 concurrent requests. Agent handshakes and public ingress also use bounded global token-bucket rates (32/s burst 64 and 256/s burst 512 respectively). Existing session/stream/frame/request limits remain in force.

`/metrics` exposes only aggregate low-cardinality resource gauges/counters for queued bytes, ingress bytes/requests and rejection totals. Device IDs, endpoint IDs and hostnames are never metric labels. The Docker Compose Gateway memory limit remains 256 MiB; authenticated Agent sessions are capped at 64 and the two explicitly retained application payload budgets total 64 MiB and are not preallocated, leaving headroom for transient protocol frames, active response chunks, Go/TLS/WebSocket/runtime overhead and metadata. This is a safety envelope, not a throughput/capacity claim.

## R-4 streaming public ingress

The Gateway preserves the existing HTTP/1 request wire semantics but no longer serializes an accepted public request into a full in-memory buffer. `http.Request.Write` feeds a bounded tunnel writer that fragments every write into at most 32 KiB data chunks, reserves the R-3 global ingress byte budget only for the chunk currently being forwarded, and releases that reservation immediately after the WebSocket write completes. The request context is checked between chunks, so public cancellation/timeout stops forwarding and normal stream teardown releases the remaining resources. `bytes_from_public` continues to count the exact serialized request bytes actually sent as tunnel data, including request line/headers/framing as before. The 8 MiB accepted request-body limit and server header limits remain unchanged.
