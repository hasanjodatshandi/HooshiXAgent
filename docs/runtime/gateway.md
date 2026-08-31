# Tunnel Gateway Runtime — AG-4

**Status:** Current runtime contract (origin AG-4; reconciled through R-13)

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

The current external integration adapter is a read-only filesystem snapshot. It is non-authoritative: durable Control Panel state remains external, and no direct Control Panel database coupling is introduced.

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

Records must conform to `contracts/v1/external/`. R-7 loads each authorization and route into a typed, strictly validated in-memory snapshot exactly once, rejects duplicate JSON object members, rejects duplicate `authorization_id` values and duplicate canonical public hostnames, and indexes revocation state by `(subject_kind, subject_id)`. Static record structure/timestamps are validated at snapshot load while enabled/disabled state, validity windows and revocation effective times remain evaluated at use time. Invalid snapshot content fails process startup through `LoadSnapshotDirectory`; if an already-constructed metadata source reports an unusable state, `/readyz` fails closed with `503 {"status":"not_ready"}` while `/healthz` remains process-health only.

## Routes

- `GET /healthz` — process health only; never authorization authority.
- `/agent/v1/connect` — protocol-v1 WebSocket upgrade for authenticated Agent sessions.
- all other paths — public HTTP ingress resolved by the request Host against validated external route metadata.

The public request cannot provide a raw Agent-local target. The Gateway sends only the external `local_endpoint_id` to the Agent.

## Default resource bounds

```text
agent sessions                        64
pending Agent handshakes               64
streams per Agent session              64
queued inbound frames/stream           16
queued Agent→Gateway bytes/stream    2 MiB
queued Agent→Gateway bytes/session   8 MiB
global queued Agent→Gateway bytes   32 MiB
public ingress in flight               32
public ingress streaming-byte budget 32 MiB
handshake rate / burst              32/s / 64
public ingress rate / burst        256/s / 512
request body                          8 MiB
response body                        32 MiB
request headers                      32 KiB
status queue                         256 signals
status export timeout                  2 s
handshake timeout                     10 s
read timeout                          15 s
write timeout                         10 s
heartbeat interval                    15 s
idle timeout                          45 s
shutdown timeout                      10 s
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
7. atomically installs the successfully authenticated reconnect as the current device session, releases the global session-registry lock, and only then closes the replaced WebSocket so a slow close handshake cannot stall unrelated session lookup/registration;
8. arms a local deadline for the establishing authorization `expires_at`, immediately removes an expired/invalid session from routing, and independently revalidates authorization freshness/revocation on each bounded heartbeat;
9. enforces protocol sequence replay/order checks, heartbeat and resource bounds.

Invalid TLS, token, signature, authorization freshness, protocol framing, replay/order, stream state or resource usage fails closed. Expired or effectively revoked session authorization is signaled with `session_revoked` before closure when the reason is authoritative; transient/unclassified metadata failures close the session without falsely asserting permanent revocation, allowing the Agent reconnect policy to retry safely.

Gateway security-sensitive IDs/nonces are generated from an injected `io.Reader` whose production source is `crypto/rand.Reader`. Entropy failure returns a normal fail-closed operation error: authentication cannot complete without a fresh session ID/nonce, stream creation cannot complete without a request ID, and heartbeat entropy failure terminates that session. There is no weak-random fallback and no process-wide panic. Status telemetry ID generation failure drops only that telemetry signal and is logged because telemetry is not authentication/routing authority.

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

The Gateway-specific runtime check remains in place. Integrated real Agent↔Gateway acceptance, including restart/reconnect behavior, is defined separately in `docs/runtime/agent-gateway-e2e-acceptance.md`; release-level interruption/recovery acceptance is in `docs/runtime/security-resilience-release-gate.md`.


## RA-1 Gateway drain and process shutdown

On `SIGINT`/`SIGTERM`, the Gateway enters draining state before HTTP server shutdown. Draining makes `/readyz` fail with `503` and rejects new Agent handshakes and new public ingress with `503`, while `/healthz` continues to represent process liveness. The HTTP server is then given the existing bounded `shutdown timeout` to finish ordinary in-flight HTTP requests. Because Go HTTP shutdown does not own upgraded WebSocket connections, the Gateway separately snapshots and removes current Agent sessions from routing and concurrently sends WebSocket `GoingAway` closes outside the global session-registry lock. If graceful WebSocket close does not finish before the same shutdown context expires, the remaining connections are force-closed. Active stream waiters are failed with a shutdown error before session close. No shutdown timeout/default capacity value is increased by RA-1.

The real Agent-to-Gateway E2E restart check now requires the Gateway process to exit cleanly after its interrupt within the harness deadline; the test no longer silently treats a forced kill as successful graceful shutdown. The already-running Agent must then reconnect to the restarted Gateway and restore the route.

## AG-7 deployment and operations

The initial deployment package is now `deploy/gateway/`: Docker Compose runs only the Tunnel Gateway and Caddy public edge. Caddy owns public TLS and forwards to the Gateway over certificate-verified HTTPS using a deployment-local CA; the Gateway itself remains TLS-only and is not published directly on a host port.

The internal Gateway listener also exposes `/readyz` and low-cardinality aggregate `/metrics` in addition to `/healthz`. Caddy blocks `/readyz` and `/metrics` on the public edge. Packaging, diagnostics, certificate bootstrap and release provenance are documented in `docs/runtime/packaging-and-operations.md`.

## R-3 bounded resource model

Gateway resource safety uses both count and byte budgets. The default Agent→Gateway queue limits are 2 MiB per stream, 8 MiB per authenticated session and 32 MiB globally; a payload must reserve all applicable budgets before it is copied into a queue. Public request headers and bodies are now written directly into bounded 32 KiB tunnel chunks; the Gateway no longer retains the full accepted request before forwarding. The global ingress byte budget is reserved only while a chunk is synchronously forwarded, and public ingress remains capped at 32 concurrent requests. Agent handshakes and public ingress also use bounded global token-bucket rates (32/s burst 64 and 256/s burst 512 respectively). Existing session/stream/frame/request limits remain in force.

`/metrics` exposes only aggregate low-cardinality resource gauges/counters for queued bytes, ingress bytes/requests and rejection totals. Device IDs, endpoint IDs and hostnames are never metric labels. The Docker Compose Gateway memory limit remains 256 MiB; authenticated Agent sessions are capped at 64 and the two explicitly retained application payload budgets total 64 MiB and are not preallocated, leaving headroom for transient protocol frames, active response chunks, Go/TLS/WebSocket/runtime overhead and metadata. This is a safety envelope, not a throughput/capacity claim.

## RA-2 admission-control and DoS isolation

Public ingress now resolves and validates the external Host route and confirms that its device has a live authorized session **before** consuming the global public-ingress rate or concurrency budgets. Invalid/no-route and offline-route traffic therefore cannot spend tunnel-admission slots or global tunnel-rate tokens that are needed by an active valid route. Request-size rejection remains an earlier cheap bound.

For valid online routes, the existing global hard ceilings remain authoritative and unchanged. RA-2 adds internal low-cardinality route- and device-key admission state using only validated external assignment/device IDs. An uncontended route/device may still use the full configured global ingress ceiling. Once another valid key is observed contending, the noisy key is temporarily constrained to a derived fair share, so it cannot immediately reacquire all released concurrency or all refilled rate capacity; the neighboring route/device can make progress on retry. This adaptive state does not add user-controlled metric labels and all fairness rejections continue to roll into the aggregate ingress rejection counter.

Agent handshake admission keeps the existing `64` global pending-handshake ceiling and `32/s` burst-`64` validated-handshake rate. The global rate token is now consumed only after a structurally valid `client_hello` resolves to current authorization metadata and its session token matches. The initial unauthenticated WebSocket preface has a bounded sub-deadline (one quarter of the existing handshake timeout, capped at 2 seconds) so silent pre-auth sockets release pending-handshake slots well before the full authentication timeout. After metadata/token validation, a single device is limited to a derived three-quarter share of pending/rate capacity, reserving global headroom for other authorized devices. The original global ceilings remain unchanged and still fail closed.

## R-4 streaming public ingress

The Gateway preserves the existing HTTP/1 request wire semantics but no longer serializes an accepted public request into a full in-memory buffer. `http.Request.Write` feeds a bounded tunnel writer that fragments every write into at most 32 KiB data chunks, reserves the R-3 global ingress byte budget only for the chunk currently being forwarded, and releases that reservation immediately after the WebSocket write completes. The request context is checked between chunks, so public cancellation/timeout stops forwarding and normal stream teardown releases the remaining resources. `bytes_from_public` continues to count the exact serialized request bytes actually sent as tunnel data, including request line/headers/framing as before. The 8 MiB accepted request-body limit and server header limits remain unchanged.

## R-5 HTTP proxy correctness and stream isolation

Tunnel stream resource failures are isolated where protocol safety permits. Agent→Gateway response-queue exhaustion terminates only the affected logical stream with `stream_error: resource_limit`; the authenticated Agent session and unrelated streams remain live. Data racing a terminal control for a previously opened Gateway-owned stream is rejected at stream scope, while truly unknown/future stream IDs remain protocol violations. Session-wide authentication, sequence and malformed-control failures remain session-fatal.

Public request and tunneled response hop-by-hop headers are removed explicitly, including headers nominated by `Connection`. The existing `MaxHeaderBytes` value is also the explicit tunneled response status-line/header-section bound. Known positive `Content-Length` values above `MaxResponseBytes` return `502` before a success status is committed. Chunked or otherwise unknown-length bodies may stream up to `MaxResponseBytes`; if any additional body byte exists, the Gateway aborts the public HTTP response rather than completing a clean truncated success. Premature body failure after a status is committed is likewise aborted. Stream terminal ownership is single-shot so peer close/error or a local resource/protocol error cannot later be followed by a contradictory local `completed` terminal signal.

## R-7 metadata scalability and determinism

The read-only snapshot adapter no longer retains raw authorization/route JSON for repeated parsing on every authentication or public request. It stores typed records with parsed validity-window boundaries and performs map lookup by authorization ID and canonical hostname. Revocations are reduced to the earliest effective time per unique `(subject_kind, subject_id)`, so repeated revocation events for one subject do not grow the runtime revocation index. This preserves fail-closed semantics because a subject is considered revoked once the earliest event becomes effective.

Snapshot load is deterministic and fail-closed: strict JSON rejects unknown fields, duplicate object member names and malformed timestamps; duplicate authorization IDs and canonical host routes reject the whole snapshot rather than allowing filename/order-dependent overwrite behavior. Structurally valid records may be currently expired, future-dated or disabled without making the snapshot itself malformed; those dynamic authorization/route conditions are checked at the exact use time. `scripts/ci/metadata-scalability.sh` covers malformed/duplicate negatives, use-time expiry/revocation behavior, readiness failure and a 100,000-subject lookup benchmark with allocation reporting.

## R-8 observability and tunnel writer isolation

Gateway status/traffic signals are exported through a bounded asynchronous worker instead of calling the external `StatusSink` from authentication, session, or public-request critical paths. The default queue holds at most 256 typed status signals. Producers perform a non-blocking enqueue; when the queue is full the signal is dropped and counted rather than delaying tunnel work. Each export attempt receives a 2-second context deadline, and exporter failures are counted separately. Shutdown performs only a bounded best-effort flush; incomplete telemetry flush is logged and does not convert an otherwise clean Gateway shutdown into a runtime failure.

`/metrics` exposes only aggregate unlabeled telemetry health: `hooshix_gateway_status_queue_depth`, `hooshix_gateway_status_queue_limit`, `hooshix_gateway_status_dropped_total`, and `hooshix_gateway_status_export_failures_total`. Device IDs, endpoint IDs, session IDs, hostnames, event IDs, and status kinds are not metric labels. Status records remain integration telemetry only and never become authentication, routing, quota, or billing authority.

After authentication, each Gateway session has exactly one outbound WebSocket writer goroutine. Control frames use a bounded 32-entry queue and data frames use a bounded 2-entry queue. Sequence numbers are assigned only by that writer immediately before encoding/writing, preserving the single-writer invariant and exact sequence order. When data and control are both waiting, control is serviced first at the next frame boundary; an already-running WebSocket data-frame write is not preempted and may delay control only until that bounded frame write completes or the existing write timeout fires. Handshake frames remain direct writes because the handshake is single-threaded and precedes session data traffic.

`scripts/ci/observability-writer.sh` exercises a blocked exporter under a 1,000-signal burst, aggregate drop/failure metrics, control-vs-data writer ordering on both Gateway and Agent, exact outbound sequence progression, single-writer concurrency, and repeated race-detector runs. This gate is about bounded critical-path behavior and writer isolation; it is not a throughput or capacity claim.
