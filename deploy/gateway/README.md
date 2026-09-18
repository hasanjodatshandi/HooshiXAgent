# HooshiX Tunnel Gateway Deployment

This directory is the Docker Compose deployment package for the Tunnel Gateway and Caddy public TLS edge only, reconciled through RA-4 multi-host public edge.

It intentionally does **not** contain the external HooshiX Control Panel, a database, users/tenants/quotas, Redis, Kubernetes or any other control-plane service.

## Topology

```text
Internet / Agent WSS :443
          |
        Caddy
   public TLS / ACME
          |
 verified HTTPS using deployment CA
          |
     Tunnel Gateway :8443
          |
 read-only external live metadata projection
```

The Gateway is not published on a host port. Caddy is the only public listener.

## 1. Configure

Copy the environment example:

```bash
cp .env.example .env
```

Production/default Caddy uses the ADR-0011 restricted On-Demand TLS model. Set `HOOSHIX_TLS_ASK_URL` to the external permission endpoint supplied by the Control Panel integration. Caddy appends the requested `domain` query parameter and may manage a certificate only when that endpoint returns `200 OK`. The permission authority must perform exact canonical-hostname authorization and fail closed for unknown, disabled, expired, malformed or unavailable authority; DNS resolution or suffix membership alone is not authorization.

`HOOSHIX_PUBLIC_HOST` remains the explicit static-compatibility/local edge-health hostname. In a dynamic production deployment, choose a currently approved hostname for this health probe. `HOOSHIX_CADDYFILE=./Caddyfile` is the production dynamic configuration. `HOOSHIX_CADDYFILE=./Caddyfile.static` is the explicit single-host compatibility mode and requires `HOOSHIX_PUBLIC_HOST`. Static compatibility must not be used to claim RA-4 multi-host behavior.

The default dynamic Caddyfile is intentionally fail-closed if `HOOSHIX_TLS_ASK_URL` is empty or invalid; there is no unrestricted On-Demand TLS fallback.

### On-Demand TLS issuance rate limiting

The permission authority at `HOOSHIX_TLS_ASK_URL` is the **only** issuance rate limiter in this deployment, so it must enforce one: bound how many issuance decisions a single client address and a single hostname can obtain per unit of time, and answer non-2xx once that bound is exceeded (Caddy treats any non-2xx as a denial and aborts the handshake).

This is a deployment requirement rather than a Caddyfile setting because the pinned `caddy:2.11.4-alpine` image provides no supported mechanism for it. Caddy v2.11.4 accepts only `ask` and `permission` under the `on_demand_tls` global option: `interval` and `burst` are rejected as no longer supported, and there is no `rate_limit` option (nor a global `rate_limit` option). Adding any of them makes `caddy adapt` fail, so the edge would never start — the production Caddyfile therefore contains a comment where a reader would otherwise expect a limit, and `scripts/ci/packaging-ops.sh` adapts the production Caddyfile with a valid ask URL so an unsupported sub-directive is caught in CI instead of in production.

The edge does emit the response-hardening headers (`Strict-Transport-Security` with a 180-day `max-age`, `X-Content-Type-Options: nosniff`, and no `Server` header) in both the production and static compatibility configurations; `scripts/ci/packaging-ops.sh` and `scripts/ci/multi-host-public-edge.sh` assert them.

`HOOSHIX_METADATA_DIR` is a read-only projection supplied by the external Control Panel integration flow. The Compose default is `HOOSHIX_METADATA_MODE=live`, with a 1-second refresh interval and 30-second maximum generation age. Production live layout is:

```text
current.json
generations/<generation>/authorizations/*.json
generations/<generation>/routes/*.json
generations/<generation>/revocations/*.json
```

The publisher writes a complete immutable generation and atomically publishes `current.json` last. `bootstrap-internal-tls.sh` creates the empty metadata/generations directories but deliberately does **not** invent authorization/routing authority. Until an external publisher supplies a valid current generation, Gateway `/healthz` remains live while `/readyz` fails closed and Caddy will not route to it.

`HOOSHIX_METADATA_REFRESH_INTERVAL` and `HOOSHIX_METADATA_MAX_AGE` override the bounded defaults. `HOOSHIX_METADATA_MODE=static` is retained only for explicit compatibility/test/migration use with the legacy flat `authorizations/`, `routes/`, `revocations/` layout and does not provide live-revocation semantics.

No Control Panel database/API/service is mounted or assumed.

## 2. Bootstrap internal TLS

Run:

```bash
./bootstrap-internal-tls.sh
```

This creates a deployment-local CA and a Gateway server certificate whose SAN is `gateway`, matching the Docker service DNS name.

The CA private key remains on the host under the private TLS directory and is **not** mounted into either runtime container. Caddy receives only `ca.crt`; Gateway receives only its certificate/key and CA certificate.
R-9 makes CA bootstrap fail closed if only one of `ca.key` or `ca.crt` exists, if either file is malformed, or if their public keys do not match. Fresh CA material is generated as a temporary key/certificate pair before either final path is installed. Operators must recover or deliberately remove incomplete/mismatched CA state; bootstrap will not silently replace one half of an existing CA pair.

A newly generated CA carries the standard trust-anchor profile (`basicConstraints=critical,CA:TRUE`, `keyUsage=critical,keyCertSign,cRLSign`, `subjectKeyIdentifier`), so strict OpenSSL 3.x clients accept it as a trust anchor; an extension-less CA from an earlier bootstrap is left untouched and must be re-issued if strict verification is required.

Caddy verifies the Gateway certificate with:

```text
tls_trust_pool file /etc/caddy/gateway-ca.pem
tls_server_name gateway
```

Do not replace this with `tls_insecure_skip_verify`.

## 3. Start

```bash
docker compose up -d --build
```

Inspect status:

```bash
./diagnose.sh
```

## Operations

- `/healthz`, `/readyz` and `/metrics` are served on the Gateway's separate administrative listener (`-ops-listen 127.0.0.1:9090`, plaintext, loopback inside the container, not published). They are never served on the public listener, so they can never shadow a tenant route.
- `/readyz` is an internal readiness endpoint and fails closed when live metadata has no fresh validated generation.
- `/metrics` emits low-cardinality aggregate Prometheus text metrics, including live metadata freshness/refresh health.
- Caddy refuses `/readyz` and `/metrics` on the public edge for every hostname as defence in depth. It deliberately does **not** refuse `/healthz`: `/healthz` is one of the most common tenant health paths, and the separate ops listener already removed the Gateway-local shadowing, so an edge refusal would only make a tenant's own `/healthz` unreachable. This is the structural fix for the pre-launch finding that a Gateway-local endpoint had made a tenant's `/healthz` unreachable.
- `-trusted-proxy` (default `172.16.0.0/12`, override with `HOOSHIX_TRUSTED_PROXY`) names the edge that may supply the client address in `X-Forwarded-For`. The Gateway discards every client-supplied forwarding header; only a request whose immediate peer is inside this set contributes the edge-observed client hop to tenant applications. Set it to the actual compose/edge network if your Docker address pool differs, otherwise tenant applications see the edge's address instead of the client's.
- TLS permission is independent from Gateway route authorization: a hostname may be certificate-approved yet still receive Gateway 404 when no current route assignment exists.
- Gateway structured logs go to stderr.
- Gateway integration/status JSONL goes to stdout.
- Caddy access logs are structured JSON on stdout.
- Docker json-file logs are bounded by size/count.

The metrics intentionally contain only aggregate session/stream/handshake/resource gauges and counters. They do not label device IDs, endpoint IDs, tokens or user-controlled hostnames.

### R-3 resource envelope

The Compose profile keeps the Gateway at `mem_limit: 256m` while the application-owned payload budgets are explicitly capped at 32 MiB of queued Agent→Gateway data plus a 32 MiB global public-ingress streaming-chunk budget. Public requests are not retained in full: the ingress budget is held only for bounded chunks while they are synchronously forwarded. These budgets are not preallocated; together they cap the explicit application payload reservations at 64 MiB and leave the remaining container memory for Go/runtime, WebSocket/TLS, metadata, stacks and ordinary request overhead. Each stream may queue at most 2 MiB and each Agent session at most 8 MiB, regardless of the existing frame-count/stream-count ceilings.

The same profile bounds public ingress to 32 concurrent requests with a global 256 requests/second rate and 512-request burst, and Agent sessions to 64 authenticated connections and Agent handshakes to 64 concurrent handshakes with a global 32/second rate and 64-handshake burst. Pre-authentication Agent connections are separately throttled per trusted peer (16/second, burst 32) before any pending-handshake slot is taken, so a peer that opens sockets and stalls in the unauthenticated preface cannot cycle the bounded slots. Saturation/rejection counters are exposed on the internal `/metrics` endpoint. These are safety defaults, not capacity claims. R-12 measured synthetic 100/500/1000 scenarios and retained the shipped defaults; any larger production envelope requires representative capacity evidence.

### R-10 container runtime envelope

Both Gateway and Caddy have explicit 256 MiB memory, 1 CPU and 256-PID safety ceilings. These are fail-safe deployment ceilings, not throughput claims; R-12 synthetic results do not override this deployment envelope. Both root filesystems are read-only, `/tmp` is a bounded `noexec,nosuid,nodev` tmpfs, `no-new-privileges` is mandatory, host PID/IPC/network namespaces and device passthrough are not used, and all ambient Linux capabilities are dropped.

Gateway continues as UID/GID `10001:10001` with **no** added capability. Caddy also runs as UID/GID `10001:10001`; its sole added capability is `NET_BIND_SERVICE`, required to own public ports 80/443. Caddy's persistent `/data` and `/config` named volumes are its only writable persistent mounts. Dynamic certificates for approved hostnames remain in `/data`; an unapproved hostname must never appear there as a result of On-Demand TLS.

All host bind mounts are read-only and use `create_host_path: false`, so a missing metadata/TLS/Caddyfile source fails startup instead of being silently created by Compose. The host TLS directory remains mode `0700`; `ca.key` is never mounted. Gateway receives only its server key/certificate plus the CA certificate, and Caddy receives only the public CA certificate.

Gateway's Compose healthcheck uses the administrative readiness endpoint (`http://127.0.0.1:9090/readyz`), so a container is healthy only when its own liveness/readiness listener answers; Caddy waits for that health state before starting. Caddy's own container healthcheck verifies its local HTTPS edge certificate against the concatenated trust roots and accepts any HTTP response (it probes a neutral path, not `/healthz` or `/readyz`), so it asserts TLS termination and edge liveness rather than a particular status code; in dynamic mode that health hostname must be included in the external certificate-permission authority. `/readyz` and `/metrics` remain refused on the public edge, while `/healthz` stays an ordinary tenant path.

## Upgrade and rollback

For a source checkout deployment:

1. record the currently running Git/release version;
2. pull/checkout the new attested release;
3. run `docker compose build gateway`;
4. run `docker compose up -d`;
5. run `./diagnose.sh`;
6. if health/diagnostics fail, checkout the previous attested release and repeat build/up.

Clean deployment and deterministic previous-version rollback are verified by the packaging gate. AG-8 additionally verifies forced transport interruption/recovery, package rollback, release checksums and deliberate artifact-tamper rejection before a release-ready claim.

## TLS/certificate operations

Public certificate lifecycle is owned by Caddy, but first-time dynamic certificate authority is restricted by `HOOSHIX_TLS_ASK_URL`. The external permission service is not bundled in this repository and no Control Panel CRUD/database/business logic is added here. Cached approved certificates may continue to terminate TLS if the permission service later becomes unavailable, while Gateway still independently enforces current route metadata for every request. The internal Gateway certificate is intentionally shorter lived than the deployment CA. Rotate it by rerunning `bootstrap-internal-tls.sh` and restarting the two services. Keep `ca.key` host-private and backed up according to operator secret-management policy.

## Shutdown

```bash
docker compose down
```

Caddy data/config volumes are preserved unless explicitly removed. External metadata and TLS directories are host-managed and are not deleted by `docker compose down`.
