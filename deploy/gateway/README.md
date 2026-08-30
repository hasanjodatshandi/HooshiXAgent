# HooshiX Tunnel Gateway Deployment

This directory is the AG-7 Docker Compose deployment package for the Tunnel Gateway and Caddy public TLS edge only.

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
 read-only external metadata snapshots
```

The Gateway is not published on a host port. Caddy is the only public listener.

## 1. Configure

Copy the environment example:

```bash
cp .env.example .env
```

Set `HOOSHIX_PUBLIC_HOST` to a DNS name whose A/AAAA record points at the deployment host. Caddy performs public certificate automation for that name.

`HOOSHIX_METADATA_DIR` is a read-only snapshot supplied by the external Control Panel integration flow. Its layout remains:

```text
authorizations/*.json
routes/*.json
revocations/*.json
```

No Control Panel database is mounted or assumed.

## 2. Bootstrap internal TLS

Run:

```bash
./bootstrap-internal-tls.sh
```

This creates a deployment-local CA and a Gateway server certificate whose SAN is `gateway`, matching the Docker service DNS name.

The CA private key remains on the host under the private TLS directory and is **not** mounted into either runtime container. Caddy receives only `ca.crt`; Gateway receives only its certificate/key and CA certificate.

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

- `/healthz` is the Gateway liveness endpoint.
- `/readyz` is an internal readiness endpoint.
- `/metrics` emits low-cardinality aggregate Prometheus text metrics.
- Caddy blocks `/readyz` and `/metrics` on the public edge.
- Gateway structured logs go to stderr.
- Gateway integration/status JSONL goes to stdout.
- Caddy access logs are structured JSON on stdout.
- Docker json-file logs are bounded by size/count.

The metrics intentionally contain only aggregate session/stream/handshake/resource gauges and counters. They do not label device IDs, endpoint IDs, tokens or user-controlled hostnames.

### R-3 resource envelope

The Compose profile keeps the Gateway at `mem_limit: 256m` while the application-owned payload budgets are explicitly capped at 32 MiB of queued Agent→Gateway data plus 32 MiB of serialized public-ingress data. These budgets are not preallocated; together they cap those explicitly retained payload buffers at 64 MiB and leave the remaining container memory for Go/runtime, WebSocket/TLS, metadata, stacks and ordinary request overhead. Each stream may queue at most 2 MiB and each Agent session at most 8 MiB, regardless of the existing frame-count/stream-count ceilings.

The same profile bounds public ingress to 32 concurrent requests with a global 256 requests/second rate and 512-request burst, and Agent sessions to 64 authenticated connections and Agent handshakes to 64 concurrent handshakes with a global 32/second rate and 64-handshake burst. Saturation/rejection counters are exposed on the internal `/metrics` endpoint. These are safety defaults, not capacity claims; R-12 owns evidence-based production capacity tuning.

## Upgrade and rollback

For a source checkout deployment:

1. record the currently running Git/release version;
2. pull/checkout the new attested release;
3. run `docker compose build gateway`;
4. run `docker compose up -d`;
5. run `./diagnose.sh`;
6. if health/diagnostics fail, checkout the previous attested release and repeat build/up.

Final destructive/network interruption rollback acceptance remains AG-8. AG-7 verifies the clean deployment and deterministic previous-version rollback procedure without claiming final release readiness.

## TLS/certificate operations

Public certificate lifecycle is owned by Caddy. The internal Gateway certificate is intentionally shorter lived than the deployment CA. Rotate it by rerunning `bootstrap-internal-tls.sh` and restarting the two services. Keep `ca.key` host-private and backed up according to operator secret-management policy.

## Shutdown

```bash
docker compose down
```

Caddy data/config volumes are preserved unless explicitly removed. External metadata and TLS directories are host-managed and are not deleted by `docker compose down`.
