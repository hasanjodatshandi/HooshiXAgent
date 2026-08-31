# HooshiXAgent

HooshiXAgent is the Go repository for the installable **Edge Agent**, the server-side **Tunnel Gateway**, and the minimum shared/language-neutral contracts required for those components to interoperate with the separate HooshiX Control Panel.

The **HooshiX Control Panel is external**. This repository does not implement users, tenants, enrollment-management services, endpoint CRUD, quotas, billing, Control Panel APIs/UI, or Control Panel persistence.

## Current implemented product

```text
Internet -> Caddy -> verified HTTPS -> Tunnel Gateway -> outbound WSS/TLS Agent session -> approved loopback service
```

The current repository contains:

```text
cmd/agent/                 runnable Edge Agent
cmd/gateway/               runnable Tunnel Gateway
internal/agent/            Agent runtime, state, policy and packaging support
internal/gateway/          Gateway runtime, routing, resource and HTTP proxy logic
internal/contractv1/       strict Go reference implementation of protocol/contracts
contracts/v1/              language-neutral protocol + external integration contracts
deploy/gateway/            hardened two-service Docker Compose deployment
packaging/agent/           Linux/macOS/Windows Agent package tooling
scripts/ci/                quality, security, runtime, E2E, release and capacity gates
```

Architecture authority remains `docs/architecture/agent-gateway-architecture-contract.md` plus the Accepted ADRs in `docs/adr/decision-register.md`. The reconciled implementation/limits/failure-semantics summary is `docs/engineering/current-state.md`.

## Security and routing boundary

Each Agent installation owns a unique Ed25519 identity. Its private key remains local to the device. The Agent establishes only outbound `wss://` connectivity and resolves an opaque `local_endpoint_id` through its own approved local mapping.

Allowed local hosts are limited to `127.0.0.0/8`, `::1`, and literal `localhost`. The Gateway/public side cannot provide a raw Agent-local IP, URL, file path, socket, pipe or arbitrary DNS target. External Control Panel data is consumed through versioned authorization/route/revocation contracts; the Gateway does not use a Control Panel database directly.

## Current production safety defaults

The shipped Gateway defaults remain deliberately bounded after R-12 capacity testing:

- 64 authenticated Agent sessions;
- 64 pending handshakes;
- 64 streams per Agent session;
- 32 concurrent public ingress requests;
- 2 MiB queued Agent→Gateway bytes per stream, 8 MiB per session, 32 MiB globally;
- 32 MiB global public-ingress streaming-byte budget;
- 32 handshakes/second with burst 64;
- 256 public requests/second with burst 512;
- 8 MiB request body, 32 MiB response body, 32 KiB HTTP header bound.

The Docker Compose profile keeps both Gateway and Caddy at 256 MiB memory, 1 CPU and 256 PIDs with non-root/read-only/no-new-privileges/capability-minimized runtime settings. These are **safety limits, not throughput guarantees**.

## Runtime, packaging and recovery

The Agent supports persistent identity/configuration, explicit local exposure mappings, `status`, `doctor`, native user-scoped persistence definitions and packaged rollback. Release packages are built for Linux/macOS/Windows on amd64/arm64.

The server deployment remains **Docker Compose only**, with exactly Caddy and Tunnel Gateway. Caddy owns public ports/TLS and verifies the Gateway over deployment-local CA trust. The CA private key remains host-only.

The tested system includes real Agent↔Gateway E2E traffic, Gateway restart recovery, Agent process restart with persisted identity, forced tunnel-network interruption/reconnect, fail-closed offline behavior, package rollback, release checksum tamper rejection, SBOM/vulnerability scanning and OIDC-backed GitHub Artifact Attestations.

## Verification entry points

```bash
scripts/ci/go-quality.sh
scripts/ci/security.sh
scripts/ci/runtime-gate.sh
scripts/ci/e2e-acceptance.sh
scripts/ci/packaging-ops.sh
scripts/ci/release-gate.sh
scripts/ci/comprehensive-tests.sh
scripts/ci/performance-capacity.sh
```

CI additionally enforces architecture fitness, R-3 through R-12 focused hardening gates, Ubuntu/Windows/macOS Agent package tests, the AG-9 prototype smoke, and the dependency-chained final Agent/Gateway release gate.

## Capacity evidence

R-12 successfully exercises synthetic 100/500/1000 request-stream and resident-session scenarios, repeated benchmarks, a sustained soak, and CPU/heap/block/mutex profiles. Those tests show implementation headroom but do **not** reproduce Internet RTT, thousands of physical Agent hosts, heterogeneous localhost services, Caddy public TLS cost, or every production container constraint.

Production defaults were therefore **not raised** from synthetic results. Operators who need a larger envelope must repeat the R-12 methodology on representative deployment hardware and workloads.

## Documentation map

- `docs/engineering/current-state.md` — reconciled post-hardening current state and R-0..R-12 summary.
- `docs/runtime/agent.md` — Agent runtime/state/security behavior.
- `docs/runtime/gateway.md` — Gateway runtime, limits and failure semantics.
- `docs/runtime/agent-gateway-e2e-acceptance.md` — integrated real-process acceptance.
- `docs/runtime/packaging-and-operations.md` — packages, Compose deployment and release operations.
- `docs/runtime/security-resilience-release-gate.md` — release security/resilience acceptance.
- `docs/engineering/quality-enforcement-map.md` — current blocking quality/security gate map.
- `docs/engineering/performance-capacity-gate.md` — R-12 methodology and evidence.
- `docs/governance/plan-roadmap-scope-lock.md` — scope/execution lock and roadmap ordering.

Historical ADR text is preserved as decision provenance; current implementation documentation does not rewrite those historical decision records.
