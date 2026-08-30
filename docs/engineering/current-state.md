# HooshiXAgent Current State

**Status:** Current implementation summary reconciled by R-13

This document describes the implemented Agent/Gateway system after R-0 through R-12. It is a current-state summary, not a replacement for the normative protocol contracts or Accepted ADRs.

## Product and trust boundary

HooshiXAgent owns only:

- the Go Edge Agent;
- the Go Tunnel Gateway;
- shared/language-neutral Agent↔Gateway and minimum external Control Panel integration contracts.

The separate HooshiX Control Panel remains external and owns durable users/accounts, tenants/organizations, device/enrollment management, public endpoint management, quotas/plans/billing, Control Panel APIs/UI and control-plane persistence.

The runtime path is:

```text
Internet -> Caddy -> verified HTTPS -> Gateway -> outbound WSS/TLS Agent session -> approved loopback service
```

Each Agent install owns a unique Ed25519 identity whose private key remains on the device. The external/public side can select only an opaque `local_endpoint_id`; final target authority remains Agent-local and loopback-only.

## Implemented hardening state

| Leaf | Current implemented result |
| --- | --- |
| R-0 | Regression baseline captured authorization expiry, exact sequencing, invalid UTF-8 and duplicate JSON-key failures before fixes. |
| R-1 | Authenticated sessions fail closed on authorization expiry, invalid/unavailable authorization and effective revocation. |
| R-2 | Protocol requires exact next sequence, rejects invalid UTF-8/duplicate keys, and terminates before sequence wrap. |
| R-3 | Explicit stream/session/global byte budgets plus bounded handshake/ingress concurrency and rates. |
| R-4 | Public request bodies stream through bounded tunnel chunks instead of whole-request buffering. |
| R-5 | Safe per-stream resource failures are isolated; hop-by-hop headers, response-header/body limits and terminal ordering are explicit. |
| R-6 | Exact-commit release eligibility, immutable Action/image pins, privilege separation, SBOM, vulnerability scanning and provenance checks. |
| R-7 | Typed/indexed deterministic metadata snapshots, duplicate rejection, indexed revocations and fail-closed readiness. |
| R-8 | Bounded asynchronous telemetry and single-writer control-priority scheduling for Agent/Gateway WebSockets. |
| R-9 | Strict config/secret JSON EOF, concurrent mutation lock, state ownership/destructive path guards, CA bootstrap and entropy error hardening. |
| R-10 | Non-root/read-only/capability-minimal/resource-bounded two-service Compose runtime. |
| R-11 | Expanded fuzz, race, reconnect/slow-path/load-oriented scenarios and informational coverage artifacts. |
| R-12 | Reproducible capacity/load/soak/profile evidence; handshake-slot lifetime defect fixed; production defaults intentionally unchanged. |

## Current Agent defaults

From `internal/agent.DefaultLimits()`:

| Limit | Default |
| --- | ---: |
| Active streams/session | 64 |
| Queued inbound frames/stream | 16 |
| Queued bytes/stream | 2 MiB |
| Queued bytes/session | 8 MiB |
| Local dial timeout | 5 s |
| Handshake timeout | 10 s |
| Write timeout | 10 s |
| Reconnect backoff | 1–30 s |

The Agent accepts only `127.0.0.0/8`, `::1`, or literal `localhost` targets with explicit TCP ports. Arbitrary DNS targets, LAN/link-local/metadata addresses, schemes, paths, named pipes and Unix sockets are rejected.

## Current Gateway defaults

From `internal/gateway.DefaultLimits()`:

| Limit | Default |
| --- | ---: |
| Authenticated Agent sessions | 64 |
| Pending Agent handshakes | 64 |
| Streams/session | 64 |
| Queued frames/stream | 16 |
| Queued Agent→Gateway bytes/stream | 2 MiB |
| Queued Agent→Gateway bytes/session | 8 MiB |
| Global queued Agent→Gateway bytes | 32 MiB |
| Public ingress in flight | 32 |
| Global public-ingress streaming-byte budget | 32 MiB |
| Handshake rate / burst | 32/s / 64 |
| Public ingress rate / burst | 256/s / 512 |
| Request body | 8 MiB |
| Response body | 32 MiB |
| HTTP header bound | 32 KiB |
| Async status queue | 256 signals |
| Status export timeout | 2 s |
| Handshake timeout | 10 s |
| HTTP read timeout | 15 s |
| Tunnel/public write timeout base | 10 s |
| Heartbeat interval | 15 s |
| Session idle timeout | 45 s |
| Shutdown timeout | 10 s |

Protocol v1 separately bounds control payloads to 64 KiB and data payloads to 1 MiB.

## Deployment envelope

`deploy/gateway/docker-compose.yml` contains exactly Gateway and Caddy. Both run as numeric UID/GID `10001:10001`, with read-only root filesystems, bounded hardened `/tmp`, `no-new-privileges`, all ambient capabilities dropped and explicit ceilings of:

```text
memory: 256 MiB
CPU:    1
PIDs:   256
```

Gateway adds no Linux capabilities. Caddy adds only `NET_BIND_SERVICE`. Host bind mounts are read-only and refuse implicit source creation. The deployment CA private key remains host-only.

These values are defensive ceilings. They are not a statement that 64 sessions, 256 requests/second, or any synthetic R-12 level is a production SLO.

## Failure semantics

Current important fail-closed behavior includes:

- unknown public hostname -> `404`;
- valid route with no authenticated Agent -> `503`;
- malformed/expired/disabled/revoked authorization -> authentication or active session fails closed;
- malformed frame, sequence violation or session-scope protocol violation -> session termination;
- safe per-stream queue/resource failure -> affected stream fails without terminating unrelated streams;
- unapproved `local_endpoint_id` -> Agent cannot dial a local service;
- known response `Content-Length` above the response limit -> `502` before a success response is committed;
- unknown/chunked response that exceeds the response-body limit -> public response is aborted rather than reported as a clean truncated success;
- malformed/duplicate metadata snapshot structure -> startup/readiness fails closed;
- telemetry exporter blockage -> bounded drops/failure counters rather than blocking auth/request/session critical paths.

## Release and operational evidence

The blocking CI chain includes Go quality/vulnerability, three Agent platform jobs, architecture, Gitleaks/Semgrep, R-3 through R-12 gates, real Agent↔Gateway E2E, packaging/clean deployment, executable runtime and the final Agent/Gateway release gate.

Release publication additionally requires successful CI for the exact tagged commit on `main`, then builds/scans/checksums the candidate, generates SPDX SBOMs, creates OIDC-backed GitHub Artifact Attestations, verifies repository identity and gives `contents: write` only to the final publish job.

The Agent does not autonomously download/apply updates. Promotion and rollback use explicitly verified packages.

## R-12 capacity interpretation

R-12 uses test-only raised count/rate limits to exercise 32/100/500/1000 concurrent tunneled request-streams and 64/100/500/1000 resident authenticated sessions. It also records allocation benchmarks, a sustained soak and CPU/heap/block/mutex profiles.

The merged-main R-12 artifact for merge `0e3d299e493b41e48c98616253e677b4f62893d9` on a GitHub-hosted Linux runner with four logical CPUs recorded three 1000-request p99 samples around **1.027–1.071 s**, three 1000-session connection samples around **2.71–2.78 s** (about **360–369 sessions/s**), and ordinary round-trip benchmark samples around **156–161 µs/op**. These results are synthetic evidence only.

They do not reproduce Internet RTT, many physical Agent hosts, Caddy public-edge cost, heterogeneous local services, or every 1-CPU/256-MiB production condition. R-12 therefore retained all shipped production defaults.

## Roadmap boundary

This R-13 reconciliation changes documentation only; it does not change architecture, protocol, runtime behavior or production limits. Historical ADRs remain unchanged as decision provenance.

After R-13 completes its normal branch/PR/merge/post-merge lifecycle, the Durable Plan orders only **R-14 — Final Security, Architecture and Performance Re-audit** after it. The exact actionable leaf is always determined by `plan.resume`/`plan.next`, not by this static document.
