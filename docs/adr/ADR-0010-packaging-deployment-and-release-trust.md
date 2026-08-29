# ADR-0010: Agent Packaging, Gateway Deployment and Release Trust

Status: Accepted
Date: 2026-08-29

## Context

AG-7 must turn the already accepted Agent/Gateway runtime into installable and operable packages without changing the external Control Panel boundary or pulling AG-8 final release-hardening work forward.

The current architecture already fixes Caddy as the MVP public TLS edge, Docker Compose as the initial server deployment form, the Gateway as a TLS-only process, per-user Agent secret ownership, and a later signed release/update workflow.

AG-7 therefore needs the concrete packaging topology, Agent persistence model, internal Caddy→Gateway TLS trust, and release provenance/signing trust.

## Decision

### Agent packaging and persistence

The MVP Agent is distributed as versioned platform archives containing the real `hooshix-agent` binary plus install/uninstall tooling.

Default installation is user-scoped so the installed process runs as the same OS user that owns Agent state and secret storage:

- Linux: user binary plus a `systemd --user` unit when systemd user services are available.
- macOS: user binary plus a LaunchAgent.
- Windows: per-user binary plus a logon Scheduled Task.

This preserves the existing Unix per-user state ownership and Windows DPAPI CurrentUser trust boundary. AG-7 does not change DPAPI to machine scope and does not require a password-bearing Windows service account.

Installers support an explicit no-service/no-persistence mode for deterministic clean-install tests and constrained environments. Upgrade installation preserves one previous binary that can be restored by the packaged rollback operation.

### Gateway deployment

The initial Gateway server deployment is Docker Compose and contains only:

- the HooshiX Tunnel Gateway container;
- Caddy as the public edge/TLS component;
- mounted external metadata snapshots;
- mounted Gateway internal TLS material;
- bounded container/logging/resource configuration.

No Control Panel service, database, queue, Redis, Kubernetes, or unrelated infrastructure is bundled.

Caddy uses the official pinned `caddy:2.11.4-alpine` image. The Gateway image builds with Go 1.27.0 and runs from a minimal pinned Alpine 3.24 base.

Caddy owns public certificate automation. Caddy→Gateway traffic also remains TLS verified. Deployment bootstrap creates a private deployment CA and a Gateway certificate with the Docker service DNS name `gateway`; Caddy receives only the CA certificate and verifies the Gateway certificate with an explicit trust pool and TLS server name. `tls_insecure_skip_verify` is forbidden.

The Gateway container is not published directly on a host port; only Caddy publishes the public edge. Gateway metadata and TLS inputs are read-only mounts.

### Operational observability and diagnostics

The Gateway retains structured JSON logs and GatewayStatusSignal JSONL telemetry and adds bounded operational endpoints on the internal Gateway listener:

- `/healthz` for process liveness;
- `/readyz` for process/config readiness;
- `/metrics` for low-cardinality Prometheus text metrics covering current authenticated sessions, active streams, and pending handshakes.

The deployment Caddy configuration does not expose `/readyz` or `/metrics` on the public edge. Operational scripts query those endpoints from the internal deployment network.

Caddy emits structured access logs to stdout. Docker logging uses bounded rotation.

### Release/update trust

Release archives and the checksum manifest are produced only by the repository release workflow from a version tag. The canonical signing/provenance mechanism is GitHub Artifact Attestations backed by Sigstore/OIDC, rather than a long-lived private release key stored in this repository.

The workflow creates SHA-256 checksums and cryptographically signed GitHub artifact attestations for the release subjects. Consumers/operators verify both the checksum and the attestation identity against the canonical repository before installing or promoting an update.

The Agent does not silently download or apply updates in AG-7. Update promotion remains an explicit operator/package action. The packaged installer provides previous-binary rollback. Final interruption/exhaustion/update rollback acceptance remains AG-8.

## Alternatives

- Machine-scope Windows DPAPI plus LocalSystem service: rejected because it weakens/changes the accepted secret trust boundary.
- Password-backed Windows service running as the interactive user: rejected because installer handling of account passwords is not acceptable.
- Plain HTTP between Caddy and Gateway: rejected because the accepted Gateway executable has no plaintext production mode and the deployment should not weaken transport protection.
- `tls_insecure_skip_verify` for the Caddy upstream: rejected because it disables certificate verification.
- Bundle the external Control Panel or a database into Compose: rejected by project scope.
- Kubernetes: rejected because no approved trigger exists.
- Repository-stored long-lived release private key: rejected because it creates avoidable secret custody and rotation risk.
- Unattested checksum-only releases: rejected because AG-7 requires a signed release/update workflow.

## Consequences

Agent installs remain compatible with the existing per-user secret model. Headless/system-wide Agent service accounts can be added only through a later approved trust/persistence decision if required.

Gateway deployment has two TLS layers: public Caddy TLS and verified internal Gateway TLS. Operators must preserve the deployment CA private key securely and never mount it into Caddy or Gateway runtime containers.

Artifact attestation verification depends on the canonical GitHub repository identity rather than a repository-owned signing private key.

## Security impact

- No Control Panel secrets/services are bundled.
- Agent private identity/session secrets remain under the accepted local secret-store rules.
- Caddy→Gateway TLS verification is mandatory.
- Operational metrics remain low-cardinality and contain no device IDs, tokens or private payloads.
- Release packages require checksum plus provenance/attestation verification before promotion.
- Deployment private CA key is bootstrap-only secret material and is never mounted into runtime containers.

## Reliability/performance impact

Docker Compose is a single-Gateway MVP deployment and does not introduce HA/session coordination. Caddy and Gateway have explicit health/diagnostic paths. Agent installers preserve a previous binary for bounded manual rollback.

## Compatibility/migration impact

Archive layout, deployment environment variables and release manifest are versioned by the Git tag. A future system-wide Windows service design, alternate edge component, Kubernetes topology, or different updater/signing trust requires the applicable ADR/replan process.

## Verification / fitness functions

- Clean Agent archive install/uninstall succeeds on Linux, macOS and Windows CI runners.
- Upgrade preserves a previous binary and rollback restores it.
- Agent persistence specs do not cross the Windows DPAPI CurrentUser boundary.
- Docker Compose configuration contains only Caddy and Gateway product services.
- The Gateway image builds and a clean Compose deployment reaches Gateway health through Caddy.
- Caddy configuration contains explicit verified upstream trust and no insecure TLS skip.
- `/readyz` and `/metrics` work internally and metrics contain only bounded aggregate values.
- Release packaging produces deterministic platform archives and `SHA256SUMS`.
- Release workflow generates GitHub/Sigstore artifact attestations and documents `gh attestation verify` verification.
- Existing runtime/E2E/security gates remain blocking.

## Rollback/supersession

Supersession requires a new Accepted ADR and any required Durable Plan change.

## Related ADRs

- ADR-0002 — per-device Ed25519 identity and key locality
- ADR-0003 — external Control Panel integration boundary
- ADR-0004 — Caddy/TLS and domain edge ownership
- ADR-0008 — Gateway runtime state and ingress model
- ADR-0009 — Agent local state, secret storage and runtime model
