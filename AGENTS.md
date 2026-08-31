# HooshiXAgent Agent Instructions

This repository is governed by Durable Project `hooshix-agent` and Durable Plan `plan-c410eb3d212345bb9ed1c4285bca4b64`.

Before implementation work:

```text
plan.resume(project_id="hooshix-agent")
plan.next(plan_id="plan-c410eb3d212345bb9ed1c4285bca4b64")
```

Execute only the exact current actionable leaf. Do not start later leaves, combine leaves, broaden scope, weaken gates, or make material architecture/technology/roadmap changes without explicit user approval and the required audited plan/ADR flow.

The normative scope lock is:

`docs/governance/plan-roadmap-scope-lock.md`

HooshiXAgent scope is limited to the Go Edge Agent, Go Tunnel Gateway, and the shared/language-neutral integration contracts required by them. The separate HooshiX Control Panel is external and MUST NOT be implemented in this repository.

Architecture/authority governance is normative in:

- `docs/governance/authority-and-adr-governance.md`
- `docs/adr/decision-register.md`

Accepted, non-superseded ADRs are current architecture authority within the active Durable Plan and scope lock. Superseded or rejected ADRs are provenance only. ADR IDs are stable and MUST NOT be reused or renumbered after allocation.

Engineering/runtime/security standards are normative in:

- `docs/engineering/go-engineering-standard.md`
- `docs/engineering/security-standard.md`
- `docs/engineering/executable-runtime-gate.md`
- `docs/engineering/observability-standard.md`
- `docs/engineering/quality-enforcement-map.md`

Compilation alone is never completion evidence. Runnable capabilities require the real Executable Runtime Gate, applicable security failures block completion, and concurrency/timeouts/resources must remain bounded.

Repository delivery workflow is normative in:

- `docs/engineering/repository-change-workflow.md`

Normal implementation work uses the canonical workspace/remote and one fresh branch + one PR per Durable Plan leaf. Required CI must pass before merge when applicable, and merged `main` plus post-merge verification are required before a leaf may be marked `PASSED`.

Reporting/evidence requirements are normative in:

- `docs/engineering/reporting-and-evidence-contract.md`

Use the exact check-status vocabulary defined there. A leaf may not be reported `completed` with missing required evidence, skipped checks must be explicit, and architecture deviations must be `None` or explicitly approved and traceable.

Current Edge Agent + Tunnel Gateway architecture authority is frozen by AG-1 in:

- `docs/architecture/agent-gateway-architecture-contract.md`
- `docs/adr/ADR-0001-agent-gateway-transport.md`
- `docs/adr/ADR-0002-device-identity-key-locality.md`
- `docs/adr/ADR-0003-external-control-panel-boundary.md`
- `docs/adr/ADR-0004-caddy-tls-domain-edge.md`
- `docs/adr/ADR-0005-bounded-stream-multiplexing.md`
- `docs/adr/ADR-0006-routing-ownership.md`

RA-0 refines the accepted dynamic-hostname and live-metadata architecture in:

- `docs/adr/ADR-0011-authorized-on-demand-public-tls.md`
- `docs/adr/ADR-0012-live-external-metadata-snapshot-projection.md`

These ADRs preserve Caddy as the public TLS edge, the external Control Panel as durable endpoint/authorization authority, the Gateway as validated runtime enforcement only, and the Agent as final local-target authority. RA-3 owns live metadata implementation and RA-4 owns multi-host Caddy implementation; later RA leaves MUST NOT be pulled into RA-0.


AG-1 does not authorize concrete protocol schemas, repository/runtime scaffolding, Gateway/Agent executables, Control Panel implementation, or later-leaf deployment work. Those remain gated by future `plan.next` leaves.


Repository/CI foundation is implemented by AG-2 in:

- `go.mod` — module baseline targeting Go `1.27.0`;
- `internal/agent/` and `internal/gateway/` — product implementation boundaries without AG-2 runtime behavior;
- `contracts/` — reserved language-neutral contract boundary; concrete schemas remain AG-3 work;
- `internal/architecture/` — architecture fitness tests;
- `scripts/ci/go-quality.sh` — Go format/import/module/vet/test/race/vulnerability/build baseline;
- `scripts/ci/security.sh` — Gitleaks + Semgrep baseline;
- `scripts/ci/runtime-gate.sh` — fail-closed executable-runtime guard;
- `.github/workflows/ci.yml` — required CI workflow.

Once AG-2 is merged, applicable changes must keep these required CI gates passing. A later leaf that introduces a runnable product capability must extend/replace the AG-2 runtime guard with the real Executable Runtime Gate for that capability; it may not weaken or bypass the guard.

AG-3 contract authority is implemented in `contracts/v1/` and `internal/contractv1/`, with ADR-0007 defining protocol-v1 framing/control encoding. Concrete contract changes must preserve the external Control Panel boundary, strict validation, no raw remote local-target authority, and versioned compatibility rules. AG-3 does not authorize Gateway/Agent executables or Control Panel business logic.


AG-4 Gateway runtime authority is implemented in `cmd/gateway`, `internal/gateway/`, `docs/runtime/gateway.md`, and ADR-0008. Gateway runtime state is ephemeral/in-memory; external authorization/routing/revocation metadata remains the authority boundary. `scripts/ci/runtime-gate.sh` now executes the real Gateway process. AG-4 does not authorize Edge Agent product implementation or Control Panel persistence/business logic.


AG-5 Edge Agent runtime authority is implemented in `cmd/agent`, `internal/agent/`, `docs/runtime/agent.md`, and ADR-0009. The Agent owns its unique Ed25519 private identity, protected local secret state, loopback-only endpoint mappings, WSS/TLS client and local proxy. Public/Gateway input never selects a raw local target. External Control Panel credentials are consumed only as runtime inputs and no Control Panel server/business logic is embedded. `scripts/ci/runtime-gate.sh` executes real Agent+Gateway processes; installer/service installation, signed update delivery, staging acceptance and release hardening remain later leaves.


AG-6 integrated acceptance authority is `internal/runtimegate/e2e_acceptance_test.go`, `scripts/ci/e2e-acceptance.sh`, and `docs/runtime/agent-gateway-e2e-acceptance.md`. It is acceptance-only: do not add Control Panel implementation, deployment packaging, installer/update delivery, or AG-8 release-hardening scope under AG-6.


AG-7 packaging/operations authority is `docs/adr/ADR-0010-packaging-deployment-and-release-trust.md` plus `docs/runtime/packaging-and-operations.md`. Agent persistence must remain within the accepted per-user secret ownership model; Gateway deployment is Docker Compose with Caddy and verified upstream TLS only; no Control Panel service/database, Kubernetes, Redis, or AG-8 final release-hardening belongs in AG-7.


AG-8 release authority: AG-8 release authority is `docs/runtime/security-resilience-release-gate.md`. It is acceptance-only: do not add Control Panel scope or silently change architecture. A release-ready claim requires the final dependency-chained AG-8 CI job, merged-main CI, and applicable post-merge runtime/E2E/release verification to pass. Hosted CI evidence must not be mislabeled as a literal physical OS reboot.
