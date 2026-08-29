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

AG-1 does not authorize concrete protocol schemas, repository/runtime scaffolding, Gateway/Agent executables, Control Panel implementation, or later-leaf deployment work. Those remain gated by future `plan.next` leaves.
