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
