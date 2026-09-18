# HooshiXAgent Documentation

**Status:** Current documentation map

HooshiXAgent is implemented: the Go Edge Agent, the Go Tunnel Gateway and the shared integration contracts exist, and R-0 through R-13 are recorded. Start with `docs/engineering/current-state.md` for what is actually built, and `README.md` at the repository root for how to build, run and package it.

The `AG-*` documents under `docs/01_Current_State/` … `docs/06_Verification/` and `docs/Codex_Execution_Instructions.md` are the **historical** Codex execution package that planned this work before it was implemented. They are provenance only: their "Documentation: Complete / Implementation: Not started" status described the starting point and is superseded by the current-state and runtime documents below. Do not treat them as current status, and do not edit them to look current.

## Normative governance and standards

- `docs/governance/plan-roadmap-scope-lock.md` — scope lock (what may and may not be built here)
- `docs/governance/authority-and-adr-governance.md` — architecture authority and ADR rules
- `docs/adr/decision-register.md` — accepted/superseded/rejected ADR register
- `docs/engineering/go-engineering-standard.md`
- `docs/engineering/security-standard.md`
- `docs/engineering/executable-runtime-gate.md` — runtime-gate rules and registered gaps
- `docs/engineering/observability-standard.md`
- `docs/engineering/quality-enforcement-map.md` — which gate enforces which property
- `docs/engineering/repository-change-workflow.md`
- `docs/engineering/reporting-and-evidence-contract.md`

## Architecture and contracts

- `docs/architecture/agent-gateway-architecture-contract.md`
- `docs/adr/` — ADR-0001 … ADR-0014 (ADR-0014 supersedes the Windows Agent persistence/secret trust clauses of ADR-0010)
- `contracts/v1/` — protocol, control and external integration contracts (schemas + fixtures)

## Current state and implementation records

- `docs/engineering/current-state.md` — implemented system summary
- `docs/engineering/comprehensive-test-expansion.md`
- `docs/engineering/performance-capacity-gate.md`
- `docs/engineering/final-security-architecture-performance-reaudit.md`

## Runtime operations

- `docs/runtime/agent.md`
- `docs/runtime/gateway.md`
- `docs/runtime/packaging-and-operations.md`
- `docs/runtime/agent-gateway-e2e-acceptance.md`
- `docs/runtime/security-resilience-release-gate.md`

## Planning records

- `docs/Tunnel-Implementation-Plan/` — the tunnel upgrade plan (ADR-0013 phases)
- `docs/01_Current_State/` … `docs/06_Verification/`, `docs/Codex_Execution_Instructions.md` — historical AG-* package, superseded
