# HooshiXAgent Plan / Roadmap / Scope Lock

**Status:** Normative
**Project ID:** `hooshix-agent`
**Durable Plan ID:** `plan-c410eb3d212345bb9ed1c4285bca4b64`
**Canonical workspace:** `D:\Projects\hooshixagent`
**Canonical remote:** `https://github.com/hasanjodatshandi/HooshiXAgent.git`

## 1. Execution authority

Implementation MUST execute only the exact actionable leaf returned by:

```text
plan.resume(project_id="hooshix-agent")
plan.next(plan_id="plan-c410eb3d212345bb9ed1c4285bca4b64")
```

No later leaf may be started, combined, partially implemented, or prepared in advance.

A leaf may change only through the Durable Plan's audited replan/supersession flow and only after explicit user approval when the change is material.

## 2. Product scope lock

`HooshiXAgent` owns exactly these product/runtime responsibilities:

```text
HooshiXAgent
├── Edge Agent
├── Tunnel Gateway
└── shared/language-neutral integration contracts required by those components
```

The separate **HooshiX Control Panel** is an external project and is not implemented in this repository or this Durable Plan.

The Control Panel may be referenced only through the minimum explicit integration boundary required for Agent/Gateway operation, including authorized device/session metadata, endpoint/routing assignment metadata, revocation/disable signals, and bounded status/usage signals where later approved leaves require them.

## 3. Explicitly out of scope

The following MUST NOT be implemented in HooshiXAgent unless the user explicitly approves a material scope change and the Durable Plan is audited/replanned as required:

- users or user-account business logic;
- tenants, organizations, memberships, or account authorization;
- Control Panel persistence or database schemas;
- enrollment-management backend or device-management CRUD;
- public endpoint-management CRUD backend;
- quotas, billing, plans, or commercial account policy;
- Control Panel APIs;
- Control Panel dashboard/UI;
- Control Panel authentication/session business logic.

HooshiXBrain remains a separate orchestration product and does not own the Tunnel Gateway or Control Panel responsibilities of this project.

## 4. Architecture / technology / roadmap lock

The implementing AI MUST NOT independently:

- change product scope or ownership boundaries;
- move Tunnel Gateway responsibilities to HooshiXBrain;
- replace Go as the primary implementation language;
- replace the primary Agent transport of outbound WSS/TLS on TCP 443;
- add Redis, NATS, Kafka, Kubernetes, a service mesh, datastore, or another infrastructure layer unless an approved roadmap leaf/ADR requires it;
- start later roadmap phases;
- combine Durable Plan leaves;
- add unrelated refactors, cleanup, or speculative framework work;
- weaken security, runtime, CI, acceptance, or verification gates;
- silently alter leaf acceptance criteria.

## 5. Material change procedure

If the current approved leaf cannot safely satisfy a requirement without a material change, implementation MUST stop at that boundary and report:

```text
CHANGE REQUEST

Project:
Plan:
Current leaf:
Current approved scope:
Evidence:
Why current plan cannot safely satisfy the requirement:
Proposed change:
Alternatives:
Architecture impact:
Security impact:
Compatibility impact:
Operations/deployment impact:
Roadmap impact:
Rollback impact:
ADR required: yes/no
Replan required: yes/no
User approval required: yes
```

No material change is implemented before explicit user approval. Where applicable, the approved change MUST then use the Durable Plan's audited replan/supersession mechanism and ADR governance defined by the appropriate roadmap leaf.

## 6. Out-of-scope findings policy

When implementation reveals useful work that is outside the current leaf:

1. Do not implement it.
2. Do not prepare hidden scaffolding for it.
3. Record the finding in the leaf evidence/report if relevant.
4. Classify it as later-roadmap work, external-Control-Panel work, or a potential material change.
5. Continue the current leaf only when its approved acceptance criteria can still be met safely.
6. If the current leaf cannot be completed safely without that work, use the Change Request procedure above.

## 7. Gate integrity

A failing, missing, skipped, or inconvenient gate is not permission to weaken the gate or broaden scope.

The implementing AI MUST NOT disable, downgrade, bypass, remove, or silently reinterpret an approved security, runtime, CI, merge, or acceptance requirement merely to complete a leaf.

## 8. Current roadmap boundary

The approved roadmap is:

```text
AG-0 Governance/Repository/Delivery
→ AG-1 Edge Agent + Tunnel Gateway Architecture Contract
→ AG-2 Repository/CI Foundation
→ AG-3 Shared Tunnel Protocol + External Control Panel Integration Contract
→ AG-4 Tunnel Gateway
→ AG-5 Edge Agent
→ AG-6 Agent↔Gateway End-to-End Tunnel Acceptance
→ AG-7 Agent/Gateway Packaging and Operations
→ AG-8 Security/Resilience/Agent-Gateway Release Gate
```

Only `plan.next` determines which leaf within this roadmap is actionable.
