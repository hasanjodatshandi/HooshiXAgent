# HooshiXAgent Authority and ADR Governance

**Status:** Normative

This document governs how implementation authority is resolved and how architecture decisions become durable for HooshiXAgent.

## 1. Authority order

For implementation work, use the following authority model together, not as permission to bypass a higher-scope constraint:

1. **Current Durable Plan state** — the exact actionable leaf from `plan.resume` / `plan.next` controls what may execute now, including active supersessions and dependencies.
2. **Current repository state on `main`** — merged code, contracts, current governance documents, and current engineering documentation define the implemented project state.
3. **Current effective ADRs** — accepted, non-superseded ADRs define durable architecture decisions within the approved project scope.
4. **Normative Master Plan / current scope lock** — establishes product scope, roadmap boundaries, technology constraints, delivery gates, and the external Control Panel boundary unless superseded through an explicitly approved and audited change.
5. **Explicit user-approved material changes** — become implementation authority only after the required Durable Plan replan/supersession and ADR process is recorded where applicable.

When sources appear inconsistent, implementation MUST NOT silently choose the most convenient interpretation. The current Durable Plan state and the current effective merged governance/ADR state must be reconciled first. A material conflict uses the Change Request process in `plan-roadmap-scope-lock.md`.

## 2. Current-only documentation policy

Operational and engineering documentation that claims to describe the current system MUST describe only the currently effective state.

Rules:

- do not leave two contradictory documents both presented as current authority;
- when a current document is replaced, update current references to point to the replacement;
- historical ADRs are preserved as provenance even when superseded;
- superseded ADRs MUST NOT remain current architecture authority;
- do not rewrite historical ADR content merely to make it match the new decision;
- implementation documentation must not silently override a Durable Plan leaf or an effective ADR.

Historical provenance and current authority are separate concerns.

## 3. ADR requirement

An ADR is required before implementation for architecturally significant decisions or material changes, including changes to:

- Agent↔Gateway transport or protocol;
- cryptographic device identity or credential trust model;
- authentication, authorization, replay protection, or trust boundaries;
- datastore introduction or replacement;
- public routing, endpoint naming, or domain/TLS model;
- service/process boundaries;
- updater/signing trust;
- hosted/self-hosted deployment topology;
- high-availability or session-coordination model;
- introduction of Redis, NATS, Kafka, Kubernetes, service mesh, or equivalent infrastructure;
- scaling decisions that materially alter runtime ownership, consistency, coordination, or failure behavior.

A documentation-only clarification that does not change an accepted architecture decision does not require a new ADR.

## 4. ADR lifecycle

Supported lifecycle states are:

```text
Proposed
→ Accepted
→ Superseded

Proposed
→ Rejected
```

### Proposed

The decision is under review and is not implementation authority.

### Accepted

The decision has the required approval and is current architecture authority unless a later accepted ADR supersedes it.

Implementation of a material architecture change MUST NOT begin before the ADR is Accepted and any required Durable Plan replan/supersession has completed.

### Superseded

The ADR remains permanently in the repository as provenance, but is no longer current architecture authority. It MUST identify the ADR that superseded it, and the replacement ADR SHOULD identify what it supersedes.

### Rejected

The proposal remains historical context but never becomes architecture authority.

## 5. ADR identifiers

ADR identifiers are stable, monotonic, four-digit numbers:

```text
ADR-0001
ADR-0002
ADR-0003
...
```

Rules:

- allocate the next unused numeric ID;
- never reuse an ID, including IDs from rejected or superseded ADRs;
- after an ADR is accepted/merged, renumbering is prohibited;
- do not recycle an ID when a file is removed or a proposal is abandoned;
- a superseding decision gets a new ID;
- the filename begins with the stable ID, e.g. `ADR-0007-session-coordination.md`.

## 6. ADR required format

Each ADR MUST use this minimum structure:

```text
# ADR-XXXX: Title

Status:
Date:

Context:
Decision:
Alternatives:
Consequences:
Security impact:
Reliability/performance impact:
Compatibility/migration impact:
Verification / fitness functions:
Rollback/supersession:
Related ADRs:
```

The `Status` field MUST match the lifecycle defined above.

## 7. Decision Register

`docs/adr/decision-register.md` is the current index of ADR status and relationships.

The register MUST:

- list every allocated ADR ID;
- identify current status;
- make supersession relationships explicit;
- link to the ADR file;
- never imply that a Superseded or Rejected ADR is current authority.

The register is an index, not a substitute for the ADR itself.

## 8. Architecture change control

For a material architecture change:

1. Confirm the current `plan.next` leaf permits the work.
2. If the current approved plan does not permit the change, stop and use the Change Request process.
3. Obtain explicit user approval for the material change.
4. Perform the required audited Durable Plan replan/supersession where applicable.
5. Create the ADR using the next stable ID.
6. Obtain ADR acceptance before implementation.
7. Update the Decision Register.
8. Implement only within the approved leaf.
9. Verify the ADR's stated fitness functions and leaf acceptance evidence.

No ADR can be used to bypass the Durable Plan or the project scope lock.
