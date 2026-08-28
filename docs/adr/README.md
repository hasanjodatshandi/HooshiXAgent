# Architecture Decision Records

HooshiXAgent uses Architecture Decision Records (ADRs) for architecturally significant decisions.

Normative governance is defined in:

`docs/governance/authority-and-adr-governance.md`

## ADR rules

- Use stable monotonic four-digit IDs: `ADR-0001`, `ADR-0002`, and so on.
- Never renumber or reuse an allocated ADR ID.
- Accepted, non-superseded ADRs are current architecture authority.
- Superseded ADRs remain in the repository as provenance but are not current authority.
- Rejected ADRs are historical proposals and are not current authority.
- Material architecture changes require the applicable explicit approval, Durable Plan replan/supersession where required, and an Accepted ADR before implementation.

## Template

```text
# ADR-XXXX: Title

Status: Proposed
Date: YYYY-MM-DD

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

## Register

All allocated ADR IDs and their status are indexed in:

`docs/adr/decision-register.md`
