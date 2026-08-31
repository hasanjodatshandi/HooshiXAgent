# ADR-0012: Live External Metadata Snapshot Projection

Status: Accepted
Date: 2026-08-31

## Context

The Gateway currently loads the external Control Panel contract records from a read-only filesystem snapshot once at process start. Runtime authorization expiry is evaluated at use time, but an authorization disable, route change, or revocation published after Gateway startup is not visible until the process is restarted or a new snapshot is otherwise loaded.

ADR-0003 forbids direct Gateway coupling to Control Panel persistence/business logic. ADR-0006 assigns durable endpoint/device assignment ownership to the external Control Panel and runtime enforcement to the Gateway. ADR-0008 keeps Gateway runtime state ephemeral/in-memory.

The live integration therefore needs bounded freshness and atomic updates without adding a Control Panel database client, broker, distributed cache, or new durable Gateway datastore.

## Decision

The approved live metadata model is a **versioned, generation-based filesystem snapshot projection** from the external Control Panel boundary into the Gateway deployment.

The external publisher/projection process is outside this repository. HooshiXAgent defines and consumes the projection contract only.

### Projection shape

A live projection consists of immutable generations plus one small current-generation manifest/pointer. Conceptually:

```text
<metadata-root>/
├── current.json
└── generations/
    ├── <revision-a>/
    │   ├── authorizations/*.json
    │   ├── routes/*.json
    │   └── revocations/*.json
    └── <revision-b>/
        ├── authorizations/*.json
        ├── routes/*.json
        └── revocations/*.json
```

The exact filename encoding and Go implementation belong to RA-3, but the following semantics are normative:

1. A generation is immutable after publication.
2. The publisher writes and closes the complete generation before publishing the current-generation manifest/pointer.
3. Publication of the current manifest/pointer is atomic from the reader's perspective; a Gateway must never merge partially written generations.
4. Each published generation has a strictly monotonic opaque revision/order value, a publication time, and a bounded validity/freshness deadline.
5. A lower/replayed revision or reuse of an already accepted revision with different content is rejected fail closed.
6. A generation contains a complete authoritative runtime snapshot, not an unbounded delta/event log. The Gateway rebuilds typed indexes off the request/session critical path and atomically swaps the validated in-memory snapshot as one unit.
7. The existing versioned AG-3 authorization, route, and revocation record schemas remain the data records inside each generation. This ADR does not introduce Control Panel CRUD/business models.

### Refresh and freshness behavior

The Gateway monitors the current-generation manifest on a finite, configurable refresh interval. Exact operational defaults are RA-3 implementation details, but the interval and maximum accepted snapshot age must be explicit and bounded.

A candidate generation becomes active only after the entire candidate is successfully read, strictly parsed, structurally validated, duplicate-checked, indexed, and freshness-validated. Candidate failure never partially mutates the active snapshot.

Gateway freshness is the stricter of:

- the externally published generation validity/freshness deadline; and
- a local maximum accepted snapshot age configured by the Gateway.

This prevents an external publisher from accidentally extending stale authority indefinitely.

If a new candidate is malformed, incomplete, replayed, unavailable, or otherwise invalid, the Gateway may continue using the last fully validated active generation only until that generation's own bounded freshness deadline. It must not silently extend it.

Once there is no currently fresh validated generation:

- `/readyz` fails closed;
- new Agent authentication/authorization lookups fail closed;
- new public route lookups fail closed;
- existing authenticated sessions are terminated according to the existing bounded authorization revalidation lifecycle when their authorization can no longer be established as current;
- `/healthz` remains process-liveness only.

A live update is therefore bounded by both the projection refresh interval and the relevant existing request/session revalidation interval; the contract does not claim instantaneous revocation.

### Runtime ownership

The Gateway stores only the currently active typed/indexed generation and bounded transition bookkeeping required to reject rollback/replay. It does not become the durable system of record.

The Gateway MUST NOT:

- connect directly to a Control Panel database;
- implement user/tenant/device/endpoint CRUD;
- add Redis, NATS, Kafka, Kubernetes, a new datastore, or another synchronization service for this projection;
- treat status telemetry as authorization/routing authority.

### Legacy flat snapshot compatibility

The existing flat startup snapshot remains a static/test/migration compatibility input while RA-3 introduces the live generation adapter. It must not be described as providing live revocation/update semantics. Production deployments that require live control-plane changes use the generation-based projection after RA-3.

RA-3 owns the concrete manifest schema, polling implementation, atomic in-memory swap, observability, bounded cleanup and live-update E2E. This ADR does not implement them.

## Alternatives

### Direct Gateway queries to the Control Panel database

Rejected. This violates the explicit external-system ownership boundary and couples the data plane to Control Panel persistence/schema availability.

### Direct Gateway HTTP/gRPC CRUD/business API integration

Rejected as the primary metadata transport for this roadmap. It creates a new synchronous network dependency on request/auth paths and imports an API availability model that is unnecessary for the current file-projection deployment boundary. A later separately approved adapter may exist if it preserves the same trust/freshness semantics.

### Redis, message broker, or distributed cache

Rejected. No evidence requires a new infrastructure layer, and adding one would violate the current scope/technology lock.

### Incremental append-only revocation/route event log

Rejected as the primary model. Long-lived deltas require ordering, compaction, replay recovery, gap handling and unbounded-history controls. Complete immutable generations give simpler atomic reconciliation and deterministic cold restart.

### Reload only on Gateway restart

Rejected for production control-plane freshness because effective revocation/disable/route changes would remain invisible for an unbounded process lifetime.

### Watch mutable JSON files in place

Rejected. Readers could observe mixed generations or partial writes and would need complex per-record reconciliation semantics.

## Consequences

The external publisher must retain enough immutable generation data for a Gateway to load the published current revision and must publish the manifest last/atomically.

Gateway readiness now represents both process/config health and freshness of external authorization/routing authority. A stale external projection intentionally causes a fail-closed service condition rather than silently serving indefinitely from old authority.

Full-generation validation has bounded periodic CPU/I/O cost proportional to snapshot size, but it keeps request/session lookups O(1)-style indexed and avoids synchronization work on the critical data path. RA-10 will re-profile the final implementation rather than weakening freshness/resource controls preemptively.

## Security impact

- Revocation/disable/route changes can become visible without Gateway restart.
- Rollback/replay of older snapshots is rejected.
- Partial or malformed publication cannot partially update runtime authority.
- Stale metadata cannot be extended indefinitely by cache behavior.
- Control Panel private persistence remains outside this repository.
- No new raw local-target authority is introduced; route records still carry only `local_endpoint_id`.

## Reliability/performance impact

Temporary publisher failures do not immediately destroy a still-fresh last-known-good snapshot, but authority expires at a bounded deadline. Candidate parsing/index construction occurs before atomic activation so malformed updates do not corrupt active state.

Full snapshots trade some bounded refresh I/O for simpler consistency, deterministic restart and bounded in-memory indexes.

## Compatibility/migration impact

The AG-3 record schemas remain compatible. RA-3 adds a projection manifest/generation envelope around those records rather than changing authorization/route/revocation semantics.

Existing static snapshot fixtures/loaders may remain for deterministic tests and explicit static mode. They do not satisfy the live-production freshness claim.

Changing the live authority source to a direct database dependency, broker, durable Gateway datastore, or different ownership model requires a superseding ADR and applicable Durable Plan approval.

## Verification / fitness functions

RA-3 must prove:

- a newly published valid authorization/route/revocation generation becomes active without Gateway restart;
- an effective revocation terminates the affected existing session within the documented bounded refresh/revalidation window;
- malformed, partial, duplicate, replayed or lower-revision generations never partially replace the last valid snapshot;
- an expired/stale projection drives `/readyz`, new auth and new routing fail closed;
- recovery to a newer valid generation restores readiness without process restart;
- snapshot memory/index growth remains bounded and no Control Panel business/persistence code is introduced.

## Rollback/supersession

Before RA-3 implementation, rollback is documentation-only. After RA-3, an operator may temporarily use the explicitly supported static compatibility mode only when live control-plane freshness is not claimed. Supersession requires a new Accepted ADR and applicable Durable Plan change.

## Related ADRs

- ADR-0003 — external Control Panel integration boundary
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
- ADR-0008 — Gateway runtime state and ingress model
- ADR-0010 — packaging, deployment and release trust
- ADR-0011 — authorized On-Demand public TLS
