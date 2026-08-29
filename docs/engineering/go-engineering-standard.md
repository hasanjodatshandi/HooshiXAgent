# HooshiXAgent Go Engineering Standard

**Status:** Normative
**Primary language:** Go 1.27

This standard applies to HooshiXAgent Edge Agent, Tunnel Gateway, and shared/integration contract implementation when the relevant Durable Plan leaves become actionable.

## 1. Mandatory Go quality baseline

Applicable Go changes MUST satisfy:

```text
gofmt
goimports
go vet ./...
go test ./...
relevant go test -race
```

When a Go module exists, applicable dependency/module gates also include:

```text
go mod tidy drift check
go mod verify
govulncheck ./...
```

Compilation or a successful `go build` alone is never completion evidence.

## 2. Package design

Packages must be cohesive, lower-case, short, and purpose-oriented.

Avoid generic dumping grounds such as:

```text
common
utils
helpers
manager
misc
generic
```

unless the package represents a genuinely narrow technical responsibility.

The intended dependency direction is:

```text
network / OS / provider adapters
                ↓
application / use-case orchestration
                ↓
core policy / protocol / domain invariants
```

Core policy must not import concrete network, operating-system, datastore, or provider implementation details.

Interfaces should remain small and normally be defined near the consumer.

Composition uses explicit constructors/functions. Do not introduce:

- service locators;
- global mutable dependency registries;
- reflection-driven magical dependency injection;
- uncontrolled mutable package globals.

## 3. Context, deadlines, retries

Network, datastore, and other blocking operations use `context.Context` where cancellation/deadline propagation is applicable.

Remote synchronous operations MUST have finite deadlines.

Retries MUST be:

- finite;
- idempotency-aware;
- owned by one layer;
- bounded by a total deadline;
- observable.

A retry loop may not silently create an unbounded request lifetime.

## 4. Concurrency and resource ownership

Goroutines do not create capacity.

Use:

- bounded concurrency;
- bounded queues/channels;
- bounded pools;
- explicit ownership and cancellation;
- leak tests where applicable.

Unbounded goroutine creation is prohibited.

Long-lived goroutines must have an explicit lifecycle owner and termination path.

## 5. Dependency discipline

New dependencies require review for:

- necessity and scope fit;
- maintenance/health;
- license suitability;
- transitive dependency cost;
- security exposure;
- binary/runtime impact;
- whether the standard library or an already-approved dependency is sufficient.

A dependency must not be introduced merely for convenience when it expands architecture or infrastructure beyond the active leaf.

## 6. Smallest correct coherent change

Implementation should make the smallest correct coherent change that satisfies the exact current Durable Plan leaf.

Do not combine unrelated cleanup, speculative abstractions, later-leaf scaffolding, or architecture changes with the current leaf.

## 7. Verification hierarchy

Use the strongest applicable evidence, in addition to static quality checks:

```text
format/static checks
→ focused unit tests
→ integration/negative tests
→ real executable runtime gate
→ PR/CI evidence
→ merged-main/post-merge verification
```

Passing an earlier layer does not replace a later layer when that later layer is applicable.
