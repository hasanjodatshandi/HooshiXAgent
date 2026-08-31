# HooshiXAgent Quality / Security Enforcement Map

**Status:** Normative current mapping (reconciled R-13)

This document maps the implemented Agent/Gateway engineering requirements to current local and CI enforcement. Missing or skipped blocking evidence is never equivalent to `Passed`.

## Core enforcement

| Requirement | Local / implementation evidence | Automated CI enforcement | Blocking |
| --- | --- | --- | --- |
| Formatting/imports/module consistency | `scripts/ci/go-quality.sh` | Go quality / tests / vulnerability | Yes |
| `go vet`, unit/integration, build | `scripts/ci/go-quality.sh` | Go quality / tests / vulnerability | Yes |
| Race-sensitive paths | focused/full race runs as applicable | focused race gates across hardening jobs | Yes when applicable |
| Dependency vulnerabilities | `govulncheck ./...` via `scripts/ci/go-quality.sh` | Go quality / tests / vulnerability | Yes |
| Secret/static security | `scripts/ci/security.sh` | Gitleaks / Semgrep | Yes |
| Architecture/scope boundaries | architecture tests | Architecture fitness | Yes |
| Real executable behavior | `scripts/ci/runtime-gate.sh` | Executable runtime gate guard | Yes |
| Real Agent↔Gateway integration | `scripts/ci/e2e-acceptance.sh` | Agent↔Gateway E2E acceptance | Yes |
| Cross-platform Agent/package behavior | platform tests/package smoke | Ubuntu/Windows/macOS Agent platform jobs | Yes |
| Packaging/Compose deployment | `scripts/ci/packaging-ops.sh` | Packaging / clean deployment / rollback | Yes |
| Release security/resilience | `scripts/ci/release-gate.sh` | AG-8 final security / resilience / release gate | Yes |

## Hardening gate chain

| Gate | Main enforced property |
| --- | --- |
| R-3 resource / DoS budget gate | byte budgets, concurrency/rates, saturation cleanup and bounded resources |
| R-4 streaming ingress gate | bounded public-request streaming, cancellation and accounting |
| R-5 HTTP / stream isolation gate | stream fault isolation, HTTP header/body correctness and deterministic terminal behavior |
| R-6 release / supply-chain gate | exact-commit policy, immutable pins, privilege separation, SBOM/scanning/provenance policy |
| R-7 metadata scalability / determinism gate | typed/indexed metadata, duplicate rejection, readiness and large-index lookup behavior |
| RA-3 live metadata lifecycle gate | immutable generations, atomic activation, freshness fail-closed/recovery and existing-session live revocation |
| R-8 observability / writer isolation gate | non-blocking bounded telemetry and single-writer control-priority scheduling |
| R-9 Agent state / installer hardening gate | strict state/config, mutation lock, destructive-path and bootstrap safety |
| R-10 infrastructure runtime hardening gate | hardened two-service Compose runtime and actual-container acceptance |
| R-11 comprehensive test expansion gate | fuzz/race/reconnect/slow-path scenarios and informational coverage artifact |
| R-12 performance / capacity gate | reproducible 100/500/1000 synthetic capacity, soak, benchmark and CPU/heap/block/mutex evidence |

R-0 regression tests and R-1/R-2 authorization/protocol hardening are retained in the normal unit/E2E/release suites; they are not separate standalone CI jobs because their invariants are now part of the product baseline.

## Current final CI dependency boundary

The `AG-8 final security / resilience / release gate` job currently depends on successful completion of:

- Go quality/tests/vulnerability;
- Ubuntu, Windows and macOS Agent platform jobs;
- architecture fitness;
- Gitleaks/Semgrep;
- R-3 through R-12 focused gates;
- Agent↔Gateway E2E acceptance;
- packaging/clean deployment/rollback;
- executable runtime gate.

The AG-9 first-prototype smoke is also a blocking CI job but is an operator-visible product smoke rather than a prerequisite in the release-gate `needs` list.

## Runtime precedence

Static checks, compilation and unit tests do not replace executable runtime evidence when the capability is runnable. The runtime and E2E gates launch real `cmd/gateway` and `cmd/agent` processes over TLS/WSS, exercise an approved loopback target and verify fail-closed/reconnect behavior.

## Release and supply-chain boundary

The implemented release path includes:

- immutable full-SHA GitHub Action pins;
- digest-pinned build/runtime/scanner images where used;
- exact-main-commit CI eligibility checks before publication;
- separated read-only build/test, OIDC attestation and write-enabled publish jobs;
- checksummed release archives;
- SPDX JSON SBOM generation;
- final artifact/Gateway image vulnerability scanning;
- OIDC-backed GitHub Artifact Attestations and repository-identity verification;
- deliberate checksum tamper rejection in release acceptance.

## Gate semantics

Use only the approved evidence vocabulary:

```text
Passed
Failed
Not run
Not applicable
Partially verified
Inconclusive
Not verified
```

A missing, skipped or failing blocking gate must not be relabeled as `Passed`. A capability is complete only with the evidence required by its Durable Plan leaf and the repository change workflow.
