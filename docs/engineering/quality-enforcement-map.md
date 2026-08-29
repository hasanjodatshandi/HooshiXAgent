# HooshiXAgent Quality / Security Enforcement Map

**Status:** Normative mapping

This document maps approved engineering requirements to their enforcement mechanism. The AG-2 repository/CI foundation implements the baseline workflow in `.github/workflows/ci.yml` and reusable local gate scripts under `scripts/ci/`.

| Requirement | Local / implementation evidence | Automated CI enforcement | Blocking |
| --- | --- | --- | --- |
| Formatting | `gofmt` verification | format-drift check | Yes |
| Imports | `goimports` verification | import-format check | Yes |
| Module consistency | `go mod tidy` drift check | clean-module diff check | Yes |
| Module integrity | `go mod verify` | module verification | Yes |
| Static Go analysis | `go vet ./...` | `go vet ./...` | Yes |
| Unit/integration tests | `go test ./...` | `go test ./...` | Yes |
| Concurrency/race-sensitive paths | relevant `go test -race` | targeted/relevant race test job | Yes when applicable |
| Dependency vulnerabilities | `govulncheck ./...` | `govulncheck ./...` | Yes |
| Secret scanning | Gitleaks current tree/history | Gitleaks tree/history gate | Yes |
| Static security rules | high-signal Semgrep/project rules | Semgrep/project security gate | Yes |
| Architecture dependency rules | architecture/import fitness tests | architecture fitness test job | Yes |
| Build | real project build | build job | Yes |
| Runtime capability | real executable/runtime procedure | CI/staging runtime job where technically suitable; otherwise recorded runtime evidence | Yes when capability is runnable |
| Input/SSRF/auth/protocol security | focused negative/adversarial tests | security test job(s) | Yes when applicable |
| Bounded resources/timeouts | tests + code review + runtime evidence | architecture/security tests and relevant runtime checks | Yes |
| Day-One observability | runtime evidence and code review | architecture/runtime checks where automatable | Yes for applicable critical paths |


## AG-2 executable baseline

The baseline enforcement entry points are:

```text
scripts/ci/go-quality.sh
scripts/ci/security.sh
scripts/ci/runtime-gate.sh
.github/workflows/ci.yml
```

The runtime gate is fail-closed. AG-5 extends the approved runtime procedure to build and launch both real product binaries: `cmd/gateway` and `cmd/agent`. It exercises TLS/WSS authentication, a real public request through the Agent to an approved loopback service, Agent state/identity persistence across process restart, reconnect, and plaintext Gateway startup rejection. Any additional runnable capability still fails the gate until its own approved runtime procedure is added. The Go quality gate also cross-builds the Agent for Linux, Windows and macOS; CI separately runs Agent platform-foundation tests on all three OS families.
## Gate semantics

Use exact evidence vocabulary:

```text
Passed
Failed
Not run
Not applicable
Partially verified
Inconclusive
Not verified
```

A missing workflow is not a passing workflow.

A missing, skipped, or failing blocking gate MUST NOT be relabeled as Passed.

If a gate is not yet technically present because its implementation belongs to a later approved leaf, record it accurately as `Not run` or `Not applicable` according to the leaf context; do not create later-leaf scaffolding merely to change the label.

## Runtime precedence

Automated static/test/build checks do not replace the Executable Runtime Gate when a capability is runnable.

## Release-boundary additions

Later release boundaries add applicable:

- SBOM generation;
- final-artifact vulnerability scanning;
- signing/provenance;
- immutable artifact promotion.

These are not implemented by this governance leaf.

## Agent↔Gateway E2E acceptance

AG-6 adds `scripts/ci/e2e-acceptance.sh` and the blocking `Agent↔Gateway E2E acceptance` CI job. It builds the real Agent and Gateway binaries and executes the deterministic integrated acceptance documented in `docs/runtime/agent-gateway-e2e-acceptance.md`, including validated external metadata injection, the stable `demo.hooshix.test` test route, public tunnel success, Agent/Gateway restart recovery, offline/error behavior, and security-negative cases. This gate supplements rather than replaces the executable runtime, unit/race, architecture, vulnerability, Gitleaks and Semgrep gates.

## Packaging and operations gate

AG-7 adds platform Agent clean-install/rollback/uninstall smoke tests plus the blocking `Packaging / clean deployment / rollback` CI job driven by `scripts/ci/packaging-ops.sh`. The gate builds checksummed release archives, installs the produced Linux Agent archive, extracts and clean-deploys the produced Gateway Docker Compose+Caddy bundle, verifies Caddy→Gateway TLS, verifies that `/readyz` and `/metrics` remain internal-only, validates aggregate metrics, and checks that the tag release workflow uses OIDC-backed artifact attestations. Existing Go, architecture, security, runtime and E2E gates remain blocking.

## AG-8 final release gate

AG-8 adds the blocking dependency-chained `AG-8 final security / resilience / release gate` job. It cannot run successfully unless Go/vulnerability, all Agent platform package jobs, architecture, Gitleaks/Semgrep, executable runtime, Agent↔Gateway E2E, and packaging/clean-deployment jobs have already passed. `scripts/ci/release-gate.sh` then runs focused SSRF/update, malformed/replay, auth/resource-exhaustion, real network-interruption/cold-restart and artifact-tamper checks and uploads commit-bound release evidence. See `docs/runtime/security-resilience-release-gate.md`.
