# HooshiXAgent Quality / Security Enforcement Map

**Status:** Normative mapping

This document maps approved engineering requirements to their enforcement mechanism. The actual CI workflow is introduced only when the Durable Plan reaches the repository/CI foundation leaf; this mapping does not pull that later-leaf implementation forward.

| Requirement | Local / implementation evidence | Automated CI enforcement when CI exists | Blocking |
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
