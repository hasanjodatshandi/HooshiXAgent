# HooshiXAgent

HooshiXAgent is the Go repository for the installable **Edge Agent**, the server-side **Tunnel Gateway**, and the minimum shared/language-neutral integration contracts required by those components.

The separate **HooshiX Control Panel** is external and is not implemented in this repository.

## Repository foundation

AG-2 establishes only the repository and CI/security/architecture foundation:

```text
contracts/              reserved language-neutral contract boundary; concrete AG-3 schemas are not present
internal/agent/          Edge Agent implementation boundary; no runtime behavior yet
internal/gateway/        Tunnel Gateway implementation boundary; no runtime behavior yet
internal/architecture/   repository architecture fitness tests
scripts/ci/              executable quality/security/runtime guard scripts
.github/workflows/       baseline CI
```

Current architecture authority is documented in `docs/architecture/agent-gateway-architecture-contract.md` and the Accepted ADRs indexed by `docs/adr/decision-register.md`.

## Local baseline checks

The repository targets **Go 1.27.x**. With the required tools installed:

```bash
scripts/ci/go-quality.sh
scripts/ci/security.sh
scripts/ci/runtime-gate.sh
```

The runtime gate is intentionally fail-closed: AG-2 introduces no runnable product capability, and a later leaf that introduces one must add its real runtime procedure instead of silently treating compilation or tests as runtime evidence.
