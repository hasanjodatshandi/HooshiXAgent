# HooshiXAgent

HooshiXAgent is the Go repository for the installable **Edge Agent**, the server-side **Tunnel Gateway**, and the minimum shared/language-neutral integration contracts required by those components.

The separate **HooshiX Control Panel** is external and is not implemented in this repository.

## Current repository boundaries

```text
contracts/v1/           Agent↔Gateway protocol v1 + external Control Panel integration contracts/fixtures
internal/agent/          Edge Agent implementation boundary; no product runtime behavior yet
internal/gateway/        Tunnel Gateway implementation boundary; no product runtime behavior yet
internal/contractv1/     Go reference codec/strict validation for the language-neutral v1 contracts
internal/architecture/   repository architecture fitness tests
scripts/ci/              executable quality/security/runtime guard scripts
.github/workflows/       required baseline CI
```

Current architecture authority is documented in `docs/architecture/agent-gateway-architecture-contract.md` and the Accepted ADRs indexed by `docs/adr/decision-register.md`.

Current contract authority is documented in `contracts/v1/`, including:

- fixed protocol-v1 binary framing over the already-approved WSS/TLS transport;
- JSON control-message schema and deterministic frame/handshake fixtures;
- external device/session authorization, endpoint-route assignment, revocation, and bounded Gateway status schemas;
- strict rules preventing raw remote local-target authority or direct Control Panel database coupling.

AG-3 does not introduce an Edge Agent or Tunnel Gateway executable. Product runtime implementation begins only in the later approved runtime leaves.

## Local baseline checks

The repository targets **Go 1.27.x**. With the required tools installed:

```bash
scripts/ci/go-quality.sh
scripts/ci/security.sh
scripts/ci/runtime-gate.sh
```

The runtime gate is fail-closed. While the repository has no runnable product capability, it reports `Not applicable`; a later leaf that introduces one must add its real runtime procedure instead of treating compilation or tests as runtime evidence.
