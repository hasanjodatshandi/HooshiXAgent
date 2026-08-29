# HooshiXAgent

HooshiXAgent is the Go repository for the installable **Edge Agent**, the server-side **Tunnel Gateway**, and the minimum shared/language-neutral integration contracts required by those components.

The separate **HooshiX Control Panel** is external and is not implemented in this repository.

## Current repository boundaries

```text
contracts/v1/           Agent↔Gateway protocol v1 + external Control Panel integration contracts/fixtures
internal/agent/          Edge Agent implementation boundary; no product runtime behavior yet
internal/gateway/        AG-4 Tunnel Gateway data-plane runtime
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

The runtime gate is fail-closed. AG-4 now exercises the real `cmd/gateway` process over TLS/WSS with authenticated tunnel ingress. Any additional runnable capability must add its own approved runtime procedure instead of treating compilation or tests as runtime evidence.

## Tunnel Gateway runtime

AG-4 introduces the first runnable product capability: `cmd/gateway`. It serves TLS-only HTTPS/WSS, authenticates protocol-v1 Agent sessions against validated external metadata, multiplexes bounded logical streams, routes public HTTP ingress by externally supplied hostname assignments, and emits bounded status/traffic signals.

Operational details and the read-only external metadata snapshot layout are documented in `docs/runtime/gateway.md`. The Edge Agent product remains AG-5 work.
