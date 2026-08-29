# HooshiXAgent

HooshiXAgent is the Go repository for the installable **Edge Agent**, the server-side **Tunnel Gateway**, and the minimum shared/language-neutral integration contracts required by those components.

The separate **HooshiX Control Panel** is external and is not implemented in this repository.

## Current repository boundaries

```text
contracts/v1/           Agent↔Gateway protocol v1 + external Control Panel integration contracts/fixtures
internal/agent/          AG-5 Edge Agent product runtime
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

AG-4/AG-5 now provide the runnable Tunnel Gateway and Edge Agent. The external Control Panel remains out of this repository.

## Local baseline checks

The repository targets **Go 1.27.x**. With the required tools installed:

```bash
scripts/ci/go-quality.sh
scripts/ci/security.sh
scripts/ci/runtime-gate.sh
```

The runtime gate is fail-closed. AG-5 now exercises the real `cmd/gateway` and `cmd/agent` processes over TLS/WSS with authenticated public-to-loopback tunnel traffic and Agent identity persistence/reconnect. Any additional runnable capability must add its own approved runtime procedure instead of treating compilation or tests as runtime evidence.

## Tunnel Gateway runtime

AG-4 introduces the first runnable product capability: `cmd/gateway`. It serves TLS-only HTTPS/WSS, authenticates protocol-v1 Agent sessions against validated external metadata, multiplexes bounded logical streams, routes public HTTP ingress by externally supplied hostname assignments, and emits bounded status/traffic signals.

Operational details and the read-only external metadata snapshot layout are documented in `docs/runtime/gateway.md`. The Edge Agent product remains AG-5 work.

## Edge Agent runtime

AG-5 introduces `cmd/agent` with persistent per-install Ed25519 identity, protected local secret state, WSS/TLS authentication/reconnect, loopback-only local endpoint mappings, bounded stream proxying, and `init/configure/expose/status/doctor/service-spec/update-info` foundations.

Operational and security details are documented in `docs/runtime/agent.md`. Full installer/service installation, signed update delivery and release packaging remain AG-7 work.

## Agent↔Gateway E2E acceptance

AG-6 adds a blocking deterministic E2E acceptance gate for the real `cmd/agent` and `cmd/gateway` binaries. It validates external contract metadata injection, the stable `demo.hooshix.test` test route, a real HTTPS→Gateway→WSS→Agent→loopback-service request, Agent/Gateway restart recovery, offline/error behavior and security-negative routing/auth cases. See `docs/runtime/agent-gateway-e2e-acceptance.md`.
