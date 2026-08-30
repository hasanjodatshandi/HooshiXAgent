# Agent↔Gateway End-to-End Tunnel Acceptance — AG-6

**Status:** Current integrated acceptance contract (origin AG-6; reconciled through R-13)

AG-6 does not add Control Panel business logic, packaging, deployment, installers, update delivery or release hardening. It proves the integrated behavior of the already-implemented Edge Agent, Tunnel Gateway and AG-3 external contract boundary.

## Deterministic acceptance route

The acceptance harness uses the stable test hostname:

```text
demo.hooshix.test
```

This is a deterministic local test route, not a public Internet deployment. The HTTPS client sends that Host value to the real Gateway TLS listener. The Gateway resolves it through the same externally supplied `EndpointRouteAssignment` contract used by the product runtime.

No DNS override, Control Panel service or direct database is introduced.

## Real processes

`scripts/ci/e2e-acceptance.sh` builds and launches:

```text
real cmd/gateway process
real cmd/agent process
real loopback HTTP service
```

The harness also creates a trusted test certificate and a deterministic external metadata snapshot conforming to the AG-3 device/session authorization and endpoint-route contracts.

The Agent is initialized and configured only through its shipped CLI. The session token is passed through stdin and the public Ed25519 key emitted by `agent init` is injected into the external authorization fixture. The private key remains in Agent local secret storage.

## Required positive path

The acceptance gate proves all of the following:

1. the Gateway starts with verified TLS;
2. a valid external authorization and route assignment are injected through the defined contract boundary;
3. before an Agent is authenticated, the valid public route returns `503`;
4. the real Agent authenticates to the real Gateway over WSS/TLS;
5. a request for `demo.hooshix.test` reaches the configured approved loopback service;
6. the local service response is returned through Agent → Gateway → public HTTPS client;
7. an unknown public hostname returns `404`;
8. after a Gateway process restart, the still-running Agent reconnects automatically and the same route works again;
9. after an Agent process restart using the same state directory, the persisted identity is unchanged and the route works again;
10. stopping the Agent makes the route unavailable with `503` until it reconnects.

## Security-negative acceptance

The AG-6 gate also proves:

- a mismatched session token cannot authenticate an Agent;
- an external route record containing an unexpected raw `local_target` field is rejected by strict contract parsing and does not route;
- an externally supplied `local_endpoint_id` that is not locally approved by the Agent cannot reach a local service;
- the external/public side never gains raw local-target authority;
- the Agent session token does not appear in captured status output or Agent/Gateway runtime logs.

The lower-level AG-3/AG-4/AG-5 protocol, replay, TLS, SSRF and resource-bound tests remain required and are not replaced by this E2E gate.

## Control Panel boundary

The separate HooshiX Control Panel is represented only by deterministic versioned contract records. AG-6 contains no user registration, tenant management, endpoint CRUD API/UI, quotas, billing, Control Panel database or Control Panel service.

## Current follow-on coverage

This E2E gate remains focused on the integrated tunnel path and does not replace other current gates. Packaging/native persistence and Docker Compose+Caddy deployment are implemented and verified by `scripts/ci/packaging-ops.sh`. Release-level exhaustion, forced network interruption/reconnect, fresh-process persisted-state recovery, update/rollback checks and artifact/provenance security are implemented by `scripts/ci/release-gate.sh` and documented in `docs/runtime/security-resilience-release-gate.md`.

The external Control Panel remains outside all of those gates.
