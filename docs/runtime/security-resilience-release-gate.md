# AG-8 Security, Resilience and Agent/Gateway Release Gate

**Status:** Final HooshiXAgent release-acceptance contract

AG-8 is an acceptance/hardening leaf for the existing Edge Agent and Tunnel Gateway. It does not introduce the external HooshiX Control Panel, user/tenant authorization, quotas, billing, Control Panel persistence or Control Panel security testing.

No new architecture decision is introduced by AG-8. Current accepted ADRs through ADR-0012 remain authority.

## Release claim rule

A release-ready claim is prohibited unless every required AG-8 prerequisite and final gate is `Passed`.

The final CI job `AG-8 final security / resilience / release gate` uses explicit `needs` dependencies on:

- Go quality/tests/vulnerability scanning;
- all three Agent platform jobs;
- architecture fitness;
- Gitleaks/Semgrep;
- R-3 resource/DoS through R-12 performance/capacity focused gates;
- real Agent↔Gateway E2E acceptance;
- packaging/clean deployment/rollback;
- executable runtime gate.

If any prerequisite fails or is skipped in a way that prevents the dependency from succeeding, the final release gate cannot run successfully.

## Security acceptance

### Local-target / SSRF

The Agent release suite permits only explicit loopback targets (`localhost`, `127.0.0.0/8`, `::1`) with valid explicit TCP ports. Adversarial cases include LAN, link-local/cloud metadata, multicast, public/ULA IPv6, arbitrary DNS, schemes, paths, named pipes and Unix sockets.

The external route contract remains opaque `local_endpoint_id` authority only. Raw `local_target` fields are rejected.

### Credential, authentication and replay

The release suite verifies:

- untrusted Gateway TLS rejection;
- wrong Agent session-token rejection;
- Ed25519 authenticated handshake behavior through existing protocol tests;
- strictly increasing sequence/replay enforcement;
- token/private-key non-disclosure in status/log evidence;
- protected local secret-state rules.

### Malformed protocol and resource exhaustion

The release suite verifies:

- malformed and oversized HXT1 frame rejection;
- strict control JSON/scope validation;
- stream/request limits;
- fail-closed pending-handshake capacity exhaustion;
- RA-2 bounded pre-authentication slot recovery plus validated per-device handshake fairness, so a silent unauthenticated flood or one authorized device cannot indefinitely monopolize every pending-handshake slot;
- bounded reconnect behavior from the existing Agent runtime tests.

These tests intentionally use low deterministic limits rather than attempting uncontrolled host exhaustion.

## Resilience acceptance

### Live authorization metadata lifecycle

RA-3 adds a blocking real-process gate for the ADR-0012 live external metadata projection. The release chain now requires atomic higher-revision route activation without Gateway restart, fixed freshness expiry that cannot be extended by polling the same revision, fail-closed readiness/new routing during stale authority, recovery on a newer valid generation, and bounded termination of an existing authenticated session after a live effective revocation. The external publisher remains out of repository scope and no Control Panel business/database code is introduced.

### Multi-host public edge

RA-4 adds a blocking real Compose/Caddy acceptance for ADR-0011. The production/default Caddyfile must use restricted On-Demand TLS with an external `ask` permission URL and must fail configuration when that URL is absent rather than falling back to unrestricted issuance. The gate uses a test-only internal issuer and permission mock to avoid public CA traffic while preserving the production authorization structure. It proves two approved hostnames simultaneously reach two distinct Agent-owned local endpoints, a TLS-approved hostname with no Gateway route remains `404`, an unknown hostname cannot complete TLS or appear in certificate storage, public `/readyz` and `/metrics` remain `404`, and both dynamic and static compatibility configurations preserve certificate-verified Caddy→Gateway HTTPS. No Control Panel permission service or domain-ownership business logic is implemented in this repository.

### Network interruption

A real TCP interruption proxy is inserted on the Agent→Gateway transport path while the Gateway and public ingress remain running. AG-8 proves:

1. the real Agent establishes and serves a tunnel;
2. the transport path is forcibly interrupted;
3. the public route fails closed while the Agent is disconnected;
4. the path remains unavailable through at least one reconnect attempt;
5. transport is restored;
6. the real Agent reconnects automatically and the tunnel recovers.

### Gateway restart

The existing blocking Agent↔Gateway E2E gate stops and restarts the real Gateway while the real Agent remains running and proves automatic reconnect/recovery.

### Agent cold restart and OS persistence boundary

AG-8 proves a fresh Agent process using the same persisted state reconnects with the same Ed25519 identity after the previous process is completely stopped. Platform CI simultaneously verifies the packaged native persistence definitions on Ubuntu, macOS and Windows:

- Linux `systemd --user`;
- macOS LaunchAgent;
- Windows current-user logon Scheduled Task.

GitHub-hosted CI cannot safely reboot and then resume the same ephemeral runner job. Therefore the automated release evidence does **not** claim that a physical hosted runner reboot occurred; it verifies the two properties required across a reboot boundary: native startup registration and a fresh process recovering from persisted identity/config/credentials. A literal hardware/VM reboot, if required by a deployment operator, is an environment-specific operational smoke check rather than fabricated CI evidence.

## Update and rollback acceptance

The Agent continues to use explicit verified package promotion rather than autonomous update download/application.

AG-8 verifies:

- update metadata is platform-matched;
- update URLs are absolute HTTPS without userinfo;
- SHA-256 format is strict;
- insecure/malformed update candidates fail closed;
- packaged installers preserve a previous binary;
- previous-binary rollback succeeds on Linux, macOS and Windows platform CI;
- clean Gateway Compose deployment succeeds;
- release artifacts pass `SHA256SUMS` verification;
- a deliberately modified release artifact fails checksum verification.

## Artifact and secret security

Release archives are inspected to prevent accidental inclusion of:

- `.git` repository history;
- generated deployment CA private key/runtime TLS state;
- Control Panel implementation trees;
- user/tenant/quota/billing/migration implementation trees.

Gitleaks and Semgrep remain blocking. GitHub release provenance remains OIDC-backed Artifact Attestations, and the release workflow verifies attestation identity before publication.

## Evidence artifact

The final CI job uploads a small `AG8-EVIDENCE.txt` artifact tied to the Git commit. It contains only gate results and commit identity; no tokens, private keys, payloads or personally identifying data are written to release evidence.

## Completion boundary

The AG-8 release-acceptance leaf is considered complete only when:

1. PR CI is fully green including the final dependency-chained release gate;
2. the PR is merged to `main`;
3. merged-main CI is fully green on the merge SHA;
4. applicable post-merge runtime, E2E and release gates are rerun successfully;
5. no required evidence is `Failed`, `Not run`, `Partially verified`, `Inconclusive` or `Not verified` unless the check is genuinely `Not applicable` under the approved scope.

## R-6 release supply-chain prerequisite

The final CI release gate is now additionally dependency-chained behind `R-6 release / supply-chain gate`. That gate proves immutable third-party Action pins, digest-pinned external container bases, negative exact-commit release-policy behavior, privilege separation between read-only build/test jobs and the privileged publish job, SPDX SBOM generation and vulnerability scanning of the release archives and final Gateway image candidate. Tag publication independently rechecks exact-commit CI evidence before any publish privilege is used.
