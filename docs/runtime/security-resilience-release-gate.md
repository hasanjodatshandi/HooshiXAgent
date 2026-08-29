# AG-8 Security, Resilience and Agent/Gateway Release Gate

**Status:** Final HooshiXAgent release-acceptance contract

AG-8 is an acceptance/hardening leaf for the existing Edge Agent and Tunnel Gateway. It does not introduce the external HooshiX Control Panel, user/tenant authorization, quotas, billing, Control Panel persistence or Control Panel security testing.

No new architecture decision is introduced by AG-8. Current ADR-0001 through ADR-0010 remain authority.

## Release claim rule

A release-ready claim is prohibited unless every required AG-8 prerequisite and final gate is `Passed`.

The final CI job `AG-8 final security / resilience / release gate` uses explicit `needs` dependencies on:

- Go quality/tests/vulnerability scanning;
- all three Agent platform jobs;
- architecture fitness;
- Gitleaks/Semgrep;
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
- bounded reconnect behavior from the existing Agent runtime tests.

These tests intentionally use low deterministic limits rather than attempting uncontrolled host exhaustion.

## Resilience acceptance

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

AG-8 completes this Durable Plan only when:

1. PR CI is fully green including the final dependency-chained release gate;
2. the PR is merged to `main`;
3. merged-main CI is fully green on the merge SHA;
4. applicable post-merge runtime, E2E and release gates are rerun successfully;
5. no required evidence is `Failed`, `Not run`, `Partially verified`, `Inconclusive` or `Not verified` unless the check is genuinely `Not applicable` under the approved scope.
