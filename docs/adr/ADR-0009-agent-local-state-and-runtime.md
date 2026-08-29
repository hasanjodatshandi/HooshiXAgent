# ADR-0009: Edge Agent Local State, Secret Storage and Runtime Model

Status: Accepted
Date: 2026-08-29

## Context:

AG-5 introduces the first runnable Edge Agent. Existing authority already fixes a unique per-install Ed25519 identity, private-key locality, outbound WSS/TLS transport, protocol-v1 framing, bounded stream multiplexing, the Agent-owned local target policy, and the external Control Panel boundary.

AG-5 therefore needs concrete local-state, secret-storage, reconnect, endpoint-mapping, OS-persistence-foundation and update-foundation rules without pulling packaging/release work from AG-7 or end-to-end acceptance from AG-6.

## Decision:

The Agent stores non-secret runtime configuration in a per-install state directory and stores secret material through a platform secret-store implementation.

Secret material is limited to:

- the 32-byte Ed25519 seed for the unique device identity;
- the currently configured short-lived session token received from the external Control Panel flow.

On Windows, the secret payload is encrypted with DPAPI for the current user before being written to the private state directory. On Unix-like systems used by the MVP, the secret payload is stored only inside a private state directory with mode `0700` and a secret file with mode `0600`; symlink secret files are rejected. This filesystem protection intentionally works for headless service accounts and survives restart without requiring a desktop keyring session. A later change to the identity algorithm, private-key ownership boundary, or secret-store trust model requires the applicable ADR process.

The non-secret configuration contains only the WSS Gateway URL, optional custom trusted CA file, externally assigned device/authorization/token identifiers, locally owned endpoint mappings, and update channel. The raw session token and private key seed are never written to the normal config file or emitted by status/doctor output.

A local endpoint mapping is `local_endpoint_id -> host:port`. AG-5 accepts only literal loopback addresses in `127.0.0.0/8`, `::1`, or the literal hostname `localhost`. `localhost` is dialed only as the fixed loopback candidates `127.0.0.1` and `::1`; arbitrary DNS resolution, LAN addresses, link-local addresses, metadata endpoints, schemes, files, named pipes, Unix sockets and raw targets received from the Gateway are rejected.

The Agent consumes only the externally issued identifiers/session token required by the AG-3 contract. It does not implement enrollment/account/device-management server logic.

The Agent maintains one outbound WSS session to the configured Gateway and implements protocol-v1 authentication, heartbeat responses, strict sequence/replay validation, bounded stream handling, and TCP proxying to the locally approved endpoint mapping. Connection loss triggers bounded exponential reconnect backoff with a fixed maximum delay and context cancellation; a successful authenticated session resets the backoff.

AG-5 introduces stable per-user state-path selection, native service-spec generation, build/update metadata and update-candidate validation as installer/update foundations. It does not install OS services, build installers, download/apply updates, sign releases, or implement rollback; those remain AG-7/AG-8 work.

## Alternatives:

- Store the private key/session token in the normal config file: rejected because secrets must not mix with ordinary configuration or diagnostics.
- Let the Gateway send raw local addresses: rejected because it violates ADR-0006 and the SSRF policy.
- Permit arbitrary DNS names or LAN targets: rejected for MVP because only loopback targets are approved.
- Add Control Panel enrollment/account APIs to the Agent: rejected because the Control Panel is external.
- Install services or implement self-update delivery in AG-5: rejected because packaging/release/update delivery belongs to AG-7.

## Consequences:

One Agent installation has stable local identity and configuration across process restarts. The external Control Panel may rotate authorization/session credentials without receiving the private key. Local exposure remains explicit and Agent-owned.

## Security impact:

The implementation must preserve `0700`/`0600` Unix permissions, Windows DPAPI protection, symlink rejection, no secret logging, strict WSS/TLS verification, bounded reconnect/session/stream resources, protocol replay rejection and loopback-only target validation.

## Reliability/performance impact:

A long-running Agent retries connection with bounded backoff, keeps only bounded active streams/queues and uses finite dial/write/idle timeouts. Process restart reloads the same identity/config/secret state. Full OS reboot acceptance remains a later release gate.

## Compatibility/migration impact:

The state/config format is versioned. Incompatible on-disk format changes require explicit migration handling in a later leaf. Service installation and signed-update formats are not fixed by AG-5.

## Verification / fitness functions:

- Initializing the same state directory twice returns the same Ed25519 public identity.
- Secret files on Unix are private and reject unsafe permissions/symlink substitution; Windows builds use DPAPI.
- Status/doctor output never contains the raw session token or private seed.
- SSRF tests reject LAN, link-local, metadata, wildcard, schemes, sockets and arbitrary hostnames.
- Real Agent and Gateway processes establish an authenticated WSS tunnel and proxy a real local HTTP request.
- Agent process restart with the same state directory restores the same identity and reconnects.
- Cross-platform Agent builds succeed for Linux, Windows and macOS targets.

## Rollback/supersession:

Supersession requires a new Accepted ADR and any required Durable Plan change.

## Related ADRs:

- ADR-0001 — Agent↔Gateway transport
- ADR-0002 — per-device Ed25519 identity and key locality
- ADR-0005 — bounded stream multiplexing
- ADR-0006 — routing ownership
- ADR-0007 — protocol v1
- ADR-0008 — Gateway runtime state and ingress model
