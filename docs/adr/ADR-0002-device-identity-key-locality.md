# ADR-0002: Per-Device Ed25519 Identity and Key Locality

Status: Accepted
Date: 2026-08-29

## Context:

The Edge Agent must authenticate as a distinct device without shipping a shared fleet credential. The approved security standard requires a unique Ed25519 identity per install and requires the device private key to remain on that device.

## Decision:

Each Edge Agent installation creates and uses a unique Ed25519 key pair as its device identity.

The private key never leaves the device. Shared fleet-wide private keys are prohibited. The Agent may consume externally issued, scoped authorization/enrollment material, but that material does not transfer ownership of the device private key to the external Control Panel or Gateway.

OS-specific secure-storage implementation details are deferred to the Edge Agent implementation leaf; AG-1 fixes only the identity algorithm and private-key locality/trust boundary.

## Alternatives:

- One shared Agent private key: rejected because compromise would affect the fleet and violates the security standard.
- Exporting device private keys to the Gateway or Control Panel: rejected because it violates the approved trust boundary.
- Replacing Ed25519 with another primary device identity scheme: not selected; it requires an explicitly approved architecture change and a superseding ADR.

## Consequences:

Device authentication can be scoped to a single installation and compromised credentials can be isolated from other devices. Platform-specific secure storage still needs to be implemented and verified later.

## Security impact:

Private-key confidentiality on the device is mandatory. Authorization/enrollment material must be short-lived, scoped, replay-resistant, and one-time where specified by the external contract. Secrets must not appear in logs, diagnostics, or evidence.

## Reliability/performance impact:

Identity creation and loading must be deterministic for one installation and must survive the persistence lifecycle required by later Agent work. No fleet-wide secret dependency is introduced.

## Compatibility/migration impact:

Changing the primary device identity algorithm or key-ownership boundary requires a new accepted ADR and any required Durable Plan change.

## Verification / fitness functions:

- Architecture documentation states unique Ed25519 identity per install.
- Architecture documentation states the private key never leaves the device.
- No Control Panel or Gateway component is assigned ownership of the Agent private key.
- Later Agent implementation must provide secure local persistence without changing this trust boundary.

## Rollback/supersession:

Supersession requires a new accepted ADR and any required user-approved plan change.

## Related ADRs:

- ADR-0003 — external Control Panel integration boundary
