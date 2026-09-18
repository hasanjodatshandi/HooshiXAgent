# ADR-0015: Negotiate the bounded resume-proof extension

Status: Accepted
Date: 2026-09-17

## Context

The user authorized remediation of the audit findings and a local exception to
the unavailable Durable Plan workflow in this conversation. Making
`session_ready.resume_challenge` mandatory without negotiation broke protocol-v1
rolling upgrades. Accepting unsigned or unbound legacy resume proofs is unsafe.

## Decision

Keep baseline protocol-v1 framing and the full Ed25519 handshake unchanged.
Negotiate `hooshix.resume-proof.v1` through the TLS-protected WebSocket
subprotocol handshake. Only a connection selecting that subprotocol may receive
the extended session_ready and use resume_session/session_resumed. On that
connection the 32-byte challenge is mandatory. Without negotiation the Gateway
emits the original session_ready shape and the Agent always uses full
authentication. Absence of the extension never enables legacy resume proofs.

## Alternatives

A flag-day v2-only rollout rejects installed v1 Agents. An optional proof with
implicit downgrade is rejected. TLS subprotocol negotiation supports gradual
rollout without inventing an unauthenticated application negotiation exchange.

## Consequences

New Gateway/old Agent and new Agent/old Gateway use full authentication. New/new
peers use the extension. Strict field, signature, freshness, one-shot challenge,
authorization, and resource checks remain in force.

## Security impact

No new authority or insecure transport. Resume without the negotiated extension
is refused; suppression of the extension can only select the existing full
authentication path. Both messages and proof remain bound to verified TLS.

## Reliability/performance impact

Legacy peers pay the full handshake cost. Both handshake paths are bounded by
HandshakeTimeout. No new shared store or coordination component.

## Compatibility/migration impact

Deploy the Gateway and Agent in either order. The existing external Control Panel
contract and local state format stay unchanged. Incompatible future extension
changes need a new subprotocol identifier or framing version.

## Verification / fitness functions

Test both mixed-version full handshakes, negotiated resume, a missing negotiated
challenge, and refusal of unnegotiated/legacy resume. Preserve replay tests.

## Rollback/supersession

Either side may roll back to baseline v1 full authentication. Do not roll back
to insecure legacy resume proofs. ADR-0007 baseline wire rules remain effective;
this ADR specifies the opt-in extension boundary.

## Related ADRs

ADR-0001, ADR-0002, ADR-0007, ADR-0013.
