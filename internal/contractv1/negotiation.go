package contractv1

import "errors"

// TunnelSubprotocol is the compatible Agent/Gateway wire contract. It includes
// bound resume proofs and TCP stream half-close semantics.
const TunnelSubprotocol = "hooshix.tunnel.v1"

// TunnelSubprotocolV2 adds credit-based stream flow control (ADR-0021). The
// identifier is defined here so both peers can agree on it, but it MUST NOT be
// added to the dial/accept lists until the window message, sender accounting
// and receiver credit returns ship: negotiating v2 without them would promise
// pacing the runtime does not implement.
const TunnelSubprotocolV2 = "hooshix.tunnel.v2"

// IsTunnelSubprotocol reports whether the TLS-protected WebSocket handshake
// selected a tunnel contract this build can speak.
func IsTunnelSubprotocol(subprotocol string) bool {
	return subprotocol == TunnelSubprotocol || subprotocol == TunnelSubprotocolV2
}

// ValidateReadyNegotiation supplements structural payload validation with the
// capability selected by the TLS-protected WebSocket handshake.
func ValidateReadyNegotiation(ready SessionReady, subprotocol string) error {
	if !IsTunnelSubprotocol(subprotocol) {
		return errors.New("required tunnel subprotocol was not negotiated")
	}
	return validateRawBase64Length("resume_challenge", ready.ResumeChallenge, 32)
}
