package contractv1

import "errors"

// TunnelSubprotocol is the single supported Agent/Gateway wire contract. It
// includes bound resume proofs and TCP stream half-close semantics.
const TunnelSubprotocol = "hooshix.tunnel.v1"

// ValidateReadyNegotiation supplements structural payload validation with the
// capability selected by the TLS-protected WebSocket handshake.
func ValidateReadyNegotiation(ready SessionReady, subprotocol string) error {
	if subprotocol == TunnelSubprotocol {
		return validateRawBase64Length("resume_challenge", ready.ResumeChallenge, 32)
	}
	return errors.New("required tunnel subprotocol was not negotiated")
}
