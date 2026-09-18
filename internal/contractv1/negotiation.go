package contractv1

import "errors"

// ResumeProofSubprotocol negotiates the extended session_ready and bound resume
// exchange without changing the strict baseline protocol-v1 handshake shape.
const ResumeProofSubprotocol = "hooshix.resume-proof.v1"

// ValidateReadyNegotiation supplements structural payload validation with the
// capability selected by the TLS-protected WebSocket handshake.
func ValidateReadyNegotiation(ready SessionReady, subprotocol string) error {
	if subprotocol == ResumeProofSubprotocol {
		return validateRawBase64Length("resume_challenge", ready.ResumeChallenge, 32)
	}
	if ready.ResumeChallenge != "" {
		return errors.New("resume challenge without negotiated resume-proof extension")
	}
	return nil
}
