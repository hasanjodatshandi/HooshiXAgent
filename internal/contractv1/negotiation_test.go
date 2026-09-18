package contractv1

import (
	"strings"
	"testing"
	"time"
)

func TestSessionReadyCapabilityNegotiation(t *testing.T) {
	legacy := []byte(`{"contract_version":1,"message_type":"session_ready","session_id":"session-legacy","heartbeat_interval_seconds":15,"idle_timeout_seconds":45}`)
	if err := ValidateControlPayload(legacy, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocol, challenge string
		valid                     bool
	}{
		{"legacy", "", "", true},
		{"negotiated", ResumeProofSubprotocol, strings.Repeat("A", 43), true},
		{"missing negotiated proof", ResumeProofSubprotocol, "", false},
		{"unsolicited extension", "", strings.Repeat("A", 43), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReadyNegotiation(SessionReady{ResumeChallenge: tc.challenge}, tc.protocol)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
