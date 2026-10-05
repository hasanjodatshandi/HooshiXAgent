package contractv1

import (
	"strings"
	"testing"
	"time"
)

func TestSessionReadyRequiresTunnelSubprotocolAndResumeChallenge(t *testing.T) {
	ready := []byte(`{"contract_version":1,"message_type":"session_ready","session_id":"session-current","heartbeat_interval_seconds":15,"idle_timeout_seconds":45,"resume_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	if err := ValidateControlPayload(ready, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocol, challenge string
		valid                     bool
	}{
		{"valid", TunnelSubprotocol, strings.Repeat("A", 43), true},
		{"missing challenge", TunnelSubprotocol, "", false},
		{"missing protocol", "", strings.Repeat("A", 43), false},
		{"wrong protocol", "unsupported.tunnel.v0", strings.Repeat("A", 43), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReadyNegotiation(SessionReady{ResumeChallenge: tc.challenge}, tc.protocol)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
