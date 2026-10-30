package contractv1

import (
	"strings"
	"testing"
	"time"
)

func TestIsTunnelSubprotocolAcceptsOnlyKnownContracts(t *testing.T) {
	for _, protocol := range []string{TunnelSubprotocol, TunnelSubprotocolV2} {
		if !IsTunnelSubprotocol(protocol) {
			t.Fatalf("known subprotocol %q was rejected", protocol)
		}
	}
	for _, protocol := range []string{"", "hooshix.tunnel.v0", "hooshix.tunnel.v2-preview", "hooshix.tunnel.v1 "} {
		if IsTunnelSubprotocol(protocol) {
			t.Fatalf("unknown subprotocol %q was accepted", protocol)
		}
	}
}

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
		{"valid v2", TunnelSubprotocolV2, strings.Repeat("A", 43), true},
		{"missing challenge", TunnelSubprotocol, "", false},
		{"missing challenge v2", TunnelSubprotocolV2, "", false},
		{"missing protocol", "", strings.Repeat("A", 43), false},
		{"wrong protocol", "unsupported.tunnel.v0", strings.Repeat("A", 43), false},
		{"v1 prefix only", "hooshix.tunnel.v1-preview", strings.Repeat("A", 43), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReadyNegotiation(SessionReady{ResumeChallenge: tc.challenge}, tc.protocol)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
