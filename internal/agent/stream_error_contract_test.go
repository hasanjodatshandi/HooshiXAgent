package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// TestAgentStreamErrorCodesAreContractValid pins the fix for session-killing
// stream errors: every code the agent can put on the wire MUST be accepted by
// the gateway's ValidateControlPayload. A regression here (an out-of-enum
// code like local_target_read_error) makes the gateway close the whole
// session with a policy violation, terminating the Windows service.
func TestAgentStreamErrorCodesAreContractValid(t *testing.T) {
	// The codes the agent emits, from session.go (terminal error paths) —
	// keep this list in sync with the sendStreamTerminalError call sites.
	agentEmittedCodes := []string{
		"resource_limit",           // stream input budget exhausted or stalled
		"local_target_unavailable", // dial failed + mid-stream read failure/timeout
		"route_revoked",            // local endpoint not configured
	}

	for _, code := range agentEmittedCodes {
		t.Run(code, func(t *testing.T) {
			payload, err := json.Marshal(contractv1.StreamError{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_error",
				Code:            code,
				Message:         "approved local target read failed",
				Retryable:       true,
			})
			if err != nil {
				t.Fatalf("marshal stream_error: %v", err)
			}
			if err := contractv1.ValidateControlPayload(payload, 7, time.Now().UTC()); err != nil {
				t.Fatalf("agent-emitted stream_error code %q rejected by gateway validator: %v", code, err)
			}
		})
	}
}

// TestPermanentPolicyViolationClassification pins the reconnect-vs-terminal
// classification of gateway policy closes: infra/health closes (idle timeout
// after sleep) must be transient; genuine breaches stay terminal.
func TestPermanentPolicyViolationClassification(t *testing.T) {
	transient := []websocket.CloseError{
		{Code: websocket.StatusPolicyViolation, Reason: "idle timeout"},
		{Code: websocket.StatusPolicyViolation, Reason: "session ended"},
	}
	for _, tc := range transient {
		if permanentPolicyViolation(tc) {
			t.Errorf("policy close %q should be transient, got permanent", tc.Reason)
		}
	}

	permanent := []websocket.CloseError{
		{Code: websocket.StatusPolicyViolation, Reason: "control violation"},
		{Code: websocket.StatusPolicyViolation, Reason: "sequence violation"},
		{Code: websocket.StatusPolicyViolation, Reason: "authentication failed"},
		{Code: websocket.StatusPolicyViolation}, // no reason: assume breach
	}
	for _, tc := range permanent {
		if !permanentPolicyViolation(tc) {
			t.Errorf("policy close %q should be permanent, got transient", tc.Reason)
		}
	}
}

// TestAgentEmittedControlPayloadsPassGatewayValidation walks every control
// message shape the agent writes mid-session (pong, health_report,
// stream_close, stream_error) through the gateway-side validator, so any
// future contract drift between the two binaries fails here in CI instead of
// killing live sessions in production.
func TestAgentEmittedControlPayloadsPassGatewayValidation(t *testing.T) {
	now := time.Now().UTC()

	cases := []struct {
		name     string
		streamID uint32
		payload  any
	}{
		{
			name:     "pong",
			streamID: 0,
			payload: contractv1.Heartbeat{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "pong",
				PingID:          "ping-0123456789abcd",
				ReceivedAt:      now.Format(time.RFC3339),
			},
		},
		{
			name:     "health_report",
			streamID: 0,
			payload: contractv1.HealthReport{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "health_report",
				ReportID:        "report-0123456789",
				GeneratedAt:     now.Format(time.RFC3339),
				ActiveStreams:   1,
				QueuedFrames:    0,
				ReconnectCount:  3,
			},
		},
		{
			name:     "stream_close completed",
			streamID: 7,
			payload: contractv1.StreamClose{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_close",
				ReasonCode:      "completed",
			},
		},
		{
			name:     "stream_close peer_closed",
			streamID: 7,
			payload: contractv1.StreamClose{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_close",
				ReasonCode:      "peer_closed",
			},
		},
		{
			name:     "stream_error local_target_unavailable",
			streamID: 7,
			payload: contractv1.StreamError{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_error",
				Code:            "local_target_unavailable",
				Message:         "approved local target read failed",
				Retryable:       true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := contractv1.ValidateControlPayload(payload, tc.streamID, now); err != nil {
				t.Fatalf("agent-emitted control payload rejected by gateway validator: %v", err)
			}
		})
	}
}
