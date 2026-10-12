package agent

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
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
//
// The code list is SCANNED OUT OF THE PACKAGE SOURCE rather than hand-written,
// because the hand-written list silently fell behind the code it was meant to
// cover. A call site that passes a variable instead of a literal is checked by
// the enum test below, which validates every value the contract allows.
func TestAgentStreamErrorCodesAreContractValid(t *testing.T) {
	agentEmittedCodes := emittedStreamErrorCodes(t)
	if len(agentEmittedCodes) < 3 {
		t.Fatalf("the source scan found only %d stream_error literals (%v); the scanner is broken", len(agentEmittedCodes), agentEmittedCodes)
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

// TestEveryContractStreamErrorCodeIsValid walks the full enum from
// contracts/v1/tunnel-control.schema.json, including the codes no call site
// uses today (protocol_error, route_revoked), so the agent can adopt any
// contract-approved code without a hidden validator surprise.
func TestEveryContractStreamErrorCodeIsValid(t *testing.T) {
	for _, code := range []string{"local_target_unavailable", "route_revoked", "protocol_error", "resource_limit", "internal_error"} {
		t.Run(code, func(t *testing.T) {
			payload, err := json.Marshal(contractv1.StreamError{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_error",
				Code:            code,
				Message:         "bounded diagnostic detail",
				Retryable:       false,
			})
			if err != nil {
				t.Fatalf("marshal stream_error: %v", err)
			}
			if err := contractv1.ValidateControlPayload(payload, 7, time.Now().UTC()); err != nil {
				t.Fatalf("contract code %q rejected by the gateway validator: %v", code, err)
			}
		})
	}
}

// emittedStreamErrorCodes collects the literal codes handed to the terminal
// error senders anywhere in this package.
func emittedStreamErrorCodes(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read agent package: %v", err)
	}
	literal := regexp.MustCompile(`sendStream(?:Terminal)?Error\(\s*[^\s,]+(?:,\s*[^\s,]+)?,\s*"([a-z_]+)"`)
	seen := map[string]bool{}
	var codes []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, match := range literal.FindAllStringSubmatch(string(source), -1) {
			if !seen[match[1]] {
				seen[match[1]] = true
				codes = append(codes, match[1])
			}
		}
	}
	sort.Strings(codes)
	return codes
}

// TestPermanentPolicyViolationClassification pins the reconnect-vs-terminal
// classification of gateway policy closes: infra/health closes (idle timeout
// after sleep) must be transient; genuine breaches stay terminal.
func TestPermanentPolicyViolationClassification(t *testing.T) {
	transient := []websocket.CloseError{
		{Code: websocket.StatusPolicyViolation, Reason: "idle timeout"},
		{Code: websocket.StatusPolicyViolation, Reason: "session ended"},
		// Enrollment publishes before returning credentials, but Gateways activate
		// that generation asynchronously. The first authentication can race that
		// short propagation window and must reconnect with normal backoff.
		{Code: websocket.StatusPolicyViolation, Reason: "authentication failed"},
	}
	for _, tc := range transient {
		if permanentPolicyViolation(tc) {
			t.Errorf("policy close %q should be transient, got permanent", tc.Reason)
		}
	}

	permanent := []websocket.CloseError{
		{Code: websocket.StatusPolicyViolation, Reason: "control violation"},
		{Code: websocket.StatusPolicyViolation, Reason: "sequence violation"},
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
		{
			name:     "stream_error internal_error",
			streamID: 7,
			payload: contractv1.StreamError{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "stream_error",
				Code:            "internal_error",
				Message:         "tunneled stream send failed",
				Retryable:       false,
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
