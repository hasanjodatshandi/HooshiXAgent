package contractv1

import (
	"testing"
	"time"
)

func TestProtocolSequenceGapRejected(t *testing.T) {
	var tracker SequenceTracker
	if err := tracker.Accept(1); err != nil {
		t.Fatalf("accept first sequence: %v", err)
	}
	if err := tracker.Accept(3); err == nil {
		t.Fatal("sequence gap accepted: receiver must require exactly last+1")
	}
	if tracker.Last() != 1 {
		t.Fatalf("rejected sequence changed tracker state: last=%d", tracker.Last())
	}
}

func TestProtocolInvalidUTF8Rejected(t *testing.T) {
	payload := append([]byte("{\"contract_version\":1,\"message_type\":\"stream_error\",\"code\":\"internal_error\",\"message\":\""), byte(0xff))
	payload = append(payload, []byte("\",\"retryable\":false}")...)
	if err := ValidateControlPayload(payload, 7, time.Now().UTC()); err == nil {
		t.Fatal("invalid UTF-8 control payload accepted")
	}
}

func TestProtocolDuplicateJSONKeysRejected(t *testing.T) {
	payload := []byte("{\"contract_version\":1,\"message_type\":\"stream_close\",\"reason_code\":\"cancelled\",\"reason_code\":\"completed\"}")
	if err := ValidateControlPayload(payload, 7, time.Now().UTC()); err == nil {
		t.Fatal("duplicate JSON object keys accepted")
	}
}
