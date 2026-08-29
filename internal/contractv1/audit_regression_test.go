package contractv1

import (
	"os"
	"testing"
	"time"
)

func requireAuditRegressionProof(t *testing.T) {
	t.Helper()
	if os.Getenv("HOOSHIX_AUDIT_REGRESSION_PROOF") != "1" {
		t.Skip("R-0 regression proof is opt-in until the corresponding runtime fixes land")
	}
}

func TestAuditRegressionSequenceGapMustBeRejected(t *testing.T) {
	requireAuditRegressionProof(t)

	var tracker SequenceTracker
	if err := tracker.Accept(1); err != nil {
		t.Fatalf("accept first sequence: %v", err)
	}
	if err := tracker.Accept(3); err == nil {
		t.Fatal("AUDIT-R0 sequence gap accepted: receiver must require exactly last+1")
	}
}

func TestAuditRegressionInvalidUTF8MustBeRejected(t *testing.T) {
	requireAuditRegressionProof(t)

	payload := append([]byte("{\"contract_version\":1,\"message_type\":\"stream_error\",\"code\":\"internal_error\",\"message\":\""), byte(0xff))
	payload = append(payload, []byte("\",\"retryable\":false}")...)
	if err := ValidateControlPayload(payload, 7, time.Now().UTC()); err == nil {
		t.Fatal("AUDIT-R0 invalid UTF-8 control payload accepted")
	}
}

func TestAuditRegressionDuplicateJSONKeysMustBeRejected(t *testing.T) {
	requireAuditRegressionProof(t)

	payload := []byte("{\"contract_version\":1,\"message_type\":\"stream_close\",\"reason_code\":\"cancelled\",\"reason_code\":\"completed\"}")
	if err := ValidateControlPayload(payload, 7, time.Now().UTC()); err == nil {
		t.Fatal("AUDIT-R0 duplicate JSON object keys accepted")
	}
}
