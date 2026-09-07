package contractv1

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestResumeSessionContractValidation(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resume := ResumeSession{
		ContractVersion: ProtocolVersion,
		MessageType:     "resume_session",
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		SessionID:       "session-001",
		ResumeNonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	resume.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ResumeTranscript(resume)))

	data, err := json.Marshal(resume)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateControlPayload(data, 0, fixtureTime); err != nil {
		t.Fatalf("valid resume_session rejected: %v", err)
	}
	if err := ValidateControlPayload(data, 7, fixtureTime); err == nil {
		t.Fatal("resume_session on stream scope must be rejected")
	}
	if err := VerifyResumeSignature(base64.RawURLEncoding.EncodeToString(publicKey), resume); err != nil {
		t.Fatalf("resume signature verification failed: %v", err)
	}

	// Wrong key must fail verification.
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResumeSignature(base64.RawURLEncoding.EncodeToString(otherPublic), resume); err == nil {
		t.Fatal("resume signature verified with wrong key")
	}

	resumed := []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z"}`)
	if err := ValidateControlPayload(resumed, 0, fixtureTime); err != nil {
		t.Fatalf("valid session_resumed rejected: %v", err)
	}
	if err := ValidateControlPayload(resumed, 7, fixtureTime); err == nil {
		t.Fatal("session_resumed on stream scope must be rejected")
	}

	invalid := []struct {
		name    string
		payload []byte
	}{
		{"zero next_sequence", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":0,"resumed_at":"2026-08-29T12:00:00Z"}`)},
		{"missing resumed_at", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5}`)},
		{"bad resumed_at", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"nope"}`)},
		{"unknown field", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z","extra":1}`)},
		{"resume unknown field", append(data[:len(data)-1], []byte(`,"extra":true}`)...)},
		{"resume bad nonce", []byte(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"short","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateControlPayload(test.payload, 0, fixtureTime); err == nil {
				t.Fatalf("invalid payload accepted: %s", test.name)
			}
		})
	}
}

func TestResumeTranscriptIsDeterministic(t *testing.T) {
	t.Parallel()

	resume := ResumeSession{
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		SessionID:       "session-001",
		ResumeNonce:     "nonce-abc",
	}
	first := ResumeTranscript(resume)
	second := ResumeTranscript(resume)
	if string(first) != string(second) {
		t.Fatal("resume transcript is not deterministic")
	}
	resume.ResumeNonce = "nonce-other"
	if string(ResumeTranscript(resume)) == string(first) {
		t.Fatal("resume transcript ignored nonce change")
	}
}
