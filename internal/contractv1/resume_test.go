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
		ResumeChallenge: base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 9)),
		IssuedAt:        "2026-08-29T12:00:00Z",
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

	resumed := []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"` + challengeFixture + `"}`)
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
		{"zero next_sequence", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":0,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"` + challengeFixture + `"}`)},
		{"missing resumed_at", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resume_challenge":"` + challengeFixture + `"}`)},
		{"bad resumed_at", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"nope","resume_challenge":"` + challengeFixture + `"}`)},
		{"missing resume_challenge", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z"}`)},
		{"unknown field", []byte(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"` + challengeFixture + `","extra":1}`)},
		{"resume unknown field", append(data[:len(data)-1], []byte(`,"extra":true}`)...)},
		{"resume bad nonce", []byte(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"short","resume_challenge":"` + challengeFixture + `","issued_at":"2026-08-29T12:00:00Z","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`)},
		{"resume missing challenge", []byte(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","issued_at":"2026-08-29T12:00:00Z","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`)},
		{"resume stale-shaped issued_at", []byte(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","resume_challenge":"` + challengeFixture + `","issued_at":"yesterday","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`)},
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

	// ResumeTranscript re-validates its inputs, so the fixture must satisfy
	// the contract identifier and nonce patterns.
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	resume := ResumeSession{
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		SessionID:       "session-001",
		ResumeNonce:     nonce,
		ResumeChallenge: challengeFixture,
		IssuedAt:        "2026-08-29T12:00:00Z",
	}
	first := ResumeTranscript(resume)
	second := ResumeTranscript(resume)
	if len(first) == 0 {
		t.Fatal("valid resume transcript was rejected")
	}
	if string(first) != string(second) {
		t.Fatal("resume transcript is not deterministic")
	}
	resume.ResumeNonce = base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 1))
	if string(ResumeTranscript(resume)) == string(first) {
		t.Fatal("resume transcript ignored nonce change")
	}
	// The Gateway-issued challenge and the proof timestamp are bound too:
	// changing either must change the signed transcript.
	resume.ResumeNonce = nonce
	resume.ResumeChallenge = base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 7))
	if string(ResumeTranscript(resume)) == string(first) {
		t.Fatal("resume transcript ignored challenge change")
	}
	resume.ResumeChallenge = challengeFixture
	resume.IssuedAt = "2026-08-29T12:00:01Z"
	if string(ResumeTranscript(resume)) == string(first) {
		t.Fatal("resume transcript ignored issued_at change")
	}
}
