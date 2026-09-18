package contractv1

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestConsumeJSONValueRejectsClosingDelimiter covers the defensive branch of
// the JSON walker directly. json.Decoder never hands a closing delimiter to the
// value walker, so this is the only way to exercise the decoder/walker
// disagreement guard.
func TestConsumeJSONValueRejectsClosingDelimiter(t *testing.T) {
	t.Parallel()

	for _, delim := range []json.Delim{'}', ']'} {
		decoder := json.NewDecoder(strings.NewReader(`{"a":1}`))
		if err := consumeJSONValue(decoder, delim); err == nil {
			t.Fatalf("closing delimiter %q was treated as a value", delim)
		}
	}

	decoder := json.NewDecoder(strings.NewReader(`{"a":1}`))
	if err := consumeJSONValue(decoder, "scalar"); err != nil {
		t.Fatalf("scalar value token rejected: %v", err)
	}
	decoder = json.NewDecoder(strings.NewReader(`{"a":1}`))
	if err := consumeJSONValue(decoder, nil); err != nil {
		t.Fatalf("null value token rejected: %v", err)
	}
}

// TestNonCanonicalBase64URLRejected asserts the canonicality rule stated in
// tunnel-protocol.md section 5. A non-canonical encoding decodes to the right
// byte count, so only the re-encode comparison can reject it.
func TestNonCanonicalBase64URLRejected(t *testing.T) {
	t.Parallel()

	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	nonCanonical := canonical[:len(canonical)-1] + "B"
	if nonCanonical == canonical {
		t.Fatal("test fixture is not a distinct encoding")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonCanonical)
	if err != nil {
		t.Fatalf("non-canonical value did not decode: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("non-canonical value decoded to %d bytes want 32", len(decoded))
	}

	hello := []byte(`{"contract_version":1,"message_type":"client_hello","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_token":"test_session_token_0123456789ABCDEF","client_nonce":"` + canonical + `"}`)
	if err := ValidateControlPayload(hello, 0, fixtureTime); err != nil {
		t.Fatalf("canonical client_nonce rejected: %v", err)
	}
	aliased := []byte(strings.Replace(string(hello), canonical, nonCanonical, 1))
	if err := ValidateControlPayload(aliased, 0, fixtureTime); err == nil {
		t.Fatal("non-canonical client_nonce accepted")
	}

	resume := ResumeSession{
		ContractVersion: ProtocolVersion,
		MessageType:     "resume_session",
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		SessionID:       "session-001",
		ResumeNonce:     nonCanonical,
		ResumeChallenge: challengeFixture,
		IssuedAt:        issuedAtFixture,
		Signature:       base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
	payload, err := json.Marshal(resume)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateControlPayload(payload, 0, fixtureTime); err == nil {
		t.Fatal("non-canonical resume_nonce accepted")
	}
	// The transcript construction must not accept the same input either.
	if ResumeTranscript(resume) != nil {
		t.Fatal("ResumeTranscript accepted a non-canonical nonce")
	}
}

// TestHostnameValidationRejectsInvalidValues asserts rejection directly; the
// fuzz target only proves determinism.
func TestHostnameValidationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	valid := []string{
		"demo.hooshix.example",
		"a.example",
		"EXAMPLE.COM",
		"a-b.example",
		"xn--bcher-kva.example",
	}
	for _, hostname := range valid {
		if err := validateHostname(hostname); err != nil {
			t.Errorf("validateHostname(%q) rejected a valid public hostname: %v", hostname, err)
		}
	}

	invalid := []string{
		"localhost",           // single label
		"a.b",                 // one-letter top-level label
		"example.c",           // one-letter top-level label
		"example.c0m",         // digit in the top-level label
		"-bad.example",        // leading hyphen
		"bad-.example",        // trailing hyphen
		"bad..example",        // empty label
		".example.com",        // empty leading label
		"example.com.",        // trailing dot
		"127.0.0.1",           // top-level label is not alphabetic
		"münich.example",      // non-ASCII
		"under_score.example", // underscore
		"",                    // empty
		strings.Repeat("a", 64) + ".example",
		strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 62)}, "."), // 254 bytes
	}
	for _, hostname := range invalid {
		if err := validateHostname(hostname); err == nil {
			t.Errorf("validateHostname(%q) accepted an invalid hostname", hostname)
		}
	}
}

// TestExternalEvaluatorsRejectDisabledAndNotYetValid covers the fail-closed
// paths of the …At evaluators that the expired-fixture test does not reach.
func TestExternalEvaluatorsRejectDisabledAndNotYetValid(t *testing.T) {
	t.Parallel()

	authorization := func(disabled bool, notBefore string) []byte {
		payload := map[string]any{
			"contract_version":  ProtocolVersion,
			"authorization_id":  "auth-001",
			"device_id":         "device-001",
			"device_public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
			"token_id":          "token-001",
			"token_sha256":      tokenSHA256Fixture,
			"issued_at":         "2026-08-29T06:00:00Z",
			"not_before":        notBefore,
			"expires_at":        "2026-08-30T06:00:00Z",
			"disabled":          disabled,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	route := func(enabled bool, notBefore string) []byte {
		payload := map[string]any{
			"contract_version":  ProtocolVersion,
			"assignment_id":     "assign-001",
			"endpoint_id":       "endpoint-001",
			"public_hostname":   "demo.hooshix.example",
			"device_id":         "device-001",
			"local_endpoint_id": "local-http-001",
			"enabled":           enabled,
			"not_before":        notBefore,
			"expires_at":        "2026-08-30T06:00:00Z",
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	// Positive controls: an active, enabled record must be accepted at the
	// fixture instant.
	if _, err := ParseDeviceSessionAuthorization(authorization(false, "2026-08-29T06:00:00Z"), fixtureTime); err != nil {
		t.Fatalf("active authorization rejected: %v", err)
	}
	if _, err := ParseEndpointRouteAssignment(route(true, "2026-08-29T06:00:00Z"), fixtureTime); err != nil {
		t.Fatalf("active route assignment rejected: %v", err)
	}

	if _, err := ParseDeviceSessionAuthorization(authorization(true, "2026-08-29T06:00:00Z"), fixtureTime); err == nil {
		t.Fatal("disabled authorization accepted")
	}
	if _, err := ParseDeviceSessionAuthorization(authorization(false, "2026-08-29T13:00:00Z"), fixtureTime); err == nil {
		t.Fatal("authorization evaluated before not_before accepted")
	}
	if err := ValidateDeviceSessionAuthorizationAt(
		DeviceSessionAuthorization{Disabled: true, NotBefore: "2026-08-29T06:00:00Z", ExpiresAt: "2026-08-30T06:00:00Z"},
		fixtureTime,
	); err == nil {
		t.Fatal("ValidateDeviceSessionAuthorizationAt accepted a disabled record")
	}

	if _, err := ParseEndpointRouteAssignment(route(false, "2026-08-29T06:00:00Z"), fixtureTime); err == nil {
		t.Fatal("disabled route assignment accepted")
	}
	if _, err := ParseEndpointRouteAssignment(route(true, "2026-08-29T13:00:00Z"), fixtureTime); err == nil {
		t.Fatal("route assignment evaluated before not_before accepted")
	}
	if err := ValidateEndpointRouteAssignmentAt(
		EndpointRouteAssignment{Enabled: false, NotBefore: "2026-08-29T06:00:00Z", ExpiresAt: "2026-08-30T06:00:00Z"},
		fixtureTime,
	); err == nil {
		t.Fatal("ValidateEndpointRouteAssignmentAt accepted a disabled record")
	}

	// The exclusive end of the interval: exactly expires_at is not valid.
	exactExpiry := time.Date(2026, 8, 30, 6, 0, 0, 0, time.UTC)
	if err := ValidateDeviceSessionAuthorizationAt(
		DeviceSessionAuthorization{NotBefore: "2026-08-29T06:00:00Z", ExpiresAt: "2026-08-30T06:00:00Z"},
		exactExpiry,
	); err == nil {
		t.Fatal("authorization accepted at exactly expires_at")
	}
}

// TestTranscriptRejectsUnvalidatedInputs proves the NUL-delimiter safety
// argument is local to the transcript constructors: an input that violates the
// identifier patterns yields an unusable transcript without any prior decoder
// call.
func TestTranscriptRejectsUnvalidatedInputs(t *testing.T) {
	t.Parallel()

	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	validResume := ResumeSession{
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		SessionID:       "session-001",
		ResumeNonce:     nonce,
		ResumeChallenge: challengeFixture,
		IssuedAt:        issuedAtFixture,
	}
	if len(ResumeTranscript(validResume)) == 0 {
		t.Fatal("valid resume transcript was rejected")
	}

	// A NUL inside an identifier is the delimiter-ambiguity case: without the
	// local re-validation, ("a\x00b", "c") and ("a", "b\x00c") would produce the
	// same transcript.
	ambiguous := validResume
	ambiguous.DeviceID = "device\x00-001"
	if ResumeTranscript(ambiguous) != nil {
		t.Fatal("resume transcript accepted a NUL-bearing identifier")
	}
	verifyAmbiguous := ambiguous
	verifyAmbiguous.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if err := VerifyResumeSignature(base64.RawURLEncoding.EncodeToString(make([]byte, 32)), verifyAmbiguous); err == nil {
		t.Fatal("VerifyResumeSignature accepted an unusable transcript")
	}

	hello := ClientHello{
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		ClientNonce:     nonce,
	}
	challenge := ServerChallenge{SessionID: "session-001", ServerNonce: nonce}
	if len(AuthTranscript(hello, challenge)) == 0 {
		t.Fatal("valid auth transcript was rejected")
	}
	badChallenge := challenge
	badChallenge.SessionID = "session\x00-001"
	if AuthTranscript(hello, badChallenge) != nil {
		t.Fatal("auth transcript accepted a NUL-bearing session id")
	}
	badHello := hello
	badHello.ClientNonce = "not-base64url"
	if AuthTranscript(badHello, challenge) != nil {
		t.Fatal("auth transcript accepted a malformed nonce")
	}
}
