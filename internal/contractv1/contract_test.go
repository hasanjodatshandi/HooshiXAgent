package contractv1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func TestFrameLanguageNeutralVector(t *testing.T) {
	t.Parallel()

	var vectors struct {
		Vectors []struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			StreamID    uint32 `json:"stream_id"`
			Sequence    uint64 `json:"sequence"`
			PayloadUTF8 string `json:"payload_utf8"`
			FrameHex    string `json:"frame_hex"`
		} `json:"vectors"`
	}
	decodeFixture(t, filepath.Join("tunnel", "frame-vectors.json"), &vectors)
	if len(vectors.Vectors) == 0 {
		t.Fatal("expected at least one frame vector")
	}

	for _, vector := range vectors.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			kind := KindData
			if vector.Kind == "control" {
				kind = KindControl
			}
			frame := Frame{Kind: kind, StreamID: vector.StreamID, Sequence: vector.Sequence, Payload: []byte(vector.PayloadUTF8)}
			encoded, err := EncodeFrame(frame)
			if err != nil {
				t.Fatalf("encode vector: %v", err)
			}
			if got := hex.EncodeToString(encoded); got != vector.FrameHex {
				t.Fatalf("frame vector mismatch\n got: %s\nwant: %s", got, vector.FrameHex)
			}
			decoded, err := DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			if decoded.Kind != frame.Kind || decoded.StreamID != frame.StreamID || decoded.Sequence != frame.Sequence || !bytes.Equal(decoded.Payload, frame.Payload) {
				t.Fatalf("decoded frame mismatch: %#v", decoded)
			}
		})
	}
}

func TestFrameRejectsMalformedAndOversizedInput(t *testing.T) {
	t.Parallel()

	base, err := EncodeFrame(Frame{Kind: KindData, StreamID: 7, Sequence: 1, Payload: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func([]byte){
		"bad magic":       func(frame []byte) { frame[0] = 'X' },
		"bad version":     func(frame []byte) { frame[4] = 99 },
		"bad kind":        func(frame []byte) { frame[5] = 99 },
		"nonzero flags":   func(frame []byte) { frame[7] = 1 },
		"length mismatch": func(frame []byte) { frame[15]++ },
		"zero sequence": func(frame []byte) {
			for i := 16; i < 24; i++ {
				frame[i] = 0
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := append([]byte(nil), base...)
			mutate(candidate)
			if _, err := DecodeFrame(candidate); err == nil {
				t.Fatal("expected malformed frame rejection")
			}
		})
	}

	if _, err := EncodeFrame(Frame{Kind: KindData, StreamID: 1, Sequence: 1, Payload: make([]byte, MaxDataPayload+1)}); err == nil {
		t.Fatal("expected oversized data payload rejection")
	}
	if _, err := EncodeFrame(Frame{Kind: KindControl, StreamID: 0, Sequence: 1, Payload: make([]byte, MaxControlPayload+1)}); err == nil {
		t.Fatal("expected oversized control payload rejection")
	}
	if _, err := EncodeFrame(Frame{Kind: KindData, StreamID: 0, Sequence: 1, Payload: []byte("x")}); err == nil {
		t.Fatal("expected data stream ID zero rejection")
	}
}

func TestSequenceTrackerRejectsReplayAndReordering(t *testing.T) {
	t.Parallel()

	var tracker SequenceTracker
	for _, sequence := range []uint64{1, 2, 10} {
		if err := tracker.Accept(sequence); err != nil {
			t.Fatalf("accept %d: %v", sequence, err)
		}
	}
	for _, sequence := range []uint64{10, 9, 0} {
		if err := tracker.Accept(sequence); err == nil {
			t.Fatalf("expected sequence %d rejection", sequence)
		}
	}
}

func TestExternalContractFixturesCanBeConsumedWithoutControlPanel(t *testing.T) {
	t.Parallel()

	authData := readFixture(t, filepath.Join("external", "device-session-authorization.valid.json"))
	auth, err := ParseDeviceSessionAuthorization(authData, fixtureTime)
	if err != nil {
		t.Fatalf("authorization fixture: %v", err)
	}
	if !MatchSessionToken(auth, "test_session_token_0123456789ABCDEF") {
		t.Fatal("expected synthetic session token to match fixture digest")
	}
	if MatchSessionToken(auth, "wrong_session_token_0123456789ABCDEF") {
		t.Fatal("wrong session token must not match")
	}

	routeData := readFixture(t, filepath.Join("external", "endpoint-route-assignment.valid.json"))
	route, err := ParseEndpointRouteAssignment(routeData, fixtureTime)
	if err != nil {
		t.Fatalf("route fixture: %v", err)
	}
	if route.DeviceID != auth.DeviceID {
		t.Fatalf("route device %q does not match authorization device %q", route.DeviceID, auth.DeviceID)
	}

	if _, err := ParseRevocationSignal(readFixture(t, filepath.Join("external", "revocation-signal.valid.json"))); err != nil {
		t.Fatalf("revocation fixture: %v", err)
	}
	if _, err := ParseGatewayStatusSignal(readFixture(t, filepath.Join("external", "gateway-status-signal.valid.json"))); err != nil {
		t.Fatalf("status fixture: %v", err)
	}
}

func TestExternalContractRejectsExpiredAuthorizationAndRawLocalTarget(t *testing.T) {
	t.Parallel()

	if _, err := ParseDeviceSessionAuthorization(readFixture(t, filepath.Join("invalid", "device-session-authorization.expired.json")), fixtureTime); err == nil {
		t.Fatal("expected expired authorization rejection")
	}
	if _, err := ParseEndpointRouteAssignment(readFixture(t, filepath.Join("invalid", "endpoint-route-assignment.raw-local-target.json")), fixtureTime); err == nil {
		t.Fatal("expected raw local target/unknown field rejection")
	}
}

func TestHandshakeFixtureAndEd25519Proof(t *testing.T) {
	t.Parallel()

	var fixture map[string]json.RawMessage
	decodeFixture(t, filepath.Join("tunnel", "handshake.valid.json"), &fixture)

	hello, err := DecodeClientHello(fixture["client_hello"])
	if err != nil {
		t.Fatalf("client_hello: %v", err)
	}
	challenge, err := DecodeServerChallenge(fixture["server_challenge"])
	if err != nil {
		t.Fatalf("server_challenge: %v", err)
	}
	auth, err := DecodeClientAuth(fixture["client_auth"])
	if err != nil {
		t.Fatalf("client_auth: %v", err)
	}

	external, err := ParseDeviceSessionAuthorization(readFixture(t, filepath.Join("external", "device-session-authorization.valid.json")), fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyClientAuthSignature(external.DevicePublicKey, hello, challenge, auth); err != nil {
		t.Fatalf("signature verification: %v", err)
	}

	for _, message := range []string{"client_hello", "server_challenge", "client_auth", "session_ready"} {
		if err := ValidateControlPayload(fixture[message], 0, fixtureTime); err != nil {
			t.Fatalf("validate %s: %v", message, err)
		}
	}
}

func TestControlPayloadScopeAndStrictness(t *testing.T) {
	t.Parallel()

	streamOpen := []byte(`{"contract_version":1,"message_type":"stream_open","endpoint_id":"endpoint-001","assignment_id":"assign-001","local_endpoint_id":"local-http-001","request_id":"request-001"}`)
	if err := ValidateControlPayload(streamOpen, 7, fixtureTime); err != nil {
		t.Fatalf("valid stream_open: %v", err)
	}
	if err := ValidateControlPayload(streamOpen, 0, fixtureTime); err == nil {
		t.Fatal("stream_open on session stream must be rejected")
	}

	withRawTarget := []byte(`{"contract_version":1,"message_type":"stream_open","endpoint_id":"endpoint-001","assignment_id":"assign-001","local_endpoint_id":"local-http-001","request_id":"request-001","local_target":"127.0.0.1:8080"}`)
	if err := ValidateControlPayload(withRawTarget, 7, fixtureTime); err == nil {
		t.Fatal("stream_open raw local target must be rejected")
	}

	badReady := []byte(`{"contract_version":1,"message_type":"session_ready","session_id":"session-001","heartbeat_interval_seconds":60,"idle_timeout_seconds":30}`)
	if err := ValidateControlPayload(badReady, 0, fixtureTime); err == nil {
		t.Fatal("idle timeout shorter than twice heartbeat must be rejected")
	}

	unknown := []byte(`{"contract_version":1,"message_type":"admin_override"}`)
	if err := ValidateControlPayload(unknown, 0, fixtureTime); err == nil {
		t.Fatal("unknown control message must be rejected")
	}
}

func TestJSONSchemaDocumentsAreValidAndStrict(t *testing.T) {
	t.Parallel()

	schemas := []string{
		"tunnel-control.schema.json",
		filepath.Join("external", "device-session-authorization.schema.json"),
		filepath.Join("external", "endpoint-route-assignment.schema.json"),
		filepath.Join("external", "revocation-signal.schema.json"),
		filepath.Join("external", "gateway-status-signal.schema.json"),
	}
	for _, name := range schemas {
		name := name
		t.Run(filepath.ToSlash(name), func(t *testing.T) {
			t.Parallel()
			data := readContract(t, name)
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("invalid JSON schema document: %v", err)
			}
			if document["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
				t.Fatalf("unexpected JSON Schema dialect: %v", document["$schema"])
			}
			if _, ok := document["$id"].(string); !ok {
				t.Fatal("schema must have string $id")
			}
		})
	}
}

func TestValidExternalFixturesContainNoRawLocalTargetAuthority(t *testing.T) {
	t.Parallel()

	root := filepath.Join(contractRoot(t), "fixtures", "external")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var value any
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		assertNoRawTargetKeys(t, entry.Name(), value)
	}
}

func assertNoRawTargetKeys(t *testing.T, source string, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "local_target", "target", "target_url", "address", "socket", "socket_path", "file_path":
				t.Fatalf("%s contains forbidden raw-target authority key %q", source, key)
			}
			assertNoRawTargetKeys(t, source, child)
		}
	case []any:
		for _, child := range typed {
			assertNoRawTargetKeys(t, source, child)
		}
	}
}

func decodeFixture(t *testing.T, name string, target any) {
	t.Helper()
	data := readFixture(t, name)
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(contractRoot(t), "fixtures", name))
}

func readContract(t *testing.T, name string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(contractRoot(t), name))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func contractRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "contracts", "v1"))
}
