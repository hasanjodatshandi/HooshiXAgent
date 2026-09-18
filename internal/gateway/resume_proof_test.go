package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// signedResumeFrame builds the exact wire bytes of one resume_session proof.
func signedResumeFrame(t *testing.T, identity testIdentity, sessionID, challenge string) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	resume := contractv1.ResumeSession{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "resume_session",
		DeviceID:        identity.deviceID,
		AuthorizationID: identity.authorizationID,
		TokenID:         identity.tokenID,
		SessionID:       sessionID,
		ResumeNonce:     base64.RawURLEncoding.EncodeToString(nonce),
		ResumeChallenge: challenge,
		IssuedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	resume.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.privateKey, contractv1.ResumeTranscript(resume)))
	return encodeTestFrame(t, contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 1, Payload: mustJSON(t, resume)})
}

func encodeTestFrame(t *testing.T, frame contractv1.Frame) []byte {
	t.Helper()
	encoded, err := contractv1.EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestResumeProofIsNotABearerTokenForTheSessionLifetime proves the captured
// resume proof is not replayable: the Gateway issues a per-transport challenge
// bound into the signature and rotates it on every accepted resume, so the
// identical frame that was accepted once is rejected afterwards (fail closed
// with 1013, the full-handshake fallback signal).
func TestResumeProofIsNotABearerTokenForTheSessionLifetime(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	agentOne := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agentOne.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	original := gateway.sessionForDevice(identity.deviceID)
	if agentOne.resumeChallenge == "" {
		t.Fatal("session_ready did not carry a Gateway-issued resume challenge")
	}
	frame := signedResumeFrame(t, identity, original.sessionID, agentOne.resumeChallenge)

	// First use of the proof succeeds on a fresh transport.
	first := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer first.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := first.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	reply := readFrameForTest(t, ctx, first)
	if err := contractv1.ValidateControlPayload(reply.Payload, 0, time.Now().UTC()); err != nil {
		t.Fatalf("resume reply: %v", err)
	}
	var resumed contractv1.SessionResumed
	if err := json.Unmarshal(reply.Payload, &resumed); err != nil {
		t.Fatal(err)
	}
	if resumed.MessageType != "session_resumed" || resumed.ResumeChallenge == "" {
		t.Fatalf("resume reply=%+v", resumed)
	}
	if resumed.ResumeChallenge == agentOne.resumeChallenge {
		t.Fatal("resume challenge was not rotated on the accepted resume")
	}
	// The session_resumed reply is written by the resumed session's own writer
	// while resumeSession is still running; the connection handler swaps the
	// registry entry (registerSession) only after resumeSession returns. The
	// reply and the registry takeover are therefore sequentially ordered but
	// not observed at the same instant, so wait for the takeover instead of
	// sampling the registry once and racing the handler.
	var live *session
	waitFor(t, 2*time.Second, func() bool {
		current := gateway.sessionForDevice(identity.deviceID)
		if current == nil || current == original {
			return false
		}
		live = current
		return true
	})
	// The reply is sequence 1, assigned by the session's single writer.
	if got := live.outbound.Load(); got != 1 {
		t.Fatalf("resumed outbound=%d want 1 (single writer assigned the resume reply)", got)
	}

	// Replaying the identical proof on another transport must fail closed.
	replay := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer replay.CloseNow()
	if err := replay.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	if _, _, err := replay.Read(ctx); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("replayed resume close status=%v want %d", websocket.CloseStatus(err), websocket.StatusTryAgainLater)
	}
	if current := gateway.sessionForDevice(identity.deviceID); current != live {
		t.Fatal("replayed resume disturbed the live resumed session")
	}

	// The legitimate Agent, holding the rotated challenge, can resume again.
	rotated := signedResumeFrame(t, identity, original.sessionID, resumed.ResumeChallenge)
	third := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer third.CloseNow()
	if err := third.Write(ctx, websocket.MessageBinary, rotated); err != nil {
		t.Fatal(err)
	}
	thirdReply := readFrameForTest(t, ctx, third)
	var thirdResumed contractv1.SessionResumed
	if err := json.Unmarshal(thirdReply.Payload, &thirdResumed); err != nil {
		t.Fatal(err)
	}
	if thirdResumed.MessageType != "session_resumed" {
		t.Fatalf("rotated-challenge resume reply=%+v", thirdResumed)
	}
}

// TestResumeProofOutsideAcceptanceWindowFailsClosed proves the short
// acceptance window: an otherwise perfectly bound proof presented outside the
// window is rejected and degrades to the full-handshake fallback.
func TestResumeProofOutsideAcceptanceWindowFailsClosed(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.ResumeAcceptanceWindow = 2 * time.Second
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	agentOne := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agentOne.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	live := gateway.sessionForDevice(identity.deviceID)

	stale := func(issuedAt time.Time) []byte {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		resume := contractv1.ResumeSession{
			ContractVersion: contractv1.ProtocolVersion,
			MessageType:     "resume_session",
			DeviceID:        identity.deviceID,
			AuthorizationID: identity.authorizationID,
			TokenID:         identity.tokenID,
			SessionID:       live.sessionID,
			ResumeNonce:     base64.RawURLEncoding.EncodeToString(nonce),
			ResumeChallenge: agentOne.resumeChallenge,
			IssuedAt:        issuedAt.UTC().Format(time.RFC3339),
		}
		resume.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.privateKey, contractv1.ResumeTranscript(resume)))
		return encodeTestFrame(t, contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 1, Payload: mustJSON(t, resume)})
	}

	conn := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, stale(time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("stale resume close status=%v want %d", websocket.CloseStatus(err), websocket.StatusTryAgainLater)
	}
	if current := gateway.sessionForDevice(identity.deviceID); current != live {
		t.Fatal("stale resume disturbed the live session")
	}
}

// TestLegacyResumeProofFallsBackToFullHandshake proves compatibility
// fail-closed: an Agent that sends the previous (unbound) resume transcript is
// rejected as an unavailable resume — close 1013, the designed fallback signal
// — and can then complete a full client_hello handshake on a new connection.
func TestLegacyResumeProofFallsBackToFullHandshake(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	agentOne := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agentOne.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	live := gateway.sessionForDevice(identity.deviceID)

	// The pre-challenge transcript shape: no resume_challenge, no issued_at.
	legacy := fmt.Sprintf(`{"contract_version":1,"message_type":"resume_session","device_id":%q,"authorization_id":%q,"token_id":%q,"session_id":%q,"resume_nonce":%q,"signature":%q}`,
		identity.deviceID, identity.authorizationID, identity.tokenID, live.sessionID,
		base64.RawURLEncoding.EncodeToString(make([]byte, 32)), base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
	frame := encodeTestFrame(t, contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 1, Payload: []byte(legacy)})

	conn := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("legacy resume close status=%v want %d (full-handshake fallback signal)", websocket.CloseStatus(err), websocket.StatusTryAgainLater)
	}
	if current := gateway.sessionForDevice(identity.deviceID); current != live {
		t.Fatal("legacy resume disturbed the live session")
	}

	// The fallback itself must work: the full handshake establishes a new
	// tunnel for the device (a standby while the interrupted primary is still
	// registered), and that tunnel takes over routing once the interrupted
	// transport is gone.
	agentTwo := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agentTwo.close()
	waitFor(t, 2*time.Second, func() bool {
		gateway.mu.RLock()
		tunnels := len(gateway.tunnels[identity.deviceID])
		gateway.mu.RUnlock()
		return tunnels == 2
	})
	agentOne.close()
	waitFor(t, 2*time.Second, func() bool {
		current := gateway.sessionForDevice(identity.deviceID)
		return current != nil && current != live
	})
	response, err := tlsServer.Client().Do(newPublicRequest(t, tlsServer.URL+"/after-fallback", testRouteHost, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-fallback public status=%d", response.StatusCode)
	}
}
