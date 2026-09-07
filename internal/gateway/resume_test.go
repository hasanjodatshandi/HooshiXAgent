package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// rawResumeAgent is a minimal raw peer able to send resume_session frames.
type rawResumeAgent struct {
	conn        *websocket.Conn
	outSequence atomic.Uint64
	inbound     contractv1.SequenceTracker
}

func (agent *rawResumeAgent) sendControl(ctx context.Context, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	sequence, err := contractv1.NextSequence(agent.outSequence.Load())
	if err != nil {
		return err
	}
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: streamID, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	agent.outSequence.Store(sequence)
	return agent.conn.Write(ctx, websocket.MessageBinary, encoded)
}

func (agent *rawResumeAgent) close() {
	agent.conn.CloseNow()
}

// connectResumingAgent opens a fresh WebSocket and sends resume_session for
// the given session ID. ok=false means the connection was closed (resume
// unavailable); otherwise the parsed session_resumed reply is returned.
func connectResumingAgent(t *testing.T, server *httptest.Server, identity testIdentity, sessionID string) (*rawResumeAgent, contractv1.SessionResumed, bool) {
	t.Helper()
	conn := dialRawAgent(t, server.Client(), server.URL)
	agent := &rawResumeAgent{conn: conn}

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
	}
	signature := ed25519.Sign(identity.privateKey, contractv1.ResumeTranscript(resume))
	resume.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := agent.sendControl(context.Background(), 0, resume); err != nil {
		t.Fatalf("send resume_session: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	frame, err := readFrame(ctx, conn)
	if err != nil {
		return agent, contractv1.SessionResumed{}, false
	}
	if frame.Sequence != 1 || frame.Kind != contractv1.KindControl || frame.StreamID != 0 {
		t.Fatalf("unexpected resume reply frame: sequence=%d kind=%v stream=%d", frame.Sequence, frame.Kind, frame.StreamID)
	}
	if err := contractv1.ValidateControlPayload(frame.Payload, 0, time.Now().UTC()); err != nil {
		t.Fatalf("resume reply invalid control: %v", err)
	}
	var resumed contractv1.SessionResumed
	if err := json.Unmarshal(frame.Payload, &resumed); err != nil {
		t.Fatalf("resume reply not session_resumed: %v", err)
	}
	return agent, resumed, true
}

// sendResumeControl writes a resume_session control frame with the explicit
// starting sequence, mirroring sendHello for the resume preface.
func sendResumeControl(ctx context.Context, conn *websocket.Conn, resume contractv1.ResumeSession, sequence uint64) error {
	payload, err := json.Marshal(resume)
	if err != nil {
		return err
	}
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, encoded)
}

// connectResumingMockAgent opens a fresh WebSocket, performs the
// resume_session fast path against sessionID, and returns a fully
// stream-capable mock agent continuing on the resumed session. ok=false
// means the Gateway rejected the resume (connection closed).
func connectResumingMockAgent(t *testing.T, server *httptest.Server, identity testIdentity, sessionID, localServiceURL string) (*mockAgent, bool) {
	t.Helper()
	parsed := newURLParse(t, localServiceURL)
	agent := &mockAgent{
		identity:   identity,
		localURL:   parsed,
		httpClient: localHTTPClient(localServiceURL),
		streams:    make(map[uint32]*mockStream),
		done:       make(chan struct{}),
	}
	conn := dialRawAgent(t, server.Client(), server.URL)
	agent.conn = conn

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
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
	}
	signature := ed25519.Sign(identity.privateKey, contractv1.ResumeTranscript(resume))
	resume.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := sendResumeControl(ctx, conn, resume, 1); err != nil {
		t.Fatalf("send resume_session: %v", err)
	}
	agent.outSequence.Store(1)

	reply, err := readFrame(ctx, conn)
	if err != nil {
		agent.close()
		return agent, false
	}
	if err := agent.inSequence.Accept(reply.Sequence); err != nil {
		t.Fatal(err)
	}
	if reply.Sequence != 1 || reply.Kind != contractv1.KindControl || reply.StreamID != 0 {
		t.Fatalf("unexpected resume reply frame: sequence=%d kind=%v stream=%d", reply.Sequence, reply.Kind, reply.StreamID)
	}
	if err := contractv1.ValidateControlPayload(reply.Payload, 0, time.Now().UTC()); err != nil {
		t.Fatalf("resume reply invalid control: %v", err)
	}
	var resumed contractv1.SessionResumed
	if err := json.Unmarshal(reply.Payload, &resumed); err != nil {
		t.Fatalf("resume reply not session_resumed: %v", err)
	}
	if resumed.SessionID != sessionID {
		t.Fatalf("resumed session ID=%q want %q", resumed.SessionID, sessionID)
	}

	go agent.readLoop()
	return agent, true
}

func newURLParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestGatewayResumeFastPathReplacesLiveSession(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	// Establish the first fully authenticated session and capture its ID.
	agentOne := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agentOne.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	original := gateway.sessionForDevice(identity.deviceID)
	originalID := original.sessionID

	resumer, ok := connectResumingMockAgent(t, tlsServer, identity, originalID, local.URL)
	defer resumer.close()
	if !ok {
		t.Fatal("resume of a live session was rejected")
	}

	// The resumed session must now be the routable one with the same identity.
	waitFor(t, 2*time.Second, func() bool {
		current := gateway.sessionForDevice(identity.deviceID)
		return current != nil && current.sessionID == originalID && current != original
	})

	// The resumed session serves public traffic through its own stream proxy.
	request := newPublicRequest(t, tlsServer.URL+"/resumed", testRouteHost, nil)
	response, err := tlsServer.Client().Do(request)
	if err != nil {
		t.Fatalf("public request after resume: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-resume status=%d", response.StatusCode)
	}
}

func TestGatewayResumeFailsClosedForUnknownSession(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	agent, _, ok := connectResumingAgent(t, tlsServer, identity, "session-never-existed")
	defer agent.close()
	if ok {
		t.Fatal("resume of an unknown session was accepted")
	}
	if gateway.sessionForDevice(identity.deviceID) != nil {
		t.Fatal("failed resume created a session")
	}
}

func TestGatewayResumeRejectsMismatchedIdentity(t *testing.T) {
	identity := newTestIdentity(t)
	otherIdentity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
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

	// A different device identity cannot resume this session: the subject
	// mismatch fails closed and the live session remains untouched.
	agent, _, ok := connectResumingAgent(t, tlsServer, otherIdentity, live.sessionID)
	defer agent.close()
	if ok {
		t.Fatal("resume with mismatched device identity was accepted")
	}
	if current := gateway.sessionForDevice(identity.deviceID); current != live {
		t.Fatal("failed resume disturbed the live session")
	}
}

func TestGatewayResumeInvalidSignatureFailsClosed(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
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

	conn := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
	defer conn.CloseNow()
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
		Signature:       base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
	peer := &rawResumeAgent{conn: conn}
	if err := peer.sendControl(context.Background(), 0, resume); err != nil {
		t.Fatalf("send invalid-signature resume: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("invalid-signature resume stayed connected")
	}
	if current := gateway.sessionForDevice(identity.deviceID); current != live {
		t.Fatal("invalid resume disturbed the live session")
	}

	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	if strings.Contains(metrics.Body.String(), "{") {
		t.Fatalf("resume path introduced labeled metrics: %s", metrics.Body.String())
	}
}
