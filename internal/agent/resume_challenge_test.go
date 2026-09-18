package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// stubGateway is the Agent-side contract peer for the resume fast path: it
// performs a real protocol-v1 handshake, issues a per-transport resume
// challenge, and inspects every resume_session frame the Agent sends. It is a
// deliberate second implementation of the wire contract (the Gateway package
// provides the first), so an Agent-side regression shows up as a rejected
// frame here even though the two product packages never import each other.
type stubGateway struct {
	t                *testing.T
	publicKey        ed25519.PublicKey
	tokenDigest      string
	firstChallenge   string
	nextChallenge    string
	rotatedChallenge string

	mu         sync.Mutex
	resumes    []contractv1.ResumeSession
	sessions   []string
	handshakes int
}

func (stub *stubGateway) serve(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled, Subprotocols: []string{contractv1.ResumeProofSubprotocol}})
	if err != nil {
		stub.t.Errorf("stub gateway accept: %v", err)
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	frame, err := readAgentFrame(ctx, conn)
	if err != nil {
		stub.t.Errorf("stub gateway read preface: %v", err)
		return
	}
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
		stub.t.Errorf("stub gateway preface envelope: %v", err)
		return
	}
	switch envelope.MessageType {
	case "client_hello":
		stub.serveHandshake(ctx, conn, frame)
	case "resume_session":
		stub.serveResume(ctx, conn, frame)
	default:
		stub.t.Errorf("stub gateway unexpected preface %q", envelope.MessageType)
	}
}

func (stub *stubGateway) serveHandshake(ctx context.Context, conn *websocket.Conn, frame contractv1.Frame) {
	hello, err := contractv1.DecodeClientHello(frame.Payload)
	if err != nil {
		stub.t.Errorf("stub gateway client_hello: %v", err)
		return
	}
	sessionID := fmt.Sprintf("session-stub-%d", stub.nextSessionIndex())
	stub.mu.Lock()
	stub.sessions = append(stub.sessions, sessionID)
	stub.mu.Unlock()

	challenge := contractv1.ServerChallenge{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "server_challenge",
		SessionID:       sessionID,
		ServerNonce:     mustRandomNonce(stub.t),
		ExpiresAt:       time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
	}
	if err := writeInitialControl(ctx, conn, 1, challenge); err != nil {
		stub.t.Errorf("stub gateway challenge write: %v", err)
		return
	}
	authFrame, err := readAgentFrame(ctx, conn)
	if err != nil {
		stub.t.Errorf("stub gateway read client_auth: %v", err)
		return
	}
	auth, err := contractv1.DecodeClientAuth(authFrame.Payload)
	if err != nil {
		stub.t.Errorf("stub gateway client_auth: %v", err)
		return
	}
	if err := contractv1.VerifyClientAuthSignature(base64.RawURLEncoding.EncodeToString(stub.publicKey), hello, challenge, auth); err != nil {
		stub.t.Errorf("stub gateway client_auth signature: %v", err)
		return
	}
	ready := contractv1.SessionReady{
		ContractVersion:          contractv1.ProtocolVersion,
		MessageType:              "session_ready",
		SessionID:                sessionID,
		HeartbeatIntervalSeconds: 30,
		IdleTimeoutSeconds:       60,
		ResumeChallenge:          stub.firstChallenge,
	}
	if err := writeInitialControl(ctx, conn, 2, ready); err != nil {
		stub.t.Errorf("stub gateway session_ready write: %v", err)
		return
	}
	<-ctx.Done()
}

func (stub *stubGateway) serveResume(ctx context.Context, conn *websocket.Conn, frame contractv1.Frame) {
	var resume contractv1.ResumeSession
	if err := json.Unmarshal(frame.Payload, &resume); err != nil {
		stub.t.Errorf("stub gateway resume payload: %v", err)
		return
	}
	if err := contractv1.ValidateControlPayload(frame.Payload, 0, time.Now().UTC()); err != nil {
		stub.t.Errorf("stub gateway rejected the Agent resume frame: %v payload=%s", err, frame.Payload)
		return
	}
	if err := contractv1.VerifyResumeSignature(base64.RawURLEncoding.EncodeToString(stub.publicKey), resume); err != nil {
		stub.t.Errorf("stub gateway resume signature: %v", err)
		return
	}
	if !contractv1.MatchResumeChallenge(stub.nextChallenge, resume.ResumeChallenge) {
		stub.t.Errorf("stub gateway resume challenge=%q want the issued %q", resume.ResumeChallenge, stub.nextChallenge)
		return
	}
	issuedAt, err := contractv1.ResumeIssuedAt(resume)
	if err != nil {
		stub.t.Errorf("stub gateway resume issued_at: %v", err)
		return
	}
	if skew := time.Since(issuedAt); skew < -time.Minute || skew > time.Minute {
		stub.t.Errorf("stub gateway resume proof is %s away from the local clock", skew)
		return
	}
	stub.mu.Lock()
	stub.resumes = append(stub.resumes, resume)
	stub.mu.Unlock()

	reply := contractv1.SessionResumed{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "session_resumed",
		SessionID:       resume.SessionID,
		NextSequence:    2,
		ResumedAt:       time.Now().UTC().Format(time.RFC3339),
		ResumeChallenge: stub.rotatedChallenge,
	}
	if err := writeInitialControl(ctx, conn, 1, reply); err != nil {
		stub.t.Errorf("stub gateway session_resumed write: %v", err)
		return
	}
	<-ctx.Done()
}

func (stub *stubGateway) nextSessionIndex() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return len(stub.sessions) + 1
}

func (stub *stubGateway) resumeCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return len(stub.resumes)
}

func mustRandomNonce(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce)
}

// TestAgentBindsGatewayResumeChallenge proves the Agent-side half of the
// resume-challenge contract: the challenge the Gateway issued over the
// transport being replaced is bound into the signed transcript, the proof
// carries a fresh timestamp, and the rotated challenge from session_resumed is
// adopted for the following transport.
func TestAgentBindsGatewayResumeChallenge(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	stub := &stubGateway{
		t:                t,
		publicKey:        privateKey.Public().(ed25519.PublicKey),
		firstChallenge:   mustRandomNonce(t),
		rotatedChallenge: mustRandomNonce(t),
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(stub.serve))
	server.StartTLS()
	defer server.Close()
	caPath := writeStubGatewayCA(t, server)

	config := Config{
		Version:         1,
		DeviceID:        "device-stub-001",
		AuthorizationID: "auth-stub-001",
		TokenID:         "token-stub-001",
		CAFile:          caPath,
	}
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	first, err := runner.authenticateOrResume(ctx, dialStubGateway(t, ctx, server, caPath), config, privateKey, token, true)
	if err != nil {
		t.Fatalf("full handshake against the stub gateway: %v", err)
	}
	if first.resumeChallenge != stub.firstChallenge {
		t.Fatalf("Agent stored challenge=%q want the issued %q", first.resumeChallenge, stub.firstChallenge)
	}
	runner.storeResumable(first.sessionID, first.resumeChallenge)

	// The next transport must present the issued challenge, and nothing else.
	stub.mu.Lock()
	stub.nextChallenge = stub.firstChallenge
	stub.mu.Unlock()
	second, err := runner.authenticateOrResume(ctx, dialStubGateway(t, ctx, server, caPath), config, privateKey, token, true)
	if err != nil {
		t.Fatalf("resume against the stub gateway: %v", err)
	}
	if stub.resumeCount() != 1 {
		t.Fatalf("stub gateway saw %d resume frames want 1", stub.resumeCount())
	}
	if second.sessionID != first.sessionID {
		t.Fatalf("resumed session id=%q want %q", second.sessionID, first.sessionID)
	}
	if second.resumeChallenge != stub.rotatedChallenge {
		t.Fatalf("Agent did not adopt the rotated challenge: %q", second.resumeChallenge)
	}

	// The rotated challenge is what the following transport must present: an
	// Agent that kept using the first challenge would be rejected here.
	stub.mu.Lock()
	stub.nextChallenge = stub.rotatedChallenge
	stub.mu.Unlock()
	runner.storeResumable(second.sessionID, second.resumeChallenge)
	if _, err := runner.authenticateOrResume(ctx, dialStubGateway(t, ctx, server, caPath), config, privateKey, token, true); err != nil {
		t.Fatalf("resume with the rotated challenge: %v", err)
	}
	if stub.resumeCount() != 2 {
		t.Fatalf("stub gateway saw %d resume frames want 2", stub.resumeCount())
	}
}

// TestAgentSkipsResumeWithoutGatewayChallenge proves the Agent never sends an
// unbound (replayable) resume proof: with a stored session identity but no
// Gateway-issued challenge it performs a full client_hello handshake instead.
func TestAgentSkipsResumeWithoutGatewayChallenge(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	stub := &stubGateway{t: t, publicKey: privateKey.Public().(ed25519.PublicKey), firstChallenge: mustRandomNonce(t), rotatedChallenge: mustRandomNonce(t)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(stub.serve))
	server.StartTLS()
	defer server.Close()
	caPath := writeStubGatewayCA(t, server)

	config := Config{Version: 1, DeviceID: "device-stub-002", AuthorizationID: "auth-stub-002", TokenID: "token-stub-002", CAFile: caPath}
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	first, err := runner.authenticateOrResume(ctx, dialStubGateway(t, ctx, server, caPath), config, privateKey, token, true)
	if err != nil {
		t.Fatalf("initial handshake: %v", err)
	}
	runner.storeResumable(first.sessionID, "")
	second, err := runner.authenticateOrResume(ctx, dialStubGateway(t, ctx, server, caPath), config, privateKey, token, true)
	if err != nil {
		t.Fatalf("full-handshake fallback: %v", err)
	}
	if second.sessionID == first.sessionID {
		t.Fatal("Agent resumed without a Gateway-issued challenge")
	}
	if stub.resumeCount() != 0 {
		t.Fatalf("Agent sent %d unbound resume frames", stub.resumeCount())
	}
	if second.resumeChallenge != stub.firstChallenge {
		t.Fatalf("fallback session challenge=%q want the issued %q", second.resumeChallenge, stub.firstChallenge)
	}
}

func writeStubGatewayCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "stub-gateway-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath
}

func dialStubGateway(t *testing.T, ctx context.Context, server *httptest.Server, caPath string) *websocket.Conn {
	t.Helper()
	pemData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		t.Fatal("append stub gateway CA")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/agent/v1/connect"
	conn, _, err := websocket.Dial(ctx, wssURL, &websocket.DialOptions{HTTPClient: client, CompressionMode: websocket.CompressionDisabled, Subprotocols: []string{contractv1.ResumeProofSubprotocol}})
	if err != nil {
		t.Fatalf("dial stub gateway: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}
