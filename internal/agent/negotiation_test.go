package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestResumeHandshakeHasItsOwnDeadline(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{contractv1.ResumeProofSubprotocol}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		<-done // accept TLS/WebSocket but never answer resume_session
	}))
	defer server.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.HandshakeTimeout = 50 * time.Millisecond
	runner, err := NewRunner(t.TempDir(), limits, quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.storeResumable("session-timeout", mustRandomNonce(t))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn := dialStubGateway(t, ctx, server, writeStubGatewayCA(t, server))
	start := time.Now()
	_, err = runner.authenticateOrResume(ctx, conn, Config{}, key, "", true)
	if err == nil || time.Since(start) > time.Second || ctx.Err() != nil {
		t.Fatalf("resume ignored its deadline: elapsed=%v parent=%v error=%v", time.Since(start), ctx.Err(), err)
	}
}

func TestNewAgentAuthenticatesWithLegacyGateway(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubGateway{t: t, publicKey: key.Public().(ed25519.PublicKey)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil) // old peer does not select a subprotocol
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		frame, err := readAgentFrame(ctx, conn)
		if err != nil {
			t.Error(err)
			return
		}
		stub.serveHandshake(ctx, conn, frame) // no resume_challenge on the wire
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	// Previously stored resume material must not be sent to a legacy peer.
	runner.storeResumable("session-previous", mustRandomNonce(t))
	conn := dialStubGateway(t, ctx, server, writeStubGatewayCA(t, server))
	sess, err := runner.authenticateOrResume(ctx, conn, Config{DeviceID: "device-test", AuthorizationID: "auth-test", TokenID: "token-test"}, key, mustRandomNonce(t), true)
	if err != nil {
		t.Fatalf("legacy full authentication: %v", err)
	}
	defer sess.shutdown()
	if sess.resumeChallenge != "" || stub.resumeCount() != 0 {
		t.Fatal("legacy peer enabled the resume extension")
	}
}
