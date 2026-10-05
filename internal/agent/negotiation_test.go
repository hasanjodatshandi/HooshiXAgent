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
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{contractv1.TunnelSubprotocol}})
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
