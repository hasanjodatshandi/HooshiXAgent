package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestGatewayRejectsMalformedProtocolAndHandshakeExhaustion(t *testing.T) {
	t.Parallel()

	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	limits.MaxPendingHandshakes = 2
	limits.HandshakeTimeout = 3 * time.Second
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	t.Run("malformed binary frame is rejected", func(t *testing.T) {
		conn := dialRawAgent(t, tlsServer.Client(), tlsServer.URL)
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := conn.Write(ctx, websocket.MessageBinary, []byte("not-an-hxt1-frame")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := conn.Read(ctx); err == nil {
			t.Fatal("malformed protocol frame unexpectedly remained connected")
		}
	})

	t.Run("pending handshake capacity fails closed", func(t *testing.T) {
		held := make([]*websocket.Conn, 0, limits.MaxPendingHandshakes)
		defer func() {
			for _, conn := range held {
				conn.CloseNow()
			}
		}()
		for i := 0; i < limits.MaxPendingHandshakes; i++ {
			held = append(held, dialRawAgent(t, tlsServer.Client(), tlsServer.URL))
		}

		waitFor(t, time.Second, func() bool { return len(gateway.handshakeSlots) == limits.MaxPendingHandshakes })
		wssURL := "wss" + strings.TrimPrefix(tlsServer.URL, "https") + agentPath
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, response, err := websocket.Dial(ctx, wssURL, &websocket.DialOptions{
			HTTPClient:      tlsServer.Client(),
			CompressionMode: websocket.CompressionDisabled,
		})
		if conn != nil {
			conn.CloseNow()
		}
		if err == nil {
			t.Fatal("handshake over capacity unexpectedly succeeded")
		}
		if response == nil || response.StatusCode != http.StatusServiceUnavailable {
			if response == nil {
				t.Fatalf("handshake over capacity returned no HTTP response: %v", err)
			}
			t.Fatalf("handshake over capacity status=%d want=%d", response.StatusCode, http.StatusServiceUnavailable)
		}
	})
}
