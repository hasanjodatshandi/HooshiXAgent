package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
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

func TestGatewayRejectsAuthenticatedProtocolStrictnessViolations(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	tests := []struct {
		name  string
		frame func() contractv1.Frame
	}{
		{
			name: "sequence gap",
			frame: func() contractv1.Frame {
				payload := []byte(fmt.Sprintf(`{"contract_version":1,"message_type":"pong","ping_id":"ping-gap","received_at":%q}`, time.Now().UTC().Format(time.RFC3339)))
				return contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 4, Payload: payload}
			},
		},
		{
			name: "invalid UTF-8 control payload",
			frame: func() contractv1.Frame {
				payload := append([]byte(`{"contract_version":1,"message_type":"pong","ping_id":"ping-`), byte(0xff))
				payload = append(payload, []byte(fmt.Sprintf(`","received_at":%q}`, time.Now().UTC().Format(time.RFC3339)))...)
				return contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 3, Payload: payload}
			},
		},
		{
			name: "duplicate JSON key",
			frame: func() contractv1.Frame {
				payload := []byte(fmt.Sprintf(`{"contract_version":1,"message_type":"pong","ping_id":"ping-one","ping_id":"ping-two","received_at":%q}`, time.Now().UTC().Format(time.RFC3339)))
				return contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: 3, Payload: payload}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
			defer agent.close()
			waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := agent.writeFrame(ctx, test.frame()); err != nil {
				t.Fatalf("write adversarial frame: %v", err)
			}
			waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) == nil })
		})
	}
}

func TestGatewaySequenceExhaustionTerminatesSession(t *testing.T) {
	sess := &session{
		gateway:       &Gateway{limits: DefaultLimits()},
		streams:       make(map[uint32]*stream),
		done:          make(chan struct{}),
		controlWrites: make(chan sessionWriteRequest, 32),
		dataWrites:    make(chan sessionWriteRequest, 2),
		writeMessage:  func(context.Context, []byte) error { return nil },
	}
	sess.outbound.Store(contractv1.MaxSequence)
	go sess.writeLoop()
	if err := sess.sendFrame(context.Background(), contractv1.KindControl, 0, []byte(`{"contract_version":1}`)); err == nil {
		t.Fatal("Gateway allowed outbound sequence wrap")
	}
	select {
	case <-sess.done:
	default:
		t.Fatal("Gateway session did not terminate on sequence exhaustion")
	}
}
