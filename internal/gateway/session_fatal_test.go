package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// TestRejectedSessionRegistrationTearsDownSessionWriter proves a rejected
// authenticated handshake releases the session's writer goroutine and
// channels. Reachable whenever the session table is full (or a handshake
// races drain); without the teardown every rejection leaks one goroutine
// forever against a hard memory limit.
func TestRejectedSessionRegistrationTearsDownSessionWriter(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxAgentSessions = 1
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	// Occupy the single global session slot.
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	first := gateway.sessionForDevice(identity.deviceID)
	baseline := runtime.NumGoroutine()

	const rejections = 8
	for i := 0; i < rejections; i++ {
		peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
		// The handshake completed (session_ready was written); the session
		// itself must have been rejected by the capacity bound.
		if current := gateway.sessionForDevice(identity.deviceID); current != first {
			t.Fatalf("rejected handshake disturbed the live session: %p want %p", current, first)
		}
		peer.conn.CloseNow()
	}

	// Every rejected session must have released its writer goroutine; the
	// pre-existing live session plus transport cleanup leaves a small margin.
	waitFor(t, 5*time.Second, func() bool { return runtime.NumGoroutine() <= baseline+2 })
}

// TestTerminatedSessionLeavesRoutingBeforeCloseHandshake proves a session in a
// terminal state is removed from device routing synchronously. The WebSocket
// close handshake can wait for the peer's close frame (5s by default), and a
// dead session must not remain the device's routing primary for that window.
func TestTerminatedSessionLeavesRoutingBeforeCloseHandshake(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	// An Agent may not originate session_revoked: the session becomes fatal.
	// The peer deliberately never reads, so it never answers the Gateway's
	// close frame and the close handshake cannot complete.
	if err := peer.sendControl(context.Background(), 0, contractv1.SessionRevoked{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "session_revoked",
		AuthorizationID: identity.authorizationID,
		ReasonCode:      "disabled",
	}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 500*time.Millisecond, func() bool { return gateway.sessionForDevice(identity.deviceID) == nil })

	// The peer still observes the contract close code for the violation.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := peer.conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("close status=%v want %d", websocket.CloseStatus(err), websocket.StatusPolicyViolation)
	}
}

// TestStandbyRecycleKeepsDeviceTunnelCountExact proves the recycled standby is
// released from the registry in the same critical section that admits its
// replacement, so a device never transiently reports more tunnels than
// MaxTunnelsPerDevice (which would fail closed a concurrent registration).
func TestStandbyRecycleKeepsDeviceTunnelCountExact(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxTunnelsPerDevice = 2
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := identity.deviceID
	now := time.Now().UnixNano()
	makeSession := func(sessionID string) *session {
		sess := &session{
			gateway:                gateway,
			deviceID:               deviceID,
			sessionID:              sessionID,
			authorizationID:        identity.authorizationID,
			tokenID:                identity.tokenID,
			authorizationExpiresAt: time.Now().Add(time.Hour),
			streams:                make(map[uint32]*stream),
			done:                   make(chan struct{}),
		}
		sess.authorized.Store(true)
		sess.lastSeen.Store(now)
		return sess
	}
	for _, sessionID := range []string{"session-1", "session-2", "session-3"} {
		if err := gateway.registerSession(makeSession(sessionID)); err != nil {
			t.Fatalf("register %s: %v", sessionID, err)
		}
		gateway.mu.RLock()
		count := len(gateway.tunnels[deviceID])
		gateway.mu.RUnlock()
		if count > limits.MaxTunnelsPerDevice {
			t.Fatalf("device tunnel count=%d exceeds %d after %s", count, limits.MaxTunnelsPerDevice, sessionID)
		}
	}
	gateway.mu.RLock()
	tunnels := gateway.tunnels[deviceID]
	primary := gateway.primaries[deviceID]
	_, recycledStandby := tunnels["session-2"]
	_, primaryStillRegistered := tunnels["session-1"]
	_, newestRegistered := tunnels["session-3"]
	gateway.mu.RUnlock()
	if recycledStandby {
		t.Fatal("recycled standby remained registered after its replacement was admitted")
	}
	if !primaryStillRegistered || primary != tunnels["session-1"] {
		t.Fatal("standby recycling evicted the routing primary")
	}
	if !newestRegistered {
		t.Fatal("replacement standby was not registered")
	}
}

// TestPreAuthenticationConnectionRateIsLimitedPerPeer proves a peer cannot
// cycle the bounded pre-authentication handshake slots: the per-peer rate is
// applied before slot acquisition, and a rejected connection consumes neither
// a handshake slot nor the authenticated handshake rate bucket.
func TestPreAuthenticationConnectionRateIsLimitedPerPeer(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.PreAuthRatePerSecond = 1
	limits.PreAuthRateBurst = 1
	limits.HandshakeRatePerSecond = 100
	limits.HandshakeRateBurst = 100
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()

	first := dialRawAgent(t, server.Client(), server.URL)
	defer first.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sendClientHello(ctx, first, identity, 1); err != nil {
		t.Fatal(err)
	}
	if frame := readFrameForTest(t, ctx, first); frame.Sequence != 1 {
		t.Fatalf("first challenge sequence=%d", frame.Sequence)
	}

	// The peer's burst is exhausted: the next connection is refused before a
	// pending-handshake slot is taken.
	_, response, err := websocket.Dial(ctx, "wss"+trimHTTPS(server.URL)+agentPath, &websocket.DialOptions{
		HTTPClient:      server.Client(),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err == nil {
		t.Fatal("second pre-authentication connection bypassed the per-peer rate limit")
	}
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("pre-authentication rejection status=%v want %d", response, http.StatusTooManyRequests)
	}
	response.Body.Close()

	gateway.mu.RLock()
	slots := len(gateway.handshakeSlots)
	gateway.mu.RUnlock()
	if slots > 1 {
		t.Fatalf("rejected pre-authentication connection consumed handshake slots: %d", slots)
	}

	// A peer allowed to spend a token again is served normally.
	time.Sleep(1100 * time.Millisecond)
	third := dialRawAgent(t, server.Client(), server.URL)
	defer third.CloseNow()
	if err := sendClientHello(ctx, third, identity, 1); err != nil {
		t.Fatal(err)
	}
	if frame := readFrameForTest(t, ctx, third); frame.Sequence != 1 {
		t.Fatalf("third challenge sequence=%d", frame.Sequence)
	}
}

func trimHTTPS(baseURL string) string {
	if len(baseURL) >= len("https") && baseURL[:5] == "https" {
		return baseURL[5:]
	}
	return baseURL
}

// TestSessionFatalCloseCodesMatchProtocolTable proves the Gateway emits the
// close codes the tunnel protocol defines for each session-fatal cause:
// framing violations are 1002, malformed control payloads are 1007, and
// oversized frames are 1009.
func TestSessionFatalCloseCodesMatchProtocolTable(t *testing.T) {
	cases := []struct {
		name string
		want websocket.StatusCode
		send func(t *testing.T, peer *r5RawAgent, ctx context.Context)
	}{
		{
			name: "sequence-gap-is-protocol-error",
			want: websocket.StatusProtocolError,
			send: func(t *testing.T, peer *r5RawAgent, ctx context.Context) {
				payload, err := json.Marshal(contractv1.Heartbeat{ContractVersion: contractv1.ProtocolVersion, MessageType: "pong", PingID: "ping-001", ReceivedAt: time.Now().UTC().Format(time.RFC3339)})
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: peer.outSequence.Load() + 5, Payload: payload})
				if err != nil {
					t.Fatal(err)
				}
				if err := peer.conn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed-control-payload-is-invalid-frame-payload-data",
			want: websocket.StatusInvalidFramePayloadData,
			send: func(t *testing.T, peer *r5RawAgent, ctx context.Context) {
				sequence, err := contractv1.NextSequence(peer.outSequence.Load())
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: sequence, Payload: []byte("{")})
				if err != nil {
					t.Fatal(err)
				}
				peer.outSequence.Store(sequence)
				if err := peer.conn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown-frame-kind-is-protocol-error",
			want: websocket.StatusProtocolError,
			send: func(t *testing.T, peer *r5RawAgent, ctx context.Context) {
				sequence, err := contractv1.NextSequence(peer.outSequence.Load())
				if err != nil {
					t.Fatal(err)
				}
				encoded := make([]byte, contractv1.HeaderSize)
				copy(encoded[0:4], []byte("HXT1"))
				encoded[4] = byte(contractv1.ProtocolVersion)
				encoded[5] = 9
				encoded[16] = byte(sequence >> 56)
				encoded[17] = byte(sequence >> 48)
				encoded[18] = byte(sequence >> 40)
				encoded[19] = byte(sequence >> 32)
				encoded[20] = byte(sequence >> 24)
				encoded[21] = byte(sequence >> 16)
				encoded[22] = byte(sequence >> 8)
				encoded[23] = byte(sequence)
				peer.outSequence.Store(sequence)
				if err := peer.conn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			identity := newTestIdentity(t)
			gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
			if err != nil {
				t.Fatal(err)
			}
			tlsServer := httptest.NewTLSServer(gateway.Handler())
			defer tlsServer.Close()
			peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
			defer peer.conn.CloseNow()
			waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			test.send(t, peer, ctx)
			if _, _, err := peer.conn.Read(ctx); websocket.CloseStatus(err) != test.want {
				t.Fatalf("close status=%v want %d (err=%v)", websocket.CloseStatus(err), test.want, err)
			}
		})
	}
}

// TestOversizedAgentFrameClosesWithMessageTooBig proves the read-limit
// violation surfaces as close code 1009 rather than a policy violation.
func TestOversizedAgentFrameClosesWithMessageTooBig(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	oversized := make([]byte, contractv1.HeaderSize+contractv1.MaxDataPayload+1)
	copy(oversized[0:4], []byte("HXT1"))
	oversized[4] = byte(contractv1.ProtocolVersion)
	oversized[5] = byte(contractv1.KindData)
	oversized[8] = 0
	oversized[11] = 1
	if err := peer.conn.Write(ctx, websocket.MessageBinary, oversized); err != nil {
		t.Fatalf("write oversized frame: %v", err)
	}
	if _, _, err := peer.conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("close status=%v want %d (err=%v)", websocket.CloseStatus(err), websocket.StatusMessageTooBig, err)
	}
}
