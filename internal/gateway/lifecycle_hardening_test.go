package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type failingEntropyReader struct {
	err error
}

func (reader failingEntropyReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func TestRegisterSessionDoesNotHoldGatewayMutexDuringPreviousSessionClose(t *testing.T) {
	gateway := &Gateway{
		limits:    DefaultLimits(),
		tunnels:   make(map[string]map[string]*session),
		primaries: make(map[string]*session),
	}
	deviceID := "device-ra1-lock"
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	old := &session{
		gateway:                gateway,
		deviceID:               deviceID,
		sessionID:              "session-old",
		authorizationExpiresAt: time.Now().Add(time.Hour),
		streams:                make(map[uint32]*stream),
		done:                   make(chan struct{}),
		closeConn: func(websocket.StatusCode, string) error {
			close(closeStarted)
			<-releaseClose
			return nil
		},
	}
	old.authorized.Store(true)
	old.lastSeen.Store(time.Now().UnixNano())
	gateway.tunnels[deviceID] = map[string]*session{old.sessionID: old}
	gateway.primaries[deviceID] = old

	// The replacement reuses the same session ID (the reconnect/resume
	// path), so it takes over the routing primary role for the device.
	next := &session{
		gateway:                gateway,
		deviceID:               deviceID,
		sessionID:              old.sessionID,
		authorizationExpiresAt: time.Now().Add(time.Hour),
		streams:                make(map[uint32]*stream),
		done:                   make(chan struct{}),
	}
	next.authorized.Store(true)
	next.lastSeen.Store(time.Now().UnixNano())

	registered := make(chan error, 1)
	go func() { registered <- gateway.registerSession(next) }()

	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("previous session close did not start")
	}

	lookup := make(chan *session, 1)
	go func() { lookup <- gateway.sessionForDevice(deviceID) }()
	select {
	case got := <-lookup:
		if got != next {
			t.Fatalf("session lookup returned %p want replacement %p", got, next)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("session lookup blocked behind previous network close; Gateway mutex is still held")
	}

	select {
	case err := <-registered:
		t.Fatalf("registerSession returned before blocked close was released: %v", err)
	default:
	}
	close(releaseClose)
	if err := <-registered; err != nil {
		t.Fatalf("register replacement: %v", err)
	}
}

func TestGatewayEntropyFailureFailsAuthenticationWithoutPanic(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.entropy = failingEntropyReader{err: errors.New("synthetic entropy unavailable")}

	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()
	opsServer := httptest.NewTLSServer(gateway.OpsHandler())
	defer opsServer.Close()
	client := server.Client()
	conn := dialRawAgent(t, client, server.URL)
	defer conn.CloseNow()
	if err := sendClientHello(context.Background(), conn, identity, 1); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("authentication unexpectedly continued after entropy failure")
	}

	response, err := opsServer.Client().Get(opsServer.URL + "/healthz")
	if err != nil {
		t.Fatalf("Gateway stopped serving after entropy failure: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d want=%d", response.StatusCode, http.StatusOK)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayBeginDrainRejectsNewWorkButKeepsLiveness(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.BeginDrain()

	for _, test := range []struct {
		name    string
		path    string
		want    int
		opsOnly bool
	}{
		{name: "healthz", path: "/healthz", want: http.StatusOK, opsOnly: true},
		{name: "readyz", path: "/readyz", want: http.StatusServiceUnavailable, opsOnly: true},
		{name: "agent", path: agentPath, want: http.StatusServiceUnavailable},
		{name: "public", path: "/public", want: http.StatusServiceUnavailable},
		// The operational paths are only servable by the administrative
		// handler. On the public listener they are ordinary tenant paths and
		// must be resolved as ingress (503 while draining), never as a
		// Gateway-local endpoint.
		{name: "public-healthz-is-ingress", path: "/healthz", want: http.StatusServiceUnavailable},
		{name: "public-metrics-is-ingress", path: "/metrics", want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://gateway.test"+test.path, nil)
			request.Host = testRouteHost
			response := httptest.NewRecorder()
			handler := gateway.Handler()
			if test.opsOnly {
				handler = gateway.OpsHandler()
			}
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%q", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestGatewayCloseIsBoundedAndForceClosesStuckWebSocket(t *testing.T) {
	gateway := &Gateway{
		limits:    DefaultLimits(),
		tunnels:   make(map[string]map[string]*session),
		primaries: make(map[string]*session),
	}
	blocked := make(chan struct{})
	var unblock sync.Once
	var forceCalled atomic.Bool
	sess := &session{
		gateway:                gateway,
		deviceID:               "device-ra1-drain",
		sessionID:              "session-ra1-drain",
		authorizationExpiresAt: time.Now().Add(time.Hour),
		streams:                make(map[uint32]*stream),
		done:                   make(chan struct{}),
		closeConn: func(websocket.StatusCode, string) error {
			<-blocked
			return nil
		},
		closeNowConn: func() error {
			forceCalled.Store(true)
			unblock.Do(func() { close(blocked) })
			return nil
		},
	}
	sess.authorized.Store(true)
	gateway.tunnels[sess.deviceID] = map[string]*session{sess.sessionID: sess}
	gateway.primaries[sess.deviceID] = sess

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := gateway.Close(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error=%v want context deadline", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("bounded Gateway.Close took %s", elapsed)
	}
	if !forceCalled.Load() {
		t.Fatal("Gateway.Close did not force-close a stuck WebSocket at the shutdown deadline")
	}
	if !gateway.draining.Load() {
		t.Fatal("Gateway did not enter draining state")
	}
	if got := gateway.sessionForDevice(sess.deviceID); got != nil {
		t.Fatal("drained Gateway still exposed a session")
	}
}

// TestGatewayDrainAfterInflightTunneledRequestSucceedsInFreshWindow proves the
// ordering contract cmd/gateway relies on: http.Server.Shutdown can spend its
// whole bounded window waiting for one in-flight public request (the tunnel
// response is what it is waiting on), and a tunnel drain started with its own
// fresh bounded window then completes successfully and releases that request.
// Sharing one window instead hands the drain an already-expired context, which
// reports a completed drain as "context deadline exceeded" and exits 1 — the
// same drain against a slower window is what a restart-on-failure supervisor
// would treat as a crash.
func TestGatewayDrainAfterInflightTunneledRequestSucceedsInFreshWindow(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A real loopback backend that never answers, so the public request stays
	// genuinely in flight over a real tunnel for the whole drain.
	backendReached := make(chan struct{})
	releaseBackend := make(chan struct{})
	var reachOnce sync.Once
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachOnce.Do(func() { close(backendReached) })
		<-releaseBackend
	}))
	defer local.Close()
	defer close(releaseBackend)

	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	peer := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer peer.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	type outcome struct {
		status int
		err    error
	}
	inflight := make(chan outcome, 1)
	go func() {
		request, err := newPublicRequestAsync(t, tlsServer.URL+"/inflight", testRouteHost, nil)
		if err != nil {
			inflight <- outcome{err: err}
			return
		}
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			inflight <- outcome{err: err}
			return
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, response.Body)
		inflight <- outcome{status: response.StatusCode, err: err}
	}()

	select {
	case <-backendReached:
	case <-time.After(5 * time.Second):
		t.Fatal("tunneled request never reached the loopback backend")
	}

	// Production shutdown ordering: enter draining, give the listener its own
	// bounded window, then drain tunnels in a separate fresh bounded window.
	gateway.BeginDrain()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelShutdown()
	serverErr := tlsServer.Config.Shutdown(shutdownCtx)
	if !errors.Is(serverErr, context.DeadlineExceeded) {
		t.Fatalf("listener shutdown error=%v want a bounded timeout with the tunneled request still in flight", serverErr)
	}

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDrain()
	if err := gateway.Close(drainCtx); err != nil {
		t.Fatalf("tunnel drain in a fresh bounded window failed: %v", err)
	}

	select {
	case got := <-inflight:
		t.Logf("in-flight tunneled request released by the drain: status=%d error=%v", got.status, got.err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight tunneled request was not released by the drain")
	}

	if got := gateway.sessionForDevice(identity.deviceID); got != nil {
		t.Fatal("drained Gateway still exposed a session")
	}
	waitFor(t, time.Second, func() bool { return len(gateway.resources.ingressSlots) == 0 })
}
