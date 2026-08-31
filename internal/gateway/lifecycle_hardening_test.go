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
		limits:   DefaultLimits(),
		sessions: make(map[string]*session),
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
	gateway.sessions[deviceID] = old

	next := &session{
		gateway:                gateway,
		deviceID:               deviceID,
		sessionID:              "session-new",
		authorizationExpiresAt: time.Now().Add(time.Hour),
		streams:                make(map[uint32]*stream),
		done:                   make(chan struct{}),
	}
	next.authorized.Store(true)

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

	response, err := client.Get(server.URL + "/healthz")
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
		path string
		want int
	}{
		{path: "/healthz", want: http.StatusOK},
		{path: "/readyz", want: http.StatusServiceUnavailable},
		{path: agentPath, want: http.StatusServiceUnavailable},
		{path: "/public", want: http.StatusServiceUnavailable},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://gateway.test"+test.path, nil)
			request.Host = testRouteHost
			response := httptest.NewRecorder()
			gateway.Handler().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%q", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestGatewayCloseIsBoundedAndForceClosesStuckWebSocket(t *testing.T) {
	gateway := &Gateway{
		limits:   DefaultLimits(),
		sessions: make(map[string]*session),
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
	gateway.sessions[sess.deviceID] = sess

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
