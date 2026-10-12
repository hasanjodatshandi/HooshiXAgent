package connectgui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// bundleFor builds a valid bundle for the given protocol. It deliberately does
// not carry a listen address: the loopback port belongs to the connecting
// machine, not to the Panel, so tests steer the bind through the seams below.
func bundleFor(t *testing.T, protocol string) string {
	t.Helper()
	payload, err := json.Marshal(connector.Bundle{
		GatewayURL:     "wss://edge.hooshix-agent.ir/connector/v1/connect",
		GrantID:        "grant-UPG9c9GFPY3Z",
		TokenID:        "token-C6_j48B9",
		Token:          strings.Repeat("a", 32),
		Protocol:       protocol,
		MaxConnections: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return connector.BundlePrefix + base64.RawURLEncoding.EncodeToString(payload)
}

// newEphemeralApp binds any real loopback port the OS hands out, so tests never
// collide with a fixed port or with each other.
func newEphemeralApp() *App {
	app := New()
	app.listenTCP = func(network, address string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	app.listenUDP = func(network, address string) (net.PacketConn, error) {
		return net.ListenPacket("udp", "127.0.0.1:0")
	}
	return app
}

func TestConnectBindsLoopbackAndReportsListening(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer app.Disconnect()

	status := app.Status()
	if status.State != StateListening || status.Protocol != "tcp" {
		t.Fatalf("status after Connect: %+v", status)
	}
	host, _, err := net.SplitHostPort(status.Listen)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("status did not report the bound loopback address: %+v", status)
	}
	if !strings.Contains(status.Message, status.Listen) {
		t.Fatalf("status message lost the address: %+v", status)
	}
	// The port really is served, which is what the Open Remote Desktop button
	// depends on.
	conn, err := net.Dial("tcp", status.Listen)
	if err != nil {
		t.Fatalf("listener not accepting: %v", err)
	}
	_ = conn.Close()
}

func TestConnectRejectsNonLoopbackBind(t *testing.T) {
	app := New()
	app.listenTCP = func(string, string) (net.Listener, error) {
		return fakeListener{addr: "203.0.113.7:13389"}, nil
	}
	if err := app.Connect(bundleFor(t, "tcp")); err == nil ||
		!strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback bind accepted: %v", err)
	}
	if status := app.Status(); status.State != StateFailed {
		t.Fatalf("state after refused bind: %+v", status)
	}
}

func TestConnectRejectsBadBundleWithoutTouchingTheSocket(t *testing.T) {
	app := newEphemeralApp()
	binds := 0
	original := app.listenTCP
	app.listenTCP = func(network, address string) (net.Listener, error) {
		binds++
		return original(network, address)
	}
	if err := app.Connect("hx1.not-really-base64"); err == nil {
		t.Fatal("malformed bundle accepted")
	}
	if binds != 0 {
		t.Fatalf("a rejected bundle bound %d sockets", binds)
	}
	status := app.Status()
	if status.State != StateFailed || status.Message == "" {
		t.Fatalf("bad bundle left %+v, want a failure the window can show", status)
	}
}

func TestConnectAllowsExactlyOneSession(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	defer app.Disconnect()

	if err := app.Connect(bundleFor(t, "tcp")); err == nil ||
		!strings.Contains(err.Error(), "already connected") {
		t.Fatalf("second Connect: %v", err)
	}
	if status := app.Status(); status.State != StateListening {
		t.Fatalf("rejected Connect disturbed the live session: %+v", status)
	}
}

func TestConnectReportsBindFailure(t *testing.T) {
	app := New()
	app.listenTCP = func(string, string) (net.Listener, error) {
		return nil, errors.New("bind: Only one usage of each socket address")
	}
	if err := app.Connect(bundleFor(t, "tcp")); err == nil {
		t.Fatal("bind failure swallowed")
	}
	if status := app.Status(); status.State != StateFailed ||
		!strings.Contains(status.Message, "socket address") {
		t.Fatalf("bind failure not surfaced: %+v", status)
	}
}

func TestDisconnectReleasesThePortAndIsIdempotent(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	address := app.Status().Listen
	app.Disconnect()
	app.Disconnect()

	if status := app.Status(); status.State != StateStopped {
		t.Fatalf("status after Disconnect: %+v", status)
	}
	// Disconnect must wait for the serving goroutine, so the port is free again.
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("port still held after Disconnect: %v", err)
	}
	_ = rebound.Close()

	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatalf("reconnect after Disconnect: %v", err)
	}
	app.Disconnect()
}

func TestConnectSupportsUDPBundles(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "udp")); err != nil {
		t.Fatalf("udp Connect: %v", err)
	}
	defer app.Disconnect()

	status := app.Status()
	if status.State != StateListening || status.Protocol != "udp" {
		t.Fatalf("udp session: %+v", status)
	}
	if status.Listen == "" || strings.HasSuffix(status.Listen, ":0") {
		t.Fatalf("udp status lost the bound address: %+v", status)
	}
}

func TestFlowWarningUpdatesMessageWithoutEndingSession(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	defer app.Disconnect()

	slog.New(&statusHandler{app: app, session: app.sessionID()}).
		Warn("connector flow ended", "error", "connector gateway rejected connection: HTTP 401")

	deadline := time.Now().Add(2 * time.Second)
	for {
		status := app.Status()
		if strings.Contains(status.Message, "HTTP 401") {
			if status.State != StateListening {
				t.Fatalf("a single failed flow changed the state to %q", status.State)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow warning never reached the status: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFlowCountSeparatesAnIdleTunnelFromAnAttachedClient: before this count
// existed, "nobody dialed the port" and "a client dialed and dropped" looked
// identical in the window, which is what sent an operator clicking Connect again.
func TestFlowCountSeparatesAnIdleTunnelFromAnAttachedClient(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	defer app.Disconnect()
	session := app.sessionID()

	status := app.Status()
	if status.Flows != 0 || !strings.Contains(status.Message, "tunnel ready") {
		t.Fatalf("idle tunnel: %+v", status)
	}
	if strings.Contains(status.Message, "connected") {
		t.Fatalf("an idle tunnel claims a client: %+v", status.Message)
	}

	app.noteFlows(session, 1)
	status = app.Status()
	if status.Flows != 1 || !strings.Contains(status.Message, "1 client connected") {
		t.Fatalf("one client: %+v", status)
	}
	if ButtonsFor(status, false).OpenClient {
		t.Error("the second-client button stayed live while one was attached")
	}

	app.noteFlows(session, 3)
	if status := app.Status(); !strings.Contains(status.Message, "3 clients connected") {
		t.Fatalf("three clients: %+v", status.Message)
	}

	app.noteFlows(session, 0)
	if status := app.Status(); status.Flows != 0 || strings.Contains(status.Message, "connected") {
		t.Fatalf("detached clients: %+v", status)
	}

	app.recordFlowEvent(session, "connection reset by peer")
	if status := app.Status(); !strings.Contains(status.Message, "Last client ended: connection reset by peer") {
		t.Fatalf("flow failure lost from the message: %+v", status.Message)
	}
	app.noteFlows(session, 1)
	if status := app.Status(); strings.Contains(status.Message, "Last client ended") {
		t.Fatalf("a live client still reports the previous one's failure: %+v", status.Message)
	}
}

// TestFlowReportsFromAReplacedSessionAreDropped: Serve returns while its flow
// goroutines are still finishing, so their counts belong to a listener that no
// longer exists and must not be painted onto the next session.
func TestFlowReportsFromAReplacedSessionAreDropped(t *testing.T) {
	app := newEphemeralApp()
	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	stale := app.sessionID()
	app.Disconnect()

	if err := app.Connect(bundleFor(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	defer app.Disconnect()

	app.noteFlows(stale, 2)
	app.recordFlowEvent(stale, "connector flow ended: stale session")
	status := app.Status()
	if status.Flows != 0 || strings.Contains(status.Message, "stale") {
		t.Fatalf("a replaced session rewrote the live status: %+v", status)
	}
	app.noteFlows(app.sessionID(), 1)
	if status := app.Status(); status.Flows != 1 {
		t.Fatalf("the live session stopped being reported: %+v", status)
	}
}

// TestConcurrentConnectStartsOneSession hammers Connect from several threads:
// exactly one session may win, because the one-session check and the bind have
// to be atomic or the loser leaks a bound socket.
func TestConcurrentConnectStartsOneSession(t *testing.T) {
	app := newEphemeralApp()
	var wg sync.WaitGroup
	results := make([]error, 8)
	for index := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = app.Connect(bundleFor(t, "tcp"))
		}(index)
	}
	wg.Wait()

	wins := 0
	for _, err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent Connect produced %d sessions, want 1", wins)
	}
	app.Disconnect()
}

// fakeListener reports an address the app must reject.
type fakeListener struct{ addr string }

func (fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not used") }
func (fakeListener) Close() error              { return nil }
func (l fakeListener) Addr() net.Addr          { return fakeAddr(l.addr) }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }
