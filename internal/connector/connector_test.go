package connector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestConnectorCarriesTCPAndPreservesHalfClose(t *testing.T) {
	serverErrors := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testToken() ||
			request.Header.Get("X-Hooshix-Grant-ID") != "grant-1" ||
			request.Header.Get("X-Hooshix-Token-ID") != "token-1" {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(response, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			serverErrors <- err
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
		defer cancel()
		messageType, payload, err := conn.Read(ctx)
		if err != nil || messageType != websocket.MessageBinary || string(payload) != string([]byte{dataFrame})+"hello" {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			serverErrors <- err
			return
		}
		_, payload, err = conn.Read(ctx)
		if err != nil || len(payload) != 1 || payload[0] != halfCloseFrame {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			serverErrors <- err
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, append([]byte{dataFrame}, []byte("reply")...)); err != nil {
			serverErrors <- err
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, []byte{halfCloseFrame}); err != nil {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}))
	defer server.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.GatewayURL = "wss" + strings.TrimPrefix(server.URL, "https") + "/connector/v1/connect"
	config.GrantID, config.TokenID, config.Token = "grant-1", "token-1", testToken()
	config.ListenAddress = listener.Addr().String()
	config.HTTPClient = server.Client()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, config, nil) }()

	local, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcp := local.(*net.TCPConn)
	if _, err := tcp.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(tcp)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	if string(reply) != "reply" {
		t.Fatalf("reply=%q want reply", reply)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestFlowFreesItsSlotWhenTheGatewayStopsReading: a stalled gateway leg makes
// the connector's write fail, and before the write error ended the flow nothing
// noticed until IdleTimeout — by default five minutes of one dead client holding
// the only slot, so the tunnel looks alive while refusing every new client.
func TestFlowFreesItsSlotWhenTheGatewayStopsReading(t *testing.T) {
	release := make(chan struct{})
	warnings := make(chan string, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(response, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		<-release
	}))
	defer close(release)
	defer server.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	flows := make(chan int, 32)
	config := DefaultConfig()
	config.GatewayURL = "wss" + strings.TrimPrefix(server.URL, "https") + "/connector/v1/connect"
	config.GrantID, config.TokenID, config.Token = "grant-1", "token-1", testToken()
	config.ListenAddress = listener.Addr().String()
	config.HTTPClient = server.Client()
	config.MaxConnections = 1
	config.WriteTimeout = 500 * time.Millisecond
	config.IdleTimeout = 30 * time.Second
	config.OnFlow = func(active int) {
		select {
		case flows <- active:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, listener, config, slog.New(&warningCollector{warnings: warnings})) }()

	local, err := net.Dial("tcp", config.ListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	if !waitForFlow(t, flows, 1) {
		t.Fatal("the first client was never counted")
	}
	go func() {
		// Filling the gateway's receive window is what forces the write to fail.
		_ = local.SetWriteDeadline(time.Now().Add(10 * time.Second))
		payload := make([]byte, 256<<10)
		for index := 0; index < 128; index++ {
			if _, err := local.Write(payload); err != nil {
				return
			}
		}
	}()

	if !waitForFlow(t, flows, 0) {
		t.Fatal("the stalled flow never released its slot")
	}
	select {
	case message := <-warnings:
		if message != "connector flow ended" {
			t.Errorf("unexpected warning: %q", message)
		}
	default:
		t.Error("a stalled flow ended without an error the operator can see")
	}

	// The released slot must be usable again, which is the whole point.
	second, err := net.Dial("tcp", config.ListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if !waitForFlow(t, flows, 1) {
		t.Fatal("a new client was refused after the stalled flow ended")
	}
	cancel()
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
}

func waitForFlow(t *testing.T, flows chan int, want int) bool {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case active := <-flows:
			if active == want {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// warningCollector keeps Serve's flow warnings observable to a test without a
// log file.
type warningCollector struct{ warnings chan string }

func (c *warningCollector) Enabled(context.Context, slog.Level) bool { return true }
func (c *warningCollector) Handle(_ context.Context, record slog.Record) error {
	select {
	case c.warnings <- record.Message:
	default:
	}
	return nil
}
func (c *warningCollector) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *warningCollector) WithGroup(string) slog.Handler      { return c }

func TestConfigRejectsPublicListenerAndInsecureGateway(t *testing.T) {
	config := DefaultConfig()
	config.GatewayURL = "ws://example.test/connector/v1/connect"
	config.GrantID, config.TokenID, config.Token = "grant-1", "token-1", testToken()
	if err := config.Validate(); err == nil {
		t.Fatal("insecure gateway URL was accepted")
	}
	config.GatewayURL = "wss://example.test/connector/v1/connect"
	config.ListenAddress = "0.0.0.0:13389"
	if err := config.Validate(); err == nil {
		t.Fatal("public connector listener was accepted")
	}
}

func testToken() string { return strings.Repeat("t", 43) }
