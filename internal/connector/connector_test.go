package connector

import (
	"context"
	"io"
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
