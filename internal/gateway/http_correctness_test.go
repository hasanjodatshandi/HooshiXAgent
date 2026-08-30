package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestGatewayStreamQueueExhaustionIsIsolatedAcrossConcurrentStreams(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxStreamQueueFrames = 1
	limits.MaxStreamQueueBytes = 4
	limits.MaxSessionQueueBytes = 16
	limits.MaxGlobalQueueBytes = 32
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	sess := gateway.sessionForDevice(identity.deviceID)
	_, route := metadataRecords(identity, testRouteHost)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := sess.openStream(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	if frame := peer.read(t, ctx); frame.StreamID != first.id {
		t.Fatalf("first stream_open id=%d want=%d", frame.StreamID, first.id)
	}
	second, err := sess.openStream(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	if frame := peer.read(t, ctx); frame.StreamID != second.id {
		t.Fatalf("second stream_open id=%d want=%d", frame.StreamID, second.id)
	}

	if err := peer.sendData(ctx, first.id, []byte("1234")); err != nil {
		t.Fatal(err)
	}
	if err := peer.sendData(ctx, first.id, []byte("x")); err != nil {
		t.Fatal(err)
	}
	terminal := peer.read(t, ctx)
	var streamErr contractv1.StreamError
	if terminal.Kind != contractv1.KindControl || terminal.StreamID != first.id {
		t.Fatalf("overflow terminal kind=%d stream=%d", terminal.Kind, terminal.StreamID)
	}
	if err := json.Unmarshal(terminal.Payload, &streamErr); err != nil {
		t.Fatal(err)
	}
	if streamErr.MessageType != "stream_error" || streamErr.Code != "resource_limit" {
		t.Fatalf("overflow terminal=%+v", streamErr)
	}

	if err := peer.sendData(ctx, first.id, []byte("z")); err != nil {
		t.Fatal(err)
	}
	if err := peer.sendData(ctx, second.id, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2)
	if n, err := second.Read(buffer); err != nil || n != 2 || string(buffer[:n]) != "ok" {
		t.Fatalf("healthy stream n=%d err=%v body=%q", n, err, buffer[:n])
	}
	if gateway.sessionForDevice(identity.deviceID) != sess {
		t.Fatal("stream overload terminated Agent session")
	}
	select {
	case <-sess.done:
		t.Fatal("session closed after isolated overload")
	default:
	}
	peer.sendClose(t, ctx, second.id, "completed")
	waitFor(t, 2*time.Second, func() bool { sess.mu.Lock(); defer sess.mu.Unlock(); return len(sess.streams) == 0 })
}

func TestHopByHopHeadersAreRemovedAcrossTunnel(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	seenRequest := make(chan http.Header, 1)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenRequest <- r.Header.Clone()
		w.Header().Set("Connection", "X-Response-Hop, Keep-Alive")
		w.Header().Set("X-Response-Hop", "remove-me")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Proxy-Authenticate", "remove-me")
		w.Header().Set("X-End-To-End-Response", "kept")
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	request := newPublicRequest(t, tlsServer.URL+"/headers", testRouteHost, nil)
	request.Header.Set("Connection", "X-Request-Hop, Keep-Alive")
	request.Header.Set("X-Request-Hop", "remove-me")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("Proxy-Connection", "keep-alive")
	request.Header.Set("X-End-To-End", "kept")
	response, err := tlsServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	localHeaders := <-seenRequest
	for _, name := range []string{"Connection", "X-Request-Hop", "Keep-Alive", "Proxy-Connection"} {
		if value := localHeaders.Get(name); value != "" {
			t.Fatalf("request hop header %s=%q", name, value)
		}
	}
	if localHeaders.Get("X-End-To-End") != "kept" {
		t.Fatal("end-to-end request header removed")
	}
	for _, name := range []string{"Connection", "X-Response-Hop", "Keep-Alive", "Proxy-Authenticate"} {
		if value := response.Header.Get(name); value != "" {
			t.Fatalf("response hop header %s=%q", name, value)
		}
	}
	if response.Header.Get("X-End-To-End-Response") != "kept" {
		t.Fatal("end-to-end response header removed")
	}
}

func TestTunneledResponseHeaderLimitFailsClosed(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxHeaderBytes = 1024
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("h", 2048))
		_, _ = io.WriteString(w, "body")
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	response, err := tlsServer.Client().Do(newPublicRequest(t, tlsServer.URL+"/large-header", testRouteHost, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "headers too large") {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if gateway.sessionForDevice(identity.deviceID) == nil {
		t.Fatal("large response header terminated Agent session")
	}
}

func TestKnownLengthOversizedResponseFailsBeforeSuccessStatus(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxResponseBytes = 1024
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2048")
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, 2048))
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	response, err := tlsServer.Client().Do(newPublicRequest(t, tlsServer.URL+"/known-oversize", testRouteHost, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "response too large") {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
}

func TestOversizedChunkedResponseAbortsInsteadOfCleanTruncation(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxResponseBytes = 1024
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write(bytes.Repeat([]byte{'y'}, 2048))
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	response, err := tlsServer.Client().Do(newPublicRequest(t, tlsServer.URL+"/chunked-oversize", testRouteHost, nil))
	if err != nil {
		return
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	if readErr == nil {
		t.Fatalf("oversized unknown-length response ended cleanly status=%d bytes=%d", response.StatusCode, len(body))
	}
	if len(body) > int(limits.MaxResponseBytes) {
		t.Fatalf("public body exceeded bound: %d", len(body))
	}
	if gateway.sessionForDevice(identity.deviceID) == nil {
		t.Fatal("oversized response terminated Agent session")
	}
}

func TestResponseHeaderLimitReaderRejectsBeforeUnboundedParsing(t *testing.T) {
	reader := newResponseHeaderLimitReader(strings.NewReader("HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("a", 128)+"\r\n\r\nbody"), 64)
	_, err := http.ReadResponse(bufio.NewReader(reader), nil)
	if !errors.Is(err, errResponseHeaderTooLarge) {
		t.Fatalf("header parse error=%v want=%v", err, errResponseHeaderTooLarge)
	}
}

type r5RawAgent struct {
	conn        *websocket.Conn
	outSequence atomic.Uint64
	inbound     contractv1.SequenceTracker
}

func authenticateRawAgentForR5(t *testing.T, client *http.Client, baseURL string, identity testIdentity) *r5RawAgent {
	t.Helper()
	conn := dialRawAgent(t, client, baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hello := clientHello(identity)
	if err := sendHello(ctx, conn, hello, 1); err != nil {
		t.Fatal(err)
	}
	peer := &r5RawAgent{conn: conn}
	peer.outSequence.Store(1)
	challengeFrame := peer.read(t, ctx)
	var challenge contractv1.ServerChallenge
	if err := json.Unmarshal(challengeFrame.Payload, &challenge); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(identity.privateKey, contractv1.AuthTranscript(hello, challenge))
	auth := contractv1.ClientAuth{ContractVersion: contractv1.ProtocolVersion, MessageType: "client_auth", SessionID: challenge.SessionID, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	if err := peer.sendControl(ctx, 0, auth); err != nil {
		t.Fatal(err)
	}
	ready := peer.read(t, ctx)
	if err := contractv1.ValidateControlPayload(ready.Payload, 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return peer
}

func (peer *r5RawAgent) read(t *testing.T, ctx context.Context) contractv1.Frame {
	t.Helper()
	frame := readFrameForTest(t, ctx, peer.conn)
	if err := peer.inbound.Accept(frame.Sequence); err != nil {
		t.Fatal(err)
	}
	return frame
}

func (peer *r5RawAgent) sendControl(ctx context.Context, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return peer.sendFrame(ctx, contractv1.KindControl, streamID, payload)
}

func (peer *r5RawAgent) sendData(ctx context.Context, streamID uint32, payload []byte) error {
	return peer.sendFrame(ctx, contractv1.KindData, streamID, payload)
}

func (peer *r5RawAgent) sendClose(t *testing.T, ctx context.Context, streamID uint32, reason string) {
	t.Helper()
	if err := peer.sendControl(ctx, streamID, contractv1.StreamClose{ContractVersion: contractv1.ProtocolVersion, MessageType: "stream_close", ReasonCode: reason}); err != nil {
		t.Fatal(err)
	}
}

func (peer *r5RawAgent) sendFrame(ctx context.Context, kind contractv1.Kind, streamID uint32, payload []byte) error {
	sequence, err := contractv1.NextSequence(peer.outSequence.Load())
	if err != nil {
		return err
	}
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: kind, StreamID: streamID, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	peer.outSequence.Store(sequence)
	return peer.conn.Write(ctx, websocket.MessageBinary, encoded)
}
