package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const testRouteHost = "demo.hooshix.test"

type testIdentity struct {
	deviceID        string
	authorizationID string
	tokenID         string
	token           string
	publicKey       ed25519.PublicKey
	privateKey      ed25519.PrivateKey
}

type statusRecorder struct {
	mu      sync.Mutex
	signals []contractv1.GatewayStatusSignal
}

func (recorder *statusRecorder) Emit(_ context.Context, signal contractv1.GatewayStatusSignal) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.signals = append(recorder.signals, signal)
	return nil
}

func (recorder *statusRecorder) count(kind string) int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	count := 0
	for _, signal := range recorder.signals {
		if signal.Kind == kind {
			count++
		}
	}
	return count
}

func (recorder *statusRecorder) latest(kind string) (contractv1.GatewayStatusSignal, bool) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for i := len(recorder.signals) - 1; i >= 0; i-- {
		if recorder.signals[i].Kind == kind {
			return recorder.signals[i], true
		}
	}
	return contractv1.GatewayStatusSignal{}, false
}

func TestGatewayWSSAuthenticationMultiplexingAndReconnect(t *testing.T) {
	t.Parallel()

	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	statuses := &statusRecorder{}
	limits := DefaultLimits()
	limits.MaxStreamsPerSession = 4
	limits.MaxRequestBytes = 1 << 20
	limits.MaxResponseBytes = 2 << 20
	gateway, err := New(metadata, statuses, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	})
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	var pairCount atomic.Int32
	pairReady := make(chan struct{})
	var pairOnce sync.Once
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" || r.URL.Path == "/two" {
			if pairCount.Add(1) == 2 {
				pairOnce.Do(func() { close(pairReady) })
			}
			select {
			case <-pairReady:
			case <-time.After(2 * time.Second):
				http.Error(w, "pair barrier timeout", http.StatusGatewayTimeout)
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Local-Service", "true")
		fmt.Fprintf(w, "local:%s:%s", r.URL.Path, body)
	}))
	defer local.Close()

	client := tlsServer.Client()
	offline := newPublicRequest(t, tlsServer.URL+"/offline", testRouteHost, nil)
	response, err := client.Do(offline)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("offline status=%d want=%d", response.StatusCode, http.StatusServiceUnavailable)
	}
	response.Body.Close()

	agent := connectMockAgent(t, context.Background(), tlsServer.URL, client, identity, local.URL)
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for _, path := range []string{"/one", "/two"} {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newPublicRequest(t, tlsServer.URL+path, testRouteHost, strings.NewReader("payload"+path))
			resp, err := client.Do(req)
			if err != nil {
				errorsCh <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errorsCh <- err
				return
			}
			if resp.StatusCode != http.StatusOK || string(body) != "local:"+path+":payload"+path {
				errorsCh <- fmt.Errorf("unexpected tunneled response status=%d body=%q", resp.StatusCode, body)
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if max := agent.maxConcurrent.Load(); max < 2 {
		t.Fatalf("expected multiplexing with at least 2 concurrent streams, got %d", max)
	}

	agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) == nil })

	reconnected := connectMockAgent(t, context.Background(), tlsServer.URL, client, identity, local.URL)
	defer reconnected.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	req := newPublicRequest(t, tlsServer.URL+"/reconnected", testRouteHost, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "local:/reconnected:" {
		t.Fatalf("reconnected response status=%d body=%q", resp.StatusCode, body)
	}

	waitFor(t, 2*time.Second, func() bool {
		return statuses.count("session_connected") >= 2 && statuses.count("traffic_delta") >= 3
	})
}

func TestGatewayRejectsUntrustedTLSInvalidTokenAndReplay(t *testing.T) {
	t.Parallel()

	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	wssURL := "wss" + strings.TrimPrefix(tlsServer.URL, "https") + agentPath
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, _, err := websocket.Dial(ctx, wssURL, nil); err == nil {
		conn.CloseNow()
		t.Fatal("expected WSS connection with untrusted certificate to fail")
	}

	badIdentity := identity
	badIdentity.token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	trusted := tlsServer.Client()
	conn := dialRawAgent(t, trusted, tlsServer.URL)
	defer conn.CloseNow()
	if err := sendClientHello(context.Background(), conn, badIdentity, 1); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("expected invalid token connection to be closed")
	}

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, trusted, identity, local.URL)
	defer agent.close()
	if err := agent.sendControlWithSequence(context.Background(), 3, 0, contractv1.Heartbeat{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "ping",
		PingID:          "replay-probe",
		SentAt:          time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := agent.sendControlWithSequence(context.Background(), 3, 0, contractv1.Heartbeat{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "ping",
		PingID:          "replay-probe",
		SentAt:          time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) == nil })
}

func TestGatewayProtocolHeartbeat(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	limits.HeartbeatInterval = 5 * time.Second
	limits.IdleTimeout = 15 * time.Second
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 7*time.Second, func() bool { return agent.pings.Load() >= 1 })
	if gateway.sessionForDevice(identity.deviceID) == nil {
		t.Fatal("heartbeat-capable session unexpectedly closed")
	}
}

func TestGatewayRequestAndStreamLimits(t *testing.T) {
	t.Parallel()

	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	limits.MaxRequestBytes = 32
	limits.MaxStreamsPerSession = 1
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			started <- struct{}{}
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()

	oversized := newPublicRequest(t, tlsServer.URL+"/large", testRouteHost, bytes.NewReader(bytes.Repeat([]byte{'x'}, 33)))
	resp, err := tlsServer.Client().Do(oversized)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status=%d", resp.StatusCode)
	}

	firstDone := make(chan error, 1)
	go func() {
		request := newPublicRequest(t, tlsServer.URL+"/hold", testRouteHost, nil)
		response, err := tlsServer.Client().Do(request)
		if err == nil {
			response.Body.Close()
		}
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first stream did not become active")
	}
	second := newPublicRequest(t, tlsServer.URL+"/second", testRouteHost, nil)
	secondResp, err := tlsServer.Client().Do(second)
	if err != nil {
		t.Fatal(err)
	}
	secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stream limit status=%d want=%d", secondResp.StatusCode, http.StatusServiceUnavailable)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequestStreamWriterBoundsChunkRetentionAndAccounting(t *testing.T) {
	budget := newByteBudget(64 << 10)
	var rejects atomic.Uint64
	var observedPeak int64
	var observedMaxChunk int
	writer := newRequestStreamWriter(context.Background(), budget, &rejects, func(_ context.Context, payload []byte) error {
		used, _, _ := budget.snapshot()
		if used > observedPeak {
			observedPeak = used
		}
		if len(payload) > observedMaxChunk {
			observedMaxChunk = len(payload)
		}
		return nil
	})
	payload := bytes.Repeat([]byte{'x'}, 8<<20)
	n, err := writer.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("stream write n=%d err=%v", n, err)
	}
	if writer.Written() != int64(len(payload)) {
		t.Fatalf("written=%d want=%d", writer.Written(), len(payload))
	}
	if observedMaxChunk > requestStreamChunkSize || observedPeak > requestStreamChunkSize {
		t.Fatalf("streaming retention exceeded chunk bound: max_chunk=%d peak_budget=%d", observedMaxChunk, observedPeak)
	}
	if used, _, _ := budget.snapshot(); used != 0 {
		t.Fatalf("streaming writer leaked byte budget: %d", used)
	}
	if rejects.Load() != 0 {
		t.Fatalf("unexpected ingress budget rejection: %d", rejects.Load())
	}
}

func BenchmarkRequestStreamWriterBoundedRetention(b *testing.B) {
	b.StopTimer()
	payload := bytes.Repeat([]byte{'x'}, 8<<20)
	budget := newByteBudget(64 << 10)
	var rejects atomic.Uint64
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer := newRequestStreamWriter(context.Background(), budget, &rejects, func(context.Context, []byte) error { return nil })
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGatewayStreamsRequestBeforeUploadCompletesAndAccountsTunnelBytes(t *testing.T) {
	identity := newTestIdentity(t)
	statuses := &statusRecorder{}
	limits := DefaultLimits()
	limits.IngressRatePerSecond = 1000
	limits.IngressRateBurst = 1000
	gateway, err := New(testMetadata(t, identity, testRouteHost), statuses, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	})
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	firstByte := make(chan struct{})
	var firstOnce sync.Once
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, 1)
		n, err := io.ReadFull(r.Body, buffer)
		if err != nil || n != 1 {
			http.Error(w, "body read failed", http.StatusBadRequest)
			return
		}
		firstOnce.Do(func() { close(firstByte) })
		rest, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "body copy failed", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "%d", rest+1)
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	const bodySize = 512 << 10
	reader, writer := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, tlsServer.URL+"/streaming", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = testRouteHost
	request.ContentLength = bodySize
	beforeTunnelBytes := agent.dataFromGateway.Load()
	result := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := tlsServer.Client().Do(request)
		result <- struct {
			response *http.Response
			err      error
		}{response: response, err: err}
	}()

	firstChunk := bytes.Repeat([]byte{'a'}, 64<<10)
	if _, err := writer.Write(firstChunk); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstByte:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive request body before public upload completed; request path is still buffering")
	}
	remaining := bodySize - len(firstChunk)
	if _, err := writer.Write(bytes.Repeat([]byte{'b'}, remaining)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	outcome := <-result
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	defer outcome.response.Body.Close()
	body, _ := io.ReadAll(outcome.response.Body)
	if outcome.response.StatusCode != http.StatusOK || string(body) != fmt.Sprintf("%d", bodySize) {
		t.Fatalf("streamed response status=%d body=%q", outcome.response.StatusCode, body)
	}
	waitFor(t, 2*time.Second, func() bool { return statuses.count("traffic_delta") > 0 })
	signal, ok := statuses.latest("traffic_delta")
	if !ok || signal.BytesFromPublic == nil {
		t.Fatal("streamed request traffic signal missing bytes_from_public")
	}
	tunnelDelta := agent.dataFromGateway.Load() - beforeTunnelBytes
	if *signal.BytesFromPublic != tunnelDelta {
		t.Fatalf("traffic accounting=%d tunnel_data_bytes=%d", *signal.BytesFromPublic, tunnelDelta)
	}
	if *signal.BytesFromPublic < bodySize {
		t.Fatalf("traffic accounting=%d smaller than request body=%d", *signal.BytesFromPublic, bodySize)
	}
	if used, _, _ := gateway.resources.ingressBytes.snapshot(); used != 0 {
		t.Fatalf("ingress streaming budget leaked after request: %d", used)
	}
}

func TestGatewayStreamingUploadCancellationReleasesResources(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.IngressRatePerSecond = 1000
	limits.IngressRateBurst = 1000
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	firstByte := make(chan struct{})
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, 1)
		if _, err := io.ReadFull(r.Body, buffer); err == nil {
			close(firstByte)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "done")
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	ctx, cancel := context.WithCancel(context.Background())
	reader, pipeWriter := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tlsServer.URL+"/cancel", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = testRouteHost
	request.ContentLength = 4 << 20
	result := make(chan error, 1)
	go func() {
		response, err := tlsServer.Client().Do(request)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	if _, err := pipeWriter.Write(bytes.Repeat([]byte{'x'}, 64<<10)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstByte:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not observe partial upload before cancellation")
	}
	cancel()
	_ = pipeWriter.CloseWithError(context.Canceled)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled public upload unexpectedly completed successfully")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled public upload did not terminate promptly")
	}
	waitFor(t, 3*time.Second, func() bool {
		used, _, _ := gateway.resources.ingressBytes.snapshot()
		return used == 0 && len(gateway.resources.ingressSlots) == 0 && agent.active.Load() == 0
	})
}

func TestExternalProcessRuntimeGate(t *testing.T) {
	binary := os.Getenv("HOOSHIX_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set HOOSHIX_GATEWAY_BINARY to exercise the real gateway executable")
	}

	identity := newTestIdentity(t)
	metadataDir := t.TempDir()
	writeMetadataSnapshot(t, metadataDir, identity, testRouteHost)
	certPath, keyPath, roots := writeTestCertificate(t)
	address := reserveAddress(t)

	cmd := exec.Command(binary,
		"-listen", address,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Signal(os.Interrupt)
			_, _ = cmd.Process.Wait()
		}
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	baseURL := "https://" + address
	waitFor(t, 5*time.Second, func() bool {
		resp, err := client.Get(baseURL + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "process:%s", r.URL.Path)
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), baseURL, client, identity, local.URL)

	req := newPublicRequest(t, baseURL+"/runtime", testRouteHost, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("runtime public request: %v\nstderr=%s", err, stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "process:/runtime" {
		t.Fatalf("runtime response status=%d body=%q\nstderr=%s", resp.StatusCode, body, stderr.String())
	}

	agent.close()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gateway graceful shutdown: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"kind":"traffic_delta"`) {
		t.Fatalf("expected traffic status signal on stdout, got %q", stdout.String())
	}
}

func TestExecutableRefusesPlaintextStartup(t *testing.T) {
	binary := os.Getenv("HOOSHIX_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set HOOSHIX_GATEWAY_BINARY to exercise the real gateway executable")
	}
	cmd := exec.Command(binary, "-metadata-dir", t.TempDir())
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("gateway unexpectedly started without TLS certificate/key")
	}
	if !strings.Contains(string(output), "tls-cert") {
		t.Fatalf("expected TLS startup rejection, output=%q", output)
	}
}

type mockAgent struct {
	conn            *websocket.Conn
	identity        testIdentity
	localURL        *url.URL
	httpClient      *http.Client
	writeMu         sync.Mutex
	outSequence     atomic.Uint64
	inSequence      contractv1.SequenceTracker
	mu              sync.Mutex
	streams         map[uint32]*mockStream
	done            chan struct{}
	closeOnce       sync.Once
	active          atomic.Int32
	maxConcurrent   atomic.Int32
	pings           atomic.Int32
	dataFromGateway atomic.Int64
}

type mockStream struct {
	id       uint32
	incoming chan []byte
	done     chan struct{}
}

func connectMockAgent(t *testing.T, parent context.Context, baseURL string, client *http.Client, identity testIdentity, localServiceURL string) *mockAgent {
	t.Helper()
	parsed, err := url.Parse(localServiceURL)
	if err != nil {
		t.Fatal(err)
	}
	agent := &mockAgent{
		identity:   identity,
		localURL:   parsed,
		httpClient: localHTTPClient(localServiceURL),
		streams:    make(map[uint32]*mockStream),
		done:       make(chan struct{}),
	}
	conn := dialRawAgent(t, client, baseURL)
	agent.conn = conn

	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	hello := clientHello(identity)
	if err := sendHello(ctx, conn, hello, 1); err != nil {
		t.Fatal(err)
	}
	agent.outSequence.Store(1)

	challengeFrame := readFrameForTest(t, ctx, conn)
	if challengeFrame.Sequence != 1 {
		t.Fatalf("challenge sequence=%d", challengeFrame.Sequence)
	}
	if err := agent.inSequence.Accept(challengeFrame.Sequence); err != nil {
		t.Fatal(err)
	}
	var challenge contractv1.ServerChallenge
	if err := json.Unmarshal(challengeFrame.Payload, &challenge); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(identity.privateKey, contractv1.AuthTranscript(hello, challenge))
	auth := contractv1.ClientAuth{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "client_auth",
		SessionID:       challenge.SessionID,
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
	}
	if err := agent.sendControlWithSequence(ctx, 2, 0, auth); err != nil {
		t.Fatal(err)
	}
	agent.outSequence.Store(2)
	ready := readFrameForTest(t, ctx, conn)
	if err := agent.inSequence.Accept(ready.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := contractv1.ValidateControlPayload(ready.Payload, 0, time.Now().UTC()); err != nil {
		t.Fatalf("session_ready: %v", err)
	}

	go agent.readLoop()
	return agent
}

func (agent *mockAgent) readLoop() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		frame, err := readFrame(ctx, agent.conn)
		cancel()
		if err != nil {
			agent.close()
			return
		}
		if err := agent.inSequence.Accept(frame.Sequence); err != nil {
			agent.close()
			return
		}
		switch frame.Kind {
		case contractv1.KindControl:
			agent.handleControl(frame)
		case contractv1.KindData:
			agent.dataFromGateway.Add(int64(len(frame.Payload)))
			agent.mu.Lock()
			stream := agent.streams[frame.StreamID]
			agent.mu.Unlock()
			if stream == nil {
				agent.close()
				return
			}
			select {
			case stream.incoming <- append([]byte(nil), frame.Payload...):
			default:
				agent.close()
				return
			}
		}
	}
}

func (agent *mockAgent) handleControl(frame contractv1.Frame) {
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
		agent.close()
		return
	}
	switch envelope.MessageType {
	case "stream_open":
		var open contractv1.StreamOpen
		if err := json.Unmarshal(frame.Payload, &open); err != nil || open.LocalEndpointID != "local-http-001" {
			agent.close()
			return
		}
		stream := &mockStream{id: frame.StreamID, incoming: make(chan []byte, 64), done: make(chan struct{})}
		agent.mu.Lock()
		agent.streams[frame.StreamID] = stream
		agent.mu.Unlock()
		active := agent.active.Add(1)
		for {
			current := agent.maxConcurrent.Load()
			if active <= current || agent.maxConcurrent.CompareAndSwap(current, active) {
				break
			}
		}
		go agent.proxyStream(stream)
	case "stream_close":
		agent.finishStream(frame.StreamID)
	case "ping":
		agent.pings.Add(1)
		var ping contractv1.Heartbeat
		if err := json.Unmarshal(frame.Payload, &ping); err == nil {
			_ = agent.sendControl(context.Background(), 0, contractv1.Heartbeat{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "pong",
				PingID:          ping.PingID,
				ReceivedAt:      time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
}

func (agent *mockAgent) proxyStream(stream *mockStream) {
	defer agent.finishStream(stream.id)
	reader := &mockStreamReader{stream: stream}
	request, err := http.ReadRequest(bufio.NewReader(reader))
	if err != nil {
		_ = agent.sendStreamError(stream.id, "protocol_error", err.Error())
		return
	}
	request.RequestURI = ""
	request.URL.Scheme = agent.localURL.Scheme
	request.URL.Host = agent.localURL.Host
	request.Host = agent.localURL.Host
	response, err := agent.httpClient.Do(request)
	if err != nil {
		_ = agent.sendStreamError(stream.id, "local_target_unavailable", err.Error())
		return
	}
	defer response.Body.Close()
	var encoded bytes.Buffer
	if err := response.Write(&encoded); err != nil {
		_ = agent.sendStreamError(stream.id, "internal_error", err.Error())
		return
	}
	if err := agent.sendBytes(context.Background(), stream.id, encoded.Bytes()); err != nil {
		return
	}
	_ = agent.sendControl(context.Background(), stream.id, contractv1.StreamClose{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "stream_close",
		ReasonCode:      "completed",
	})
}

func (agent *mockAgent) finishStream(id uint32) {
	agent.mu.Lock()
	stream := agent.streams[id]
	delete(agent.streams, id)
	agent.mu.Unlock()
	if stream != nil {
		select {
		case <-stream.done:
		default:
			close(stream.done)
			agent.active.Add(-1)
		}
	}
}

func (agent *mockAgent) sendStreamError(streamID uint32, code, message string) error {
	if len(message) > 256 {
		message = message[:256]
	}
	return agent.sendControl(context.Background(), streamID, contractv1.StreamError{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "stream_error",
		Code:            code,
		Message:         message,
		Retryable:       false,
	})
}

func (agent *mockAgent) sendControl(ctx context.Context, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return agent.writeNextFrame(ctx, contractv1.KindControl, streamID, payload)
}

func (agent *mockAgent) sendControlWithSequence(ctx context.Context, sequence uint64, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return agent.writeFrame(ctx, contractv1.Frame{Kind: contractv1.KindControl, StreamID: streamID, Sequence: sequence, Payload: payload})
}

func (agent *mockAgent) sendBytes(ctx context.Context, streamID uint32, data []byte) error {
	for len(data) > 0 {
		size := len(data)
		if size > contractv1.MaxDataPayload {
			size = contractv1.MaxDataPayload
		}
		if err := agent.writeNextFrame(ctx, contractv1.KindData, streamID, data[:size]); err != nil {
			return err
		}
		data = data[size:]
	}
	return nil
}

func (agent *mockAgent) writeNextFrame(parent context.Context, kind contractv1.Kind, streamID uint32, payload []byte) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	sequence := agent.outSequence.Add(1)
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: kind, StreamID: streamID, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	return agent.conn.Write(ctx, websocket.MessageBinary, encoded)
}

func (agent *mockAgent) writeFrame(parent context.Context, frame contractv1.Frame) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	encoded, err := contractv1.EncodeFrame(frame)
	if err != nil {
		return err
	}
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	return agent.conn.Write(ctx, websocket.MessageBinary, encoded)
}

func (agent *mockAgent) close() {
	agent.closeOnce.Do(func() {
		close(agent.done)
		agent.conn.CloseNow()
	})
}

type mockStreamReader struct {
	stream *mockStream
	buffer []byte
}

func (reader *mockStreamReader) Read(data []byte) (int, error) {
	for len(reader.buffer) == 0 {
		select {
		case chunk := <-reader.stream.incoming:
			reader.buffer = chunk
		case <-reader.stream.done:
			return 0, io.EOF
		case <-time.After(5 * time.Second):
			return 0, errors.New("mock stream read timeout")
		}
	}
	n := copy(data, reader.buffer)
	reader.buffer = reader.buffer[n:]
	return n, nil
}

func newTestIdentity(t *testing.T) testIdentity {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	return testIdentity{
		deviceID:        "device-runtime-001",
		authorizationID: "auth-runtime-001",
		tokenID:         "token-runtime-001",
		token:           base64.RawURLEncoding.EncodeToString(tokenBytes),
		publicKey:       publicKey,
		privateKey:      privateKey,
	}
}

func testMetadata(t *testing.T, identity testIdentity, hostname string) *SnapshotMetadata {
	t.Helper()
	source := NewSnapshotMetadata()
	auth, route := metadataRecords(identity, hostname)
	authJSON, _ := json.Marshal(auth)
	routeJSON, _ := json.Marshal(route)
	if err := source.addAuthorizationJSON(authJSON); err != nil {
		t.Fatal(err)
	}
	if err := source.addRouteJSON(routeJSON); err != nil {
		t.Fatal(err)
	}
	return source
}

func metadataRecords(identity testIdentity, hostname string) (contractv1.DeviceSessionAuthorization, contractv1.EndpointRouteAssignment) {
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(identity.token))
	auth := contractv1.DeviceSessionAuthorization{
		ContractVersion: contractv1.ProtocolVersion,
		AuthorizationID: identity.authorizationID,
		DeviceID:        identity.deviceID,
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(identity.publicKey),
		TokenID:         identity.tokenID,
		TokenSHA256:     hex.EncodeToString(digest[:]),
		IssuedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
		Disabled:        false,
	}
	route := contractv1.EndpointRouteAssignment{
		ContractVersion: contractv1.ProtocolVersion,
		AssignmentID:    "assign-runtime-001",
		EndpointID:      "endpoint-runtime-001",
		PublicHostname:  hostname,
		DeviceID:        identity.deviceID,
		LocalEndpointID: "local-http-001",
		Enabled:         true,
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
	}
	return auth, route
}

func writeMetadataSnapshot(t *testing.T, root string, identity testIdentity, hostname string) {
	t.Helper()
	auth, route := metadataRecords(identity, hostname)
	if err := WriteSnapshotRecord(root, "authorizations", "auth.json", auth); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotRecord(root, "routes", "route.json", route); err != nil {
		t.Fatal(err)
	}
}

func dialRawAgent(t *testing.T, client *http.Client, baseURL string) *websocket.Conn {
	t.Helper()
	wssURL := "wss" + strings.TrimPrefix(baseURL, "https") + agentPath
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wssURL, &websocket.DialOptions{HTTPClient: client, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		t.Fatalf("dial agent WSS: %v", err)
	}
	conn.SetReadLimit(contractv1.HeaderSize + contractv1.MaxDataPayload)
	return conn
}

func clientHello(identity testIdentity) contractv1.ClientHello {
	return contractv1.ClientHello{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "client_hello",
		DeviceID:        identity.deviceID,
		AuthorizationID: identity.authorizationID,
		TokenID:         identity.tokenID,
		SessionToken:    identity.token,
		ClientNonce:     randomBase64URL(32),
	}
}

func sendClientHello(ctx context.Context, conn *websocket.Conn, identity testIdentity, sequence uint64) error {
	return sendHello(ctx, conn, clientHello(identity), sequence)
}

func sendHello(ctx context.Context, conn *websocket.Conn, hello contractv1.ClientHello, sequence uint64) error {
	payload, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: 0, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, encoded)
}

func readFrameForTest(t *testing.T, ctx context.Context, conn *websocket.Conn) contractv1.Frame {
	t.Helper()
	frame, err := readFrame(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func readFrame(ctx context.Context, conn *websocket.Conn) (contractv1.Frame, error) {
	messageType, data, err := conn.Read(ctx)
	if err != nil {
		return contractv1.Frame{}, err
	}
	if messageType != websocket.MessageBinary {
		return contractv1.Frame{}, errors.New("expected binary websocket message")
	}
	return contractv1.DecodeFrame(data)
}

func newPublicRequest(t *testing.T, rawURL, host string, body io.Reader) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, rawURL, body)
	if body == nil {
		request, err = http.NewRequest(http.MethodGet, rawURL, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	return request
}

func localHTTPClient(rawURL string) *http.Client {
	parsed, _ := url.Parse(rawURL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if parsed.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func writeTestCertificate(t *testing.T) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	dir := t.TempDir()
	certPath = filepath.Join(dir, "gateway.crt")
	keyPath = filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test certificate")
	}
	return certPath, keyPath, roots
}
