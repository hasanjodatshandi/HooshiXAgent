package runtimegate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
)

// The Gateway admits a request body up to MaxRequestBytes and then streams it
// into the tunnel; the Agent has to hold that body while its local target
// drains it. When the two numbers disagreed, a legitimately admitted upload
// died as `resource_limit`/502 as soon as the local target fell behind — which
// is what made the large-request CI leg intermittent. This test wires the real
// Agent runner and the real Gateway handler in-process against a local target
// that is deliberately slow, so the assertion is a capacity property and not a
// scheduling race, and it runs on every platform (the subprocess e2e legs skip
// Windows).

func TestAdmittedRequestBodyFitsTheAgentInputStream(t *testing.T) {
	agentLimits := agent.DefaultLimits()
	gatewayLimits := gateway.DefaultLimits()
	// The sizing that keeps an admitted body bufferable is a relationship
	// between two packages that must never import each other, so it is pinned
	// here rather than asserted on either side alone.
	if agentLimits.MaxSessionQueueBytes < gatewayLimits.MaxRequestBytes {
		t.Fatalf("Agent session input bound %d is below the Gateway admission bound %d: an admitted body cannot be buffered",
			agentLimits.MaxSessionQueueBytes, gatewayLimits.MaxRequestBytes)
	}
}

func TestLargeAdmittedRequestBodySurvivesASlowLocalTarget(t *testing.T) {
	const bodySize = 7<<20 + 123

	// The local service starts reading its body only after a delay, like a busy
	// upload receiver: while it is not draining, every byte the Gateway admitted
	// has to be absorbed by the Agent's per-stream input queue.
	received := make(chan string, 1)
	local := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(400 * time.Millisecond)
		hash := sha256.New()
		if _, err := io.Copy(hash, request.Body); err != nil {
			received <- ""
			return
		}
		received <- fmt.Sprintf("%08x", hash.Sum(nil)[:4])
		_, _ = io.WriteString(writer, "stored")
	}))
	t.Cleanup(local.Close)

	stateDir := t.TempDir()
	store := agent.NewPlatformSecretStore(stateDir)
	publicKey, _, err := agent.LoadOrCreateIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := strings.Repeat("t", 43)
	if err := agent.SetSessionToken(store, sessionToken); err != nil {
		t.Fatal(err)
	}
	metadataDir := t.TempDir()
	writeValidatedMetadata(t, metadataDir, base64.RawURLEncoding.EncodeToString(publicKey), sessionToken, metadataOptions{})
	metadata, err := gateway.LoadSnapshotDirectory(metadataDir)
	if err != nil {
		t.Fatal(err)
	}

	serverGateway, err := gateway.New(metadata, nil, gateway.DefaultLimits(), privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = serverGateway.Close(ctx)
	})
	httpServer := httptest.NewTLSServer(serverGateway.Handler())
	t.Cleanup(httpServer.Close)

	caPath := filepath.Join(stateDir, "gateway-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	wssBase := "wss" + strings.TrimPrefix(httpServer.URL, "https")
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version: agent.ConfigVersion, GatewayURL: wssBase + "/agent/v1/connect", CAFile: caPath,
		DeviceID: "device-runtime-001", AuthorizationID: "auth-runtime-001", TokenID: "token-runtime-001",
		UpdateChannel: "stable",
		Endpoints:     []agent.Endpoint{{ID: "local-http-001", Target: strings.TrimPrefix(local.URL, "http://")}},
	}); err != nil {
		t.Fatal(err)
	}
	runnerLimits := agent.DefaultLimits()
	runnerLimits.ReconnectMin, runnerLimits.ReconnectMax = 20*time.Millisecond, 100*time.Millisecond
	runner, err := agent.NewRunner(stateDir, runnerLimits, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runnerDone := make(chan error, 1)
	go func() { runnerDone <- runner.Run(ctx) }()
	waitFor(t, 5*time.Second, runner.HealthyTunnel)

	payload := bytes.Repeat([]byte("s"), bodySize)
	request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/large-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = e2ePublicHost
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatalf("large admitted request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q: an admitted request body must not be aborted by the Agent input queue",
			response.StatusCode, body)
	}
	if string(body) != "stored" {
		t.Fatalf("body=%q want the local service response", body)
	}
	want := sha256.Sum256(payload)
	select {
	case got := <-received:
		if got != fmt.Sprintf("%08x", want[:4]) {
			t.Fatalf("local target received hash %q want %q", got, fmt.Sprintf("%08x", want[:4]))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the local target never finished reading the admitted request body")
	}
	cancel()
	if err := <-runnerDone; err != nil {
		t.Fatal(err)
	}
}
