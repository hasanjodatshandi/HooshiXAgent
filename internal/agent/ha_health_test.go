package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHAHealthTracksRealAuthenticatedPrimary(t *testing.T) {
	dir := t.TempDir()
	publicKey, _, err := LoadOrCreateIdentity(NewPlatformSecretStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSessionToken(NewPlatformSecretStore(dir), mustRandomNonce(t)); err != nil {
		t.Fatal(err)
	}
	stub := &stubGateway{t: t, publicKey: publicKey, firstChallenge: mustRandomNonce(t)}
	server := httptest.NewTLSServer(http.HandlerFunc(stub.serve))
	defer server.Close()
	config := DefaultConfig()
	config.GatewayURL = "wss" + strings.TrimPrefix(server.URL, "https") + "/agent/v1/connect"
	config.GatewayAliases = []string{"wss://127.0.0.1:1/agent/v1/connect"}
	config.DeviceID, config.AuthorizationID, config.TokenID = "device-health", "auth-health", "token-health"
	config.CAFile = writeStubGatewayCA(t, server)
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(dir, DefaultLimits(), quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runner.Run(ctx) }()
	defer func() { cancel(); <-result }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runner.ResumableSessionID() != "" {
			if !runner.HealthyTunnel() {
				t.Fatalf("authenticated HA primary unhealthy: %v", runner.health.Current())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("primary never authenticated")
}
