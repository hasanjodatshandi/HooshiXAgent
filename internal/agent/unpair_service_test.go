package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

// servedAgentState models the Windows service deployment: a process serves the
// loopback pairing endpoint for a state directory (as the LocalSystem service
// does) while the CLI is a separate invocation against that same directory.
type servedAgentState struct {
	stateDir   string
	app        *webapp.App
	capability string
	cancel     context.CancelFunc
	done       chan error
}

func newServedAgentState(t *testing.T) *servedAgentState {
	t.Helper()
	stateDir := t.TempDir()
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingCapability(stateDir, capability); err != nil {
		t.Fatal(err)
	}
	store := agent.NewPlatformSecretStore(stateDir)
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	app, err := webapp.NewApp(stateDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := app.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.ServeListener(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	// Wait for the listener to answer before any command probes it.
	probeServiceIdentity(t, listener.Addr().String())
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("pairing listener did not stop")
		}
	})
	return &servedAgentState{stateDir: stateDir, app: app, capability: capability, cancel: cancel, done: done}
}

func probeServiceIdentity(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pairing listener never accepted a connection: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pairThroughService applies a pairing through the served UI, exactly as an
// operator pasting the panel's pairing text does.
func (state *servedAgentState) pairThroughService(t *testing.T, deviceID string) {
	t.Helper()
	if err := state.app.ApplyPairing(webapp.PairingPayload{
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        deviceID,
		AuthorizationID: "auth-service-000001",
		TokenID:         "token-service-000001",
		Token:           "test_session_token_0123456789ABCDEF",
	}); err != nil {
		t.Fatal(err)
	}
}

func (state *servedAgentState) runUnpair(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := append([]string{"unpair", "--state-dir", state.stateDir, "--json"}, args...)
	if code := agent.Main(command, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("unpair exit=%d stderr=%s", code, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode unpair JSON: %v\n%s", err, stdout.String())
	}
	return result
}

// TestUnpairDelegatesToTheServingAgent proves the coordination half of the
// design: when a process is serving the state directory (the Windows service
// in production), `unpair` is executed BY that process through the same
// authenticated endpoint the pairing UI exposes, because an interactive
// command cannot rewrite a LocalSystem DPAPI secret store.
func TestUnpairDelegatesToTheServingAgent(t *testing.T) {
	state := newServedAgentState(t)
	state.pairThroughService(t, "device-service-000001")
	store := agent.NewPlatformSecretStore(state.stateDir)
	publicKeyBefore, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	result := state.runUnpair(t)
	if result["already_unpaired"] != false {
		t.Fatalf("unpair reported nothing to clear: %#v", result)
	}
	if result["identity_preserved"] != true {
		t.Fatalf("default unpair did not report identity preservation: %#v", result)
	}
	if result["device_id"] != "device-service-000001" {
		t.Fatalf("unpair did not report the cleared device id: %#v", result)
	}
	if result["public_key"] != agent.PublicKeyBase64(publicKeyBefore) {
		t.Fatalf("delegated unpair changed the device identity: %#v", result)
	}

	config, err := agent.LoadConfig(state.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || config.DeviceID != "" || config.AuthorizationID != "" || config.TokenID != "" {
		t.Fatalf("delegated unpair left pairing material behind: %+v", config)
	}
	if err := config.ValidateRuntime(); err == nil {
		t.Fatal("the agent did not return to the unpaired (pending_config) state")
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("delegated unpair left the session token in the secret store")
	}
	publicKeyAfter, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicKeyBefore, publicKeyAfter) {
		t.Fatal("delegated unpair replaced the device identity")
	}
	assertNoTransactionJournal(t, state.stateDir)

	// Idempotent: a second run succeeds and reports that there was nothing to
	// clear.
	second := state.runUnpair(t)
	if second["already_unpaired"] != true {
		t.Fatalf("second delegated unpair did not report an already-unpaired agent: %#v", second)
	}
}

// TestUnpairDelegationReplacesIdentityOnlyWhenAsked proves --reset-identity is
// the only delegated command that mints a new key, and that the new key is
// reported so the operator can register it.
func TestUnpairDelegationReplacesIdentityOnlyWhenAsked(t *testing.T) {
	state := newServedAgentState(t)
	state.pairThroughService(t, "device-service-000002")
	store := agent.NewPlatformSecretStore(state.stateDir)
	publicKeyBefore, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	result := state.runUnpair(t, "--reset-identity")
	if result["identity_preserved"] != false {
		t.Fatalf("--reset-identity did not report a replaced identity: %#v", result)
	}
	publicKeyAfter, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatalf("--reset-identity left no usable identity: %v", err)
	}
	if bytes.Equal(publicKeyBefore, publicKeyAfter) {
		t.Fatal("--reset-identity did not replace the device identity")
	}
	if result["public_key"] != agent.PublicKeyBase64(publicKeyAfter) {
		t.Fatalf("reported public key %v is not the stored identity", result["public_key"])
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("--reset-identity left the session token in the secret store")
	}
}

// TestUnpairIgnoresAStaleEndpointRecord proves the delegation trigger is a
// probe of the live listener, not the mere presence of a file: a published
// endpoint record whose port nobody serves must not be treated as the owner of
// this state, and the command clears the state it actually owns instead.
func TestUnpairIgnoresAStaleEndpointRecord(t *testing.T) {
	stateDir := t.TempDir()
	store := agent.NewPlatformSecretStore(stateDir)
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        "device-stale-000001",
		AuthorizationID: "auth-stale-000001",
		TokenID:         "token-stale-000001",
		UpdateChannel:   "stable",
	}); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetSessionToken(store, "test_session_token_0123456789ABCDEF"); err != nil {
		t.Fatal(err)
	}
	// A record that points at a port nobody serves must not be treated as the
	// owner of this state.
	if err := agent.WritePairingEndpoint(stateDir, agent.PairingEndpoint{
		Port:      1,
		Token:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PID:       os.Getpid(),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := agent.Main([]string{"unpair", "--state-dir", stateDir, "--json"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("unpair exit=%d stderr=%s", code, stderr.String())
	}
	config, err := agent.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || config.DeviceID != "" {
		t.Fatalf("stale endpoint record prevented the local clear: %+v", config)
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("the session token survived the local clear")
	}
}

func assertNoTransactionJournal(t *testing.T, stateDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(stateDir, ".state-transaction")); !os.IsNotExist(err) {
		t.Fatalf("unpair left a state transaction journal behind: %v", err)
	}
}
