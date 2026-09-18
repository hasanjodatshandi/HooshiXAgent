//go:build windows

package agent_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// TestUnpairRefusesWithInstructionsWhenTheServiceOwnsStoppedState proves the
// degraded path is explicit. The machine-wide state root belongs to the
// LocalSystem service, whose DPAPI current-user secret store no interactive
// process can read or rewrite, so when that service is not serving, unpair
// must refuse and say exactly what to do rather than half-clear the state.
func TestUnpairRefusesWithInstructionsWhenTheServiceOwnsStoppedState(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	stateDir := filepath.Join(programData, "HooshiXAgent")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        "device-service-owned-000001",
		AuthorizationID: "auth-service-owned-000001",
		TokenID:         "token-service-owned-000001",
		UpdateChannel:   "stable",
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := agent.Main([]string{"unpair", "--state-dir", stateDir}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("unpair exit=%d want=1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "hooshix-agent service start") {
		t.Fatalf("refusal does not tell the operator what to do: %s", stderr.String())
	}
	// Nothing may have been cleared: the service would otherwise start with a
	// half-unpaired state it never agreed to.
	config, err := agent.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL == "" || config.DeviceID == "" {
		t.Fatalf("refused unpair still mutated the service-owned state: %+v", config)
	}
}
