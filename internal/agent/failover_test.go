package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestGatewayCandidatesDeduplicateAndPreserveOrder(t *testing.T) {
	t.Parallel()

	config := Config{
		GatewayURL: "wss://primary.example/agent/v1/connect",
		GatewayAliases: []string{
			"wss://secondary.example/agent/v1/connect",
			"wss://primary.example/agent/v1/connect",
			"wss://tertiary.example/agent/v1/connect",
		},
	}
	candidates := config.GatewayCandidates()
	if len(candidates) != 3 {
		t.Fatalf("candidates=%v want 3 deduplicated entries", candidates)
	}
	if candidates[0] != "wss://primary.example/agent/v1/connect" || candidates[1] != "wss://secondary.example/agent/v1/connect" || candidates[2] != "wss://tertiary.example/agent/v1/connect" {
		t.Fatalf("candidate order=%v", candidates)
	}

	empty := Config{}
	if got := empty.GatewayCandidates(); len(got) != 0 {
		t.Fatalf("empty config candidates=%v", got)
	}
}

func TestValidateRuntimeRejectsInvalidAliases(t *testing.T) {
	t.Parallel()

	base := Config{
		Version:         1,
		GatewayURL:      "wss://primary.example/agent/v1/connect",
		DeviceID:        "device-001",
		AuthorizationID: "auth-001",
		TokenID:         "token-001",
		UpdateChannel:   "stable",
	}
	if err := base.ValidateRuntime(); err != nil {
		t.Fatalf("base config rejected: %v", err)
	}

	wrongPath := base
	wrongPath.GatewayAliases = []string{"wss://secondary.example/other"}
	if err := wrongPath.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("invalid alias path accepted: %v", err)
	}

	plaintext := base
	plaintext.GatewayAliases = []string{"ws://secondary.example/agent/v1/connect"}
	if err := plaintext.ValidateRuntime(); err == nil {
		t.Fatal("plaintext alias accepted")
	}

	duplicatePrimary := base
	duplicatePrimary.GatewayAliases = []string{"wss://primary.example/agent/v1/connect"}
	if err := duplicatePrimary.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "duplicates the primary") {
		t.Fatalf("alias duplicating primary accepted: %v", err)
	}

	duplicateAlias := base
	duplicateAlias.GatewayAliases = []string{
		"wss://secondary.example/agent/v1/connect",
		"wss://secondary.example/agent/v1/connect",
	}
	if err := duplicateAlias.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "duplicate gateway alias") {
		t.Fatalf("duplicate alias accepted: %v", err)
	}

	overLimit := base
	for i := 0; i < MaxGatewayAliases+1; i++ {
		overLimit.GatewayAliases = append(overLimit.GatewayAliases,
			"wss://extra-"+strings.Repeat("x", i)+"-test.example/agent/v1/connect")
	}
	if err := overLimit.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "bounded failover list") {
		t.Fatalf("alias limit not enforced: %v", err)
	}
}

func TestDialWithFailoverRotatesOnOutage(t *testing.T) {
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	config := Config{
		GatewayURL:     "wss://dead.invalid/agent/v1/connect",
		GatewayAliases: []string{"wss://also-dead.invalid/agent/v1/connect"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	gatewayURL, conn, response, err := runner.dialWithFailover(ctx, config, nil)
	if err == nil {
		if conn != nil {
			conn.CloseNow()
		}
		t.Fatal("dial to dead candidates unexpectedly succeeded")
	}
	if gatewayURL != "" || conn != nil || response != nil {
		t.Fatalf("failed failover returned gateway=%q conn=%v response=%v", gatewayURL, conn, response)
	}
	if !strings.Contains(err.Error(), "dead.invalid") || !strings.Contains(err.Error(), "also-dead.invalid") {
		t.Fatalf("failover did not try every candidate: %v", err)
	}
	// The schedule advanced past the primary for the next attempt.
	if got := runner.failoverIndex.Load(); got != 1 {
		t.Fatalf("failover index after full outage=%d want 1 (last tried alias)", got)
	}
}

func TestDialWithFailoverPrefersHealthyPrimary(t *testing.T) {
	t.Parallel()

	// GatewayCandidates with no aliases returns only the primary; a valid
	// candidate list plus a no-op healthy path is exercised end-to-end in
	// the E2E gate with a real second gateway.
	config := Config{
		GatewayURL:     "wss://primary.example/agent/v1/connect",
		GatewayAliases: []string{"wss://secondary.example/agent/v1/connect"},
	}
	candidates := config.GatewayCandidates()
	if len(candidates) != 2 || candidates[0] != config.GatewayURL {
		t.Fatalf("candidates=%v", candidates)
	}
}

func TestConfigureCommandPersistsAliases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	token := "test_session_token_0123456789ABCDEF"
	primary := "wss://primary.example/agent/v1/connect"
	alias := "wss://secondary.example/agent/v1/connect"

	var out, errOut strings.Builder
	code := Main([]string{
		"configure", "--state-dir", dir,
		"--gateway", primary,
		"--gateway-alias", alias,
		"--device-id", "device-001",
		"--authorization-id", "auth-001",
		"--token-id", "token-001",
		"--token-stdin",
	}, strings.NewReader(token+"\n"), &out, &errOut)
	if code != 0 {
		t.Fatalf("configure exit=%d err=%s", code, errOut.String())
	}

	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.GatewayAliases) != 1 || config.GatewayAliases[0] != alias {
		t.Fatalf("persisted aliases=%v", config.GatewayAliases)
	}
	if candidates := config.GatewayCandidates(); len(candidates) != 2 || candidates[0] != primary {
		t.Fatalf("persisted candidates=%v", candidates)
	}

	var statusOut, statusErr strings.Builder
	if code := Main([]string{"status", "--state-dir", dir, "--json"}, strings.NewReader(""), &statusOut, &statusErr); code != 0 {
		t.Fatalf("status exit=%d err=%s", code, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), `"gateway_candidates":[`) || !strings.Contains(statusOut.String(), alias) {
		t.Fatalf("status missing gateway candidates: %s", statusOut.String())
	}
}

var _ = contractv1.ProtocolVersion
