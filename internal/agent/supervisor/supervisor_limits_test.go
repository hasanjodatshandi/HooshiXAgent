package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// pairedConfigWithLimits is a runtime-valid configuration carrying a limits
// block, written straight as JSON so a syntactically valid but unusable block
// reaches the supervisor the same way a hand-edited settings file would.
func pairedConfigWithLimits(t *testing.T, stateDir, limits string) {
	t.Helper()
	document := `{
		"version": 1,
		"gateway_url": "wss://gateway.example/agent/v1/connect",
		"device_id": "device-limits-000001",
		"authorization_id": "auth-limits-000001",
		"token_id": "token-limits-000001",
		"update_channel": "stable",
		"limits": ` + limits + `
	}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(document+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSettingsLimitsDriveTheRunner proves the operator-facing promise: editing
// the limits block in the settings file changes how the tunnel runs, through the
// existing config-change reload, without restarting the service.
func TestSettingsLimitsDriveTheRunner(t *testing.T) {
	stateDir := t.TempDir()
	pairedConfigWithLimits(t, stateDir, `{"max_streams": 7, "idle_timeout": "90s", "session_queue_bytes": "16MiB", "reconnect_max": "45s"}`)

	var mu sync.Mutex
	var got agent.Limits
	options := Options{
		StateDir:                stateDir,
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReconnectDelay:          10 * time.Millisecond,
		StateChangePollInterval: 25 * time.Millisecond,
		NewAgentLoop: func(_ string, limits agent.Limits, _ *slog.Logger) (AgentLoop, error) {
			mu.Lock()
			got = limits
			mu.Unlock()
			return &fakeLoop{}, nil
		},
	}
	sup, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got.MaxStreams == 7
	}, "the runner to be built with the settings-file limits")
	mu.Lock()
	applied := got
	mu.Unlock()
	if applied.IdleTimeout != 90*time.Second || applied.MaxSessionQueueBytes != 16<<20 || applied.ReconnectMax != 45*time.Second {
		t.Fatalf("limits from the settings file were not applied: %+v", applied)
	}
	defaults := agent.DefaultLimits()
	if applied.MaxQueueFrames != defaults.MaxQueueFrames || applied.MaxTunnels != defaults.MaxTunnels {
		t.Fatalf("unspecified limits changed: %+v", applied)
	}

	// The supervisor stays alive as long as the loop it built does: this is the
	// service process, not a one-shot run. The running phase is published only
	// after NewAgentLoop returns, so wait for it instead of sleeping a guess.
	waitFor(t, 5*time.Second, func() bool { return statusPhase(stateDir) == "running" },
		"the running phase to be published while the settings-tuned loop serves")

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestUnusableSettingsLimitsWaitForTheOperator proves a mistyped limits block
// cannot put the Agent into a broken state: the runner is never built, the
// reason is published for the tray, and correcting the file resumes the tunnel.
func TestUnusableSettingsLimitsWaitForTheOperator(t *testing.T) {
	stateDir := t.TempDir()
	pairedConfigWithLimits(t, stateDir, `{"max_streams": 100000}`)

	var mu sync.Mutex
	var builds []agent.Limits
	options := Options{
		StateDir:                stateDir,
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReconnectDelay:          10 * time.Millisecond,
		StateChangePollInterval: 25 * time.Millisecond,
		NewAgentLoop: func(_ string, limits agent.Limits, _ *slog.Logger) (AgentLoop, error) {
			mu.Lock()
			builds = append(builds, limits)
			mu.Unlock()
			return &fakeLoop{}, nil
		},
	}
	sup, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		data, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
		if err != nil {
			return false
		}
		var status Status
		if json.Unmarshal(data, &status) != nil {
			return false
		}
		if status.Phase != "pending_config" || !strings.Contains(status.LastError, "limits") {
			return false
		}
		if !strings.Contains(status.LastError, "max_streams") {
			t.Fatalf("status must name the offending field, got %q", status.LastError)
		}
		return true
	}, "the rejected limits block to be reported in status.json")
	mu.Lock()
	if len(builds) != 0 {
		mu.Unlock()
		t.Fatalf("the runner was built %d times despite an unusable limits block", len(builds))
	}
	mu.Unlock()

	// Correct the file until the waiting supervisor notices: it snapshots the
	// config fingerprint when it starts waiting, so the first write can race
	// with that snapshot (same reason the recovery loops in supervisor_test.go
	// rewrite state repeatedly). The budget is wall-clock and this loop is the
	// one place in the package where the product's reaction is observed rather
	// than driven, so it has to survive a `-race` run of the whole suite, where
	// parallel packages starve the supervisor goroutine for seconds: the same
	// test failed at 15.18s against a 15s bound while its own 25ms poll interval
	// says the real reaction time is ~100ms.
	deadline := time.Now().Add(60 * time.Second)
	for {
		pairedConfigWithLimits(t, stateDir, `{"max_streams": 7}`)
		mu.Lock()
		rebuilt := len(builds)
		mu.Unlock()
		if rebuilt > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel loop never started after the limits block was corrected")
		}
		time.Sleep(300 * time.Millisecond)
	}
	mu.Lock()
	applied := builds[0]
	mu.Unlock()
	defaults := agent.DefaultLimits()
	if applied.MaxStreams != 7 || applied.MaxQueueFrames != defaults.MaxQueueFrames ||
		applied.IdleTimeout != defaults.IdleTimeout {
		t.Fatalf("the corrected limits were not applied: %+v", applied)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v after the limits were corrected", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}
