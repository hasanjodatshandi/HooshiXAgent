package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// fakeLoop is a scripted AgentLoop: each Run call pops the next error from
// results (a nil entry blocks until ctx is cancelled and then returns nil),
// and calls are counted so a test can prove how many attempts were made.
type fakeLoop struct {
	mu       sync.Mutex
	results  []error
	calls    int
	state    string
	terminal bool
}

func (f *fakeLoop) Run(ctx context.Context) error {
	f.mu.Lock()
	index := f.calls
	f.calls++
	var result error
	block := false
	if index < len(f.results) {
		result = f.results[index]
	} else {
		block = true
	}
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil
	}
	return result
}

func (f *fakeLoop) HealthState() (string, bool) { return f.state, f.terminal }

func (f *fakeLoop) ReconnectCount() int64 { return 0 }

func (f *fakeLoop) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// validConfig is a runtime-valid configuration: ValidateRuntime accepts it, so
// the supervisor proceeds to run the tunnel loop.
func validConfig(t *testing.T, stateDir, deviceID string) {
	t.Helper()
	config := agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        deviceID,
		AuthorizationID: "auth-test-000001",
		TokenID:         "token-test-000001",
		UpdateChannel:   "stable",
	}
	if err := agent.SaveConfig(stateDir, config); err != nil {
		t.Fatal(err)
	}
}

func newSupervisor(t *testing.T, stateDir string, loop AgentLoop, mutate func(*Options)) *Supervisor {
	t.Helper()
	options := Options{
		StateDir:             stateDir,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		TerminalRecoveryWait: 10 * time.Second,
		ReconnectDelay:       10 * time.Millisecond,
		NewAgentLoop: func(string, agent.Limits, *slog.Logger) (AgentLoop, error) {
			return loop, nil
		},
	}
	if mutate != nil {
		mutate(&options)
	}
	sup, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// readStatus decodes the status.json the supervisor publishes for the tray.
func readStatus(t *testing.T, stateDir string) Status {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
	if err != nil {
		t.Fatalf("read status.json: %v", err)
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("decode status.json: %v", err)
	}
	return status
}

// statusPhase is readStatus for polling loops: an unreadable file yields "".
func statusPhase(stateDir string) string {
	data, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
	if err != nil {
		return ""
	}
	var status Status
	if json.Unmarshal(data, &status) != nil {
		return ""
	}
	return status.Phase
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, describe string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", describe)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTerminalFailureWaitsForStateRecovery proves a revoked session is
// recorded as a terminal status (so the tray and pairing UI can surface it and
// its recovery hint) and then RESUMES as soon as the operator re-pairs, i.e.
// as soon as the state directory changes.
func TestTerminalFailureWaitsForStateRecovery(t *testing.T) {
	stateDir := t.TempDir()
	validConfig(t, stateDir, "device-before-000001")
	loop := &fakeLoop{results: []error{fmt.Errorf("handshake refused: %w", agent.ErrSessionRevoked)}}
	sup := newSupervisor(t, stateDir, loop, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		return statusPhase(stateDir) == "terminal"
	}, "terminal status publication")
	status := readStatus(t, stateDir)
	if status.LastError == "" {
		t.Fatal("terminal status must carry the failure reason for the tray notice")
	}
	if !containsRecoveryHint(status.LastError) {
		t.Fatalf("terminal status must tell the operator how to recover: %q", status.LastError)
	}

	// Re-pair: rewrite the configuration until the supervisor notices. The
	// writes are repeated because the supervisor snapshots the fingerprint
	// right after publishing the terminal status; every write differs from any
	// snapshot, so one of them is observed.
	go func() {
		for attempt := 0; attempt < 40; attempt++ {
			validConfig(t, stateDir, fmt.Sprintf("device-after-%06d", attempt))
			time.Sleep(400 * time.Millisecond)
		}
	}()
	waitFor(t, 10*time.Second, func() bool { return loop.callCount() >= 2 },
		"the tunnel loop to restart after a state-directory change")

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v after a successful recovery", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestTerminalFailureReturnsErrorAfterBoundedWait proves the recovery wait is
// BOUNDED: with no operator recovery the error reaches the caller instead of
// the supervisor idling forever, and the terminal phase (with its recovery
// hint) survives the exit so the tray still explains the stop.
func TestTerminalFailureReturnsErrorAfterBoundedWait(t *testing.T) {
	stateDir := t.TempDir()
	validConfig(t, stateDir, "device-before-000001")
	loop := &fakeLoop{results: []error{fmt.Errorf("revoked: %w", agent.ErrSessionRevoked)}}
	sup := newSupervisor(t, stateDir, loop, func(options *Options) {
		options.TerminalRecoveryWait = 200 * time.Millisecond
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	select {
	case err := <-runDone:
		if !errors.Is(err, agent.ErrSessionRevoked) {
			t.Fatalf("Run returned %v, want the terminal error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run never returned: the terminal recovery wait is unbounded")
	}
	status := readStatus(t, stateDir)
	if status.Phase != "terminal" {
		t.Fatalf("exit erased the terminal phase: status=%+v", status)
	}
	if !containsRecoveryHint(status.LastError) {
		t.Fatalf("terminal status lost its recovery hint: %q", status.LastError)
	}
}

func containsRecoveryHint(message string) bool {
	for _, hint := range []string{"re-pair", "`hooshix-agent configure"} {
		if len(message) >= len(hint) && stringContains(message, hint) {
			return true
		}
	}
	return false
}

func stringContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestStateChangeWhileRunningReloadsInsteadOfServingStaleCredentials proves a
// live tunnel loop is torn down and the state re-read when the operator
// changes the provisioning state. This is what makes `unpair` safe while the
// service is running: the service clears the pairing (through its own
// authenticated endpoint) and then returns to pending_config instead of
// keeping an authenticated session alive for a device that is no longer
// paired, i.e. instead of the running process and the on-disk state silently
// disagreeing.
func TestStateChangeWhileRunningReloadsInsteadOfServingStaleCredentials(t *testing.T) {
	stateDir := t.TempDir()
	validConfig(t, stateDir, "device-before-000001")
	loop := &fakeLoop{}
	sup := newSupervisor(t, stateDir, loop, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { return statusPhase(stateDir) == "running" }, "the tunnel loop to be running")

	// The operator unpairs the device: the config keeps no pairing fields.
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version:       agent.ConfigVersion,
		UpdateChannel: "stable",
	}); err != nil {
		t.Fatal(err)
	}
	// The live loop is cancelled and the supervisor settles into the unpaired
	// state instead of reporting a failure or exiting.
	waitFor(t, 10*time.Second, func() bool { return statusPhase(stateDir) == "pending_config" },
		"the supervisor to return to pending_config after the state change")
	if status := readStatus(t, stateDir); status.LastError != "" {
		t.Fatalf("an operator state change must not be reported as a failure: %+v", status)
	}

	// Re-pairing brings the tunnel back without a service restart.
	validConfig(t, stateDir, "device-after-000001")
	waitFor(t, 10*time.Second, func() bool { return statusPhase(stateDir) == "running" }, "the tunnel loop to restart after re-pairing")

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v after an operator state change", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestRecoverableFailureRetriesWithoutReturning proves a network-class failure
// never escapes Run: the loop is retried until it succeeds.
func TestRecoverableFailureRetriesWithoutReturning(t *testing.T) {
	stateDir := t.TempDir()
	validConfig(t, stateDir, "device-before-000001")
	loop := &fakeLoop{results: []error{
		errors.New("dial tcp: connection refused"),
		errors.New("gateway restarting"),
		nil,
	}}
	sup := newSupervisor(t, stateDir, loop, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	// The third Run blocks until cancellation, so reaching 3 calls proves the
	// two recoverable failures were retried rather than surfaced.
	waitFor(t, 10*time.Second, func() bool { return loop.callCount() >= 3 }, "the loop to be retried")
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v for recoverable failures", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestPendingStateTransactionIsRecoveredAtStartup proves the supervisor rolls
// back an interrupted mutation at startup. Before the fix the read path failed
// closed with ErrStateTransactionPending and the supervisor returned it
// immediately, so the service dead-looped in SCM restarts: recovery is only
// reachable through the config lock, which the supervisor never took.
func TestPendingStateTransactionIsRecoveredAtStartup(t *testing.T) {
	stateDir := t.TempDir()
	validConfig(t, stateDir, "device-before-000001")
	configData, err := os.ReadFile(agent.ConfigPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(stateDir, ".state-transaction")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "config.before"), configData, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"version":1,"config_exists":true,"secret_exists":false}`
	if err := os.WriteFile(filepath.Join(journal, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	// The read path must fail closed while the journal exists.
	if _, err := agent.LoadConfig(stateDir); !errors.Is(err, agent.ErrStateTransactionPending) {
		t.Fatalf("LoadConfig with a journal present returned %v, want ErrStateTransactionPending", err)
	}

	loop := &fakeLoop{}
	sup := newSupervisor(t, stateDir, loop, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, 10*time.Second, func() bool {
		_, err := os.Stat(journal)
		return errors.Is(err, os.ErrNotExist)
	}, "the interrupted state mutation to be rolled back")

	// Recovery must have let startup proceed into the tunnel loop, not into a
	// terminal stop.
	waitFor(t, 10*time.Second, func() bool { return loop.callCount() >= 1 }, "the tunnel loop to start")
	if status := readStatus(t, stateDir); status.Phase == "terminal" {
		t.Fatalf("recovered startup reported terminal: %+v", status)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned %v after recovering state", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestWaitForStateChangeWakesOnSecretOnlyChange proves the wake-up watches the
// WHOLE state directory. `hooshix-agent rotate` (and a journal rollback) write
// only the secret store; a config.json-only fingerprint never wakes for them,
// which stranded the supervisor waiting forever.
func TestWaitForStateChangeWakesOnSecretOnlyChange(t *testing.T) {
	stateDir := t.TempDir()
	sup := newSupervisor(t, stateDir, &fakeLoop{}, nil)
	store := agent.NewPlatformSecretStore(stateDir)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := store.Save(agent.SecretState{SessionToken: "rotated_session_token_0123456789ABCDEF"}); err != nil {
			t.Errorf("save secret: %v", err)
		}
	}()
	if err := sup.waitForStateChange(ctx, 12*time.Second); err != nil {
		t.Fatalf("waitForStateChange did not wake on a secret-only change: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the wait was cancelled before it observed the change")
	}
}

// TestWaitForStateChangeIgnoresStatusWrites proves the supervisor's own status
// ticks never look like an operator recovery. If they did, the bounded wait
// after a terminal failure would return immediately and spin.
func TestWaitForStateChangeIgnoresStatusWrites(t *testing.T) {
	stateDir := t.TempDir()
	sup := newSupervisor(t, stateDir, &fakeLoop{}, nil)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				_ = sup.WriteStatusFile()
			}
		}
	}()
	err := sup.waitForStateChange(context.Background(), 1200*time.Millisecond)
	if !errors.Is(err, errRecoveryWindowElapsed) {
		t.Fatalf("status writes were treated as a recovery: %v", err)
	}
}

// TestWriteStatusFileIsSerialisedAndAtomic proves concurrent writers — the
// poll-driven setPhase/setTerminal calls and the independent status ticker —
// all succeed and never publish a blended document or leave temp files behind.
// Before the fix every writer shared one "<path>.tmp" name, so the loser's
// rename failed (and was discarded) and the published file could mix writes,
// which the tray/webapp then read as "status unavailable".
func TestWriteStatusFileIsSerialisedAndAtomic(t *testing.T) {
	stateDir := t.TempDir()
	sup := newSupervisor(t, stateDir, &fakeLoop{}, nil)

	const writers = 16
	const rounds = 25
	var failures atomic.Int64
	var waitGroup sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		waitGroup.Add(1)
		go func(writer int) {
			defer waitGroup.Done()
			for round := 0; round < rounds; round++ {
				sup.setLastError(fmt.Sprintf("writer %d round %d", writer, round))
				if err := sup.WriteStatusFile(); err != nil {
					failures.Add(1)
					t.Errorf("concurrent WriteStatusFile: %v", err)
				}
			}
		}(writer)
	}
	waitGroup.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent status writes failed", failures.Load())
	}
	// The published document must be complete valid JSON.
	status := readStatus(t, stateDir)
	if status.LastUpdateAt == "" {
		t.Fatalf("published status is incomplete: %+v", status)
	}
	// No temp files may be left behind by the losers.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); name != "status.json" && len(name) >= 8 && name[:8] == ".status-" {
			t.Fatalf("status writer left a temp file behind: %s", name)
		}
	}
}

// TestPersistStatusLogsFirstFailure proves a status write failure is reported
// rather than discarded: a silently failing writer is what makes the tray and
// the pairing UI show "status unavailable" with no cause anywhere.
func TestPersistStatusLogsFirstFailure(t *testing.T) {
	stateDir := t.TempDir()
	var logs logBuffer
	sup := newSupervisor(t, stateDir, &fakeLoop{}, func(options *Options) {
		options.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		options.StatusDir = filepath.Join(stateDir, "missing", "status")
	})
	// Occupy the status path with a directory so the rename must fail.
	if err := os.MkdirAll(filepath.Join(sup.opts.StatusDir, "status.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	sup.persistStatus()
	if !logs.contains("write status file failed") {
		t.Fatalf("status write failure was swallowed; logs: %s", logs.String())
	}
}

type logBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (buffer *logBuffer) Write(p []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.data = append(buffer.data, p...)
	return len(p), nil
}

func (buffer *logBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return string(buffer.data)
}

func (buffer *logBuffer) contains(substring string) bool {
	return stringContains(buffer.String(), substring)
}
