// Package supervisor implements the always-on Agent lifecycle used by the
// Windows service, the tray app, and headless installs.
//
// It owns the reconnect-forever loop required by the desktop product: while
// the supervisor is running, any non-terminal session failure (network drop,
// gateway restart) is retried with the Runner's bounded backoff. Terminal
// failures (revocation, permanent failure) surface to the caller and stop
// the loop so a human can fix the cause (re-register the device, rotate the
// token) instead of the process spinning on an unfixable error.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// Status is a point-in-time supervisor snapshot for UIs and diagnostics.
type Status struct {
	Phase        string `json:"phase"` // stopped|pending_config|running|terminal
	State        string `json:"state"` // tunnel state name (connecting/connected/...)
	Reconnects   int64  `json:"reconnects"`
	LastError    string `json:"last_error,omitempty"`
	LastUpdateAt string `json:"last_update_at"`
}

// Options configures one supervisor.
type Options struct {
	StateDir  string
	Logger    *slog.Logger
	Limits    agent.Limits
	StatusDir string // where status.json is written; defaults to StateDir
} // Supervisor manages the Agent Runner lifecycle with reconnect-forever
// semantics for recoverable failures.
type Supervisor struct {
	opts Options

	mu      sync.Mutex
	phase   string // stopped|pending_config|running|terminal
	lastErr string

	cancel context.CancelFunc
	done   chan struct{}

	runner *agent.Runner
}

// New creates a supervisor. Call Run to start it.
func New(opts Options) (*Supervisor, error) {
	normalized, err := agent.NormalizeStateDir(opts.StateDir)
	if err != nil {
		return nil, err
	}
	opts.StateDir = normalized
	if opts.StatusDir == "" {
		opts.StatusDir = normalized
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Limits.MaxStreams <= 0 {
		opts.Limits = agent.DefaultLimits()
	}
	return &Supervisor{opts: opts, phase: "stopped"}, nil
}

// Run blocks until ctx is cancelled or a terminal Agent failure happens.
// It never returns for recoverable failures: the internal loop keeps
// restarting the Runner. Run returns nil on graceful stop.
func (sup *Supervisor) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sup.mu.Lock()
	sup.cancel = cancel
	sup.done = make(chan struct{})
	defer close(sup.done)
	sup.mu.Unlock()

	defer sup.setPhase("stopped")

	for {
		config, err := agent.LoadConfig(sup.opts.StateDir)
		if err != nil {
			sup.setTerminal(fmt.Sprintf("read config: %v", err))
			return err
		}
		if err := config.ValidateRuntime(); err != nil {
			// Not a terminal product failure: the user has not finished
			// pairing yet (no gateway/device/token). Wait for configuration
			// to appear instead of spinning on the disk.
			sup.setPhase("pending_config")
			if err := sup.waitForConfigChange(runCtx); err != nil {
				return nil // cancelled
			}
			continue
		}

		runner, err := agent.NewRunner(sup.opts.StateDir, sup.opts.Limits, sup.opts.Logger)
		if err != nil {
			sup.setTerminal(fmt.Sprintf("create runner: %v", err))
			return err
		}
		sup.mu.Lock()
		sup.runner = runner
		sup.mu.Unlock()

		sup.setPhase("running")
		runErr := runner.Run(runCtx)

		sup.mu.Lock()
		sup.runner = nil
		sup.mu.Unlock()

		if runCtx.Err() != nil {
			return nil // graceful stop
		}
		if runErr != nil {
			if errors.Is(runErr, agent.ErrSessionRevoked) {
				sup.setTerminal("session revoked: re-issue the token in the panel and pair again")
				return runErr
			}
			if errors.Is(runErr, agent.ErrPermanentAgentFailure) {
				sup.setTerminal(runErr.Error())
				return runErr
			}
			// Recoverable: network drop, gateway restart, stale metadata.
			sup.setPhase("reconnecting")
			sup.setLastError(runErr.Error())
			if err := sleepCtx(runCtx, 5*time.Second); err != nil {
				return nil
			}
			continue
		}
		return nil
	}
}

// Status returns the current snapshot.
func (sup *Supervisor) Status() Status {
	sup.mu.Lock()
	defer sup.mu.Unlock()
	status := Status{
		Phase:        sup.phase,
		State:        "init",
		LastError:    sup.lastErr,
		LastUpdateAt: time.Now().UTC().Format(time.RFC3339),
	}
	if sup.runner != nil {
		state, terminal := sup.runner.HealthState()
		status.State = state
		status.Reconnects = sup.runner.ReconnectCount()
		if terminal {
			status.Phase = "terminal"
		}
	}
	return status
}

// WriteStatusFile writes the snapshot as status.json under StatusDir.
func (sup *Supervisor) WriteStatusFile() error {
	data, err := jsonMarshal(sup.Status())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sup.opts.StatusDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(sup.opts.StatusDir, "status.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StatusPath returns the status.json location for UIs.
func (sup *Supervisor) StatusPath() string {
	return filepath.Join(sup.opts.StatusDir, "status.json")
}

// LoopStatusWriter periodically persists status.json while ctx is live.
func (sup *Supervisor) LoopStatusWriter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = sup.WriteStatusFile()
		}
	}
}

func (sup *Supervisor) setPhase(phase string) {
	sup.mu.Lock()
	sup.phase = phase
	sup.mu.Unlock()
	_ = sup.WriteStatusFile()
}

func (sup *Supervisor) setTerminal(message string) {
	sup.mu.Lock()
	sup.phase = "terminal"
	sup.lastErr = message
	sup.mu.Unlock()
	_ = sup.WriteStatusFile()
}

func (sup *Supervisor) setLastError(message string) {
	sup.mu.Lock()
	sup.lastErr = message
	sup.mu.Unlock()
}

// waitForConfigChange blocks until the config file changes or ctx is done.
func (sup *Supervisor) waitForConfigChange(ctx context.Context) error {
	path := agent.ConfigPath(sup.opts.StateDir)
	before := fileFingerprint(path)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if fileFingerprint(path) != before {
				return nil
			}
		}
	}
}

func fileFingerprint(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
}

func sleepCtx(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
