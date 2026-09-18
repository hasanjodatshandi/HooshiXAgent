// Package supervisor implements the always-on Agent lifecycle used by the
// Windows service, the tray app, and headless installs.
//
// It owns the reconnect-forever loop required by the desktop product: while
// the supervisor is running, any non-terminal session failure (network drop,
// gateway restart) is retried with a bounded delay.
//
// Terminal failures (revocation, permanent failure) are different. They cannot
// be fixed by retrying, so the supervisor:
//
//  1. records them as phase=terminal together with a redacted reason in
//     status.json, which is how the tray and the pairing UI surface them, and
//  2. waits — for a BOUNDED window, watching the whole state directory so a
//     recovery that rewrites only the secret still wakes it — for an operator
//     to re-pair the device, and
//  3. returns the error to its caller if no recovery arrives, so the service
//     and SCM observe a genuine failure instead of a silent idle loop.
//
// Interrupted state mutations are recovered at startup under the config lock:
// the read path fails closed while a transaction journal exists, and recovery
// is otherwise only reachable from a mutating command, so without this the
// service would dead-loop in SCM restarts with no way to make progress.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// Status is a point-in-time supervisor snapshot for UIs and diagnostics.
type Status struct {
	Phase        string `json:"phase"` // stopped|pending_config|recovering|running|reconnecting|terminal
	State        string `json:"state"` // tunnel state name (connecting/connected/...)
	Reconnects   int64  `json:"reconnects"`
	LastError    string `json:"last_error,omitempty"`
	LastUpdateAt string `json:"last_update_at"`
}

// defaultTerminalRecoveryWait bounds how long a terminal failure waits for an
// operator recovery before the error is returned to the caller. It is long
// enough to re-pair from the tray/UI, and short enough that a genuinely
// unrecoverable install surfaces as a failure rather than idling forever.
const defaultTerminalRecoveryWait = 5 * time.Minute

// stateRecoveryAttempts bounds the retries of an interrupted state mutation.
// A lock held by another live process makes recovery fail transiently, so a
// few attempts are expected; a corrupt journal fails immediately.
const stateRecoveryAttempts = 3

// errRecoveryWindowElapsed reports that the bounded wait for an operator
// recovery expired with no state change.
var errRecoveryWindowElapsed = errors.New("bounded recovery window elapsed")

// AgentLoop is the tunnel-runner contract the supervisor drives. It is the
// *agent.Runner in production; tests supply a fake to exercise the lifecycle
// decisions (classification, recovery, wake-up) without a live gateway.
type AgentLoop interface {
	Run(ctx context.Context) error
	HealthState() (string, bool)
	ReconnectCount() int64
}

// Options configures one supervisor.
type Options struct {
	StateDir  string
	Logger    *slog.Logger
	Limits    agent.Limits
	StatusDir string // where status.json is written; defaults to StateDir

	// TerminalRecoveryWait bounds the wait for an operator recovery after a
	// terminal failure. Zero means defaultTerminalRecoveryWait.
	TerminalRecoveryWait time.Duration

	// ReconnectDelay is the pause before retrying a recoverable failure. Zero
	// means defaultReconnectDelay.
	ReconnectDelay time.Duration

	// NewAgentLoop constructs the runner. Nil means agent.NewRunner.
	NewAgentLoop func(stateDir string, limits agent.Limits, logger *slog.Logger) (AgentLoop, error)
}

// Supervisor manages the Agent Runner lifecycle with reconnect-forever
// semantics for recoverable failures.
type Supervisor struct {
	opts Options

	mu      sync.Mutex
	phase   string // stopped|pending_config|recovering|running|reconnecting|terminal
	lastErr string

	cancel context.CancelFunc
	done   chan struct{}

	runner AgentLoop

	// statusMu serialises status.json writes: setPhase, setTerminal and the
	// independent LoopStatusWriter ticker all write it, and two interleaved
	// writers sharing one temp path either fail their rename or publish a
	// blended file that the tray/webapp read as "status unavailable".
	statusMu       sync.Mutex
	statusFailures int
}

// defaultReconnectDelay is the pause between retries of a recoverable failure.
const defaultReconnectDelay = 5 * time.Second

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
	if opts.TerminalRecoveryWait <= 0 {
		opts.TerminalRecoveryWait = defaultTerminalRecoveryWait
	}
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = defaultReconnectDelay
	}
	if opts.NewAgentLoop == nil {
		opts.NewAgentLoop = func(stateDir string, limits agent.Limits, logger *slog.Logger) (AgentLoop, error) {
			return agent.NewRunner(stateDir, limits, logger)
		}
	}
	return &Supervisor{opts: opts, phase: "stopped"}, nil
}

// Run blocks until ctx is cancelled, a terminal Agent failure survives its
// bounded recovery window, or a terminal state error cannot be recovered.
// Recoverable failures are retried internally. Run returns nil on graceful
// stop.
func (sup *Supervisor) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sup.mu.Lock()
	sup.cancel = cancel
	sup.done = make(chan struct{})
	defer close(sup.done)
	sup.mu.Unlock()

	defer sup.setStoppedUnlessTerminal()

	for {
		config, err := agent.LoadConfig(sup.opts.StateDir)
		if err != nil {
			if errors.Is(err, agent.ErrStateTransactionPending) {
				// An interrupted mutation left its rollback journal behind and
				// the read path fails closed while it exists. Recovery lives
				// behind the config lock, which the supervisor never used to
				// take: roll it back here so startup can make progress.
				if recoverErr := sup.recoverPendingState(runCtx); recoverErr != nil {
					if runCtx.Err() != nil {
						return nil // cancelled
					}
					message := "interrupted state mutation could not be recovered: " +
						agent.SanitizedError(recoverErr) +
						"; run `hooshix-agent init` (or `hooshix-agent configure`) to recover"
					sup.setTerminal(message)
					sup.opts.Logger.Error("supervisor: state recovery failed", "error", agent.SanitizedError(recoverErr))
					return fmt.Errorf("recover interrupted Agent state: %w", recoverErr)
				}
				continue
			}
			sup.setTerminal("read config: " + agent.SanitizedError(err))
			return err
		}
		if err := config.ValidateRuntime(); err != nil {
			// Not a terminal product failure: the user has not finished
			// pairing yet (no gateway/device/token). Wait for configuration
			// to appear instead of spinning on the disk.
			sup.setPhase("pending_config")
			if err := sup.waitForStateChange(runCtx, 0); err != nil {
				return nil // cancelled
			}
			continue
		}

		runner, err := sup.opts.NewAgentLoop(sup.opts.StateDir, sup.opts.Limits, sup.opts.Logger)
		if err != nil {
			sup.setTerminal(fmt.Sprintf("create runner: %v", agent.SanitizedError(err)))
			return err
		}
		sup.mu.Lock()
		sup.runner = runner
		sup.mu.Unlock()

		sup.setPhase("running")
		runErr, stateSuperseded := sup.runAttempt(runCtx, runner)

		sup.mu.Lock()
		sup.runner = nil
		sup.mu.Unlock()

		if runCtx.Err() != nil {
			return nil // graceful stop
		}
		if stateSuperseded {
			sup.opts.Logger.Info("supervisor: agent state changed while running; reloading")
			continue
		}
		if runErr == nil {
			// Normal exit path: the loop returned without an error and without
			// cancellation. Debug, not Warn: this fires on every ordinary
			// shutdown and a warning there is pure noise in agent.log.
			sup.opts.Logger.Debug("supervisor: agent loop ended without an error; exiting")
			return nil
		}
		if errors.Is(runErr, agent.ErrSessionRevoked) || errors.Is(runErr, agent.ErrPermanentAgentFailure) {
			reason := agent.SanitizedError(runErr)
			sup.setTerminal(reason + "; re-pair this device (tray → Open pairing page, or `hooshix-agent configure --token-stdin`) to recover")
			sup.opts.Logger.Error("supervisor: terminal agent failure; waiting for operator recovery",
				"error", reason, "wait", sup.opts.TerminalRecoveryWait.String())
			if err := sup.waitForStateChange(runCtx, sup.opts.TerminalRecoveryWait); err != nil {
				if runCtx.Err() != nil {
					return nil // cancelled
				}
				if errors.Is(err, errRecoveryWindowElapsed) {
					// No operator recovery arrived: surface the failure to the
					// caller so the service/tray can show it and SCM can act.
					return runErr
				}
				return err
			}
			continue
		}
		// Recoverable: network drop, gateway restart, stale metadata.
		sup.setPhase("reconnecting")
		sup.setLastError(agent.SanitizedError(runErr))
		sup.opts.Logger.Warn("supervisor: recoverable error, retrying", "error", agent.SanitizedError(runErr), "retry_in", sup.opts.ReconnectDelay.String())
		if err := sleepCtx(runCtx, sup.opts.ReconnectDelay); err != nil {
			return nil
		}
	}
}

// setStoppedUnlessTerminal records a clean stop on exit, but never erases a
// terminal phase: the tray and the pairing UI read that phase together with the
// recovery hint in last_error to explain why the agent is not running.
func (sup *Supervisor) setStoppedUnlessTerminal() {
	sup.mu.Lock()
	if sup.phase == "terminal" {
		sup.mu.Unlock()
		return
	}
	sup.phase = "stopped"
	sup.mu.Unlock()
	sup.persistStatus()
}

// recoverPendingState rolls back an interrupted state mutation, retrying a few
// times because a lock held by another live process fails transiently.
func (sup *Supervisor) recoverPendingState(ctx context.Context) error {
	sup.setPhase("recovering")
	sup.setLastError("recovering an interrupted state mutation")
	var lastErr error
	for attempt := 1; attempt <= stateRecoveryAttempts; attempt++ {
		lastErr = agent.RecoverState(sup.opts.StateDir)
		if lastErr == nil {
			sup.opts.Logger.Warn("supervisor: recovered an interrupted state mutation", "attempts", attempt)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := sleepCtx(ctx, time.Duration(attempt)*500*time.Millisecond); err != nil {
			return err
		}
	}
	return lastErr
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

// WriteStatusFile writes the snapshot as status.json under StatusDir. Writes
// are serialised and use a uniquely named temp file, so a concurrent caller
// can never observe a partially written or blended status document.
func (sup *Supervisor) WriteStatusFile() error {
	data, err := jsonMarshal(sup.Status())
	if err != nil {
		return err
	}
	sup.statusMu.Lock()
	defer sup.statusMu.Unlock()
	if err := os.MkdirAll(sup.opts.StatusDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(sup.opts.StatusDir, "status.json")
	temp, err := os.CreateTemp(sup.opts.StatusDir, ".status-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

// StatusPath returns the status.json location for UIs.
func (sup *Supervisor) StatusPath() string {
	return filepath.Join(sup.opts.StatusDir, "status.json")
}

// LoopStatusWriter periodically persists status.json while ctx is live. Write
// failures are logged rather than discarded: a silent failure is exactly what
// makes the tray and the pairing UI show "status unavailable" with no cause.
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
			sup.persistStatus()
		}
	}
}

func (sup *Supervisor) setPhase(phase string) {
	sup.mu.Lock()
	sup.phase = phase
	sup.mu.Unlock()
	sup.persistStatus()
}

func (sup *Supervisor) setTerminal(message string) {
	sup.mu.Lock()
	sup.phase = "terminal"
	sup.lastErr = message
	sup.mu.Unlock()
	sup.persistStatus()
}

func (sup *Supervisor) setLastError(message string) {
	sup.mu.Lock()
	sup.lastErr = message
	sup.mu.Unlock()
}

// persistStatus writes status.json and reports failures. The first failure of
// a run is logged at Warn; repeats are demoted to Debug so a persistently
// unwritable status directory cannot flood agent.log every tick.
func (sup *Supervisor) persistStatus() {
	err := sup.WriteStatusFile()
	sup.statusMu.Lock()
	if err == nil {
		sup.statusFailures = 0
		sup.statusMu.Unlock()
		return
	}
	sup.statusFailures++
	first := sup.statusFailures == 1
	sup.statusMu.Unlock()
	if first {
		sup.opts.Logger.Warn("supervisor: write status file failed", "error", err)
		return
	}
	sup.opts.Logger.Debug("supervisor: write status file failed", "error", err, "consecutive_failures", sup.statusFailures)
}

// runAttempt runs one live tunnel-loop attempt until it ends on its own, the
// operator changes the recovery-relevant state, or the supervisor is
// cancelled. It reports the loop's error and whether an operator state change
// superseded the attempt.
//
// Watching the state WHILE the tunnel is live is what keeps the running
// process and the on-disk state from silently disagreeing: an operator
// mutation (configure, rotate, unpair) rewrites config.json, the secret store,
// or both, and a loop that kept serving with the credentials it started with
// would leave the service connected for a device that had just been unpaired.
func (sup *Supervisor) runAttempt(ctx context.Context, runner AgentLoop) (error, bool) {
	stateChanged, stopWatching := sup.watchStateChanges(ctx)
	defer stopWatching()
	attemptCtx, cancelAttempt := context.WithCancel(ctx)
	defer cancelAttempt()
	runResults := make(chan error, 1)
	go func() { runResults <- runner.Run(attemptCtx) }()

	select {
	case err := <-runResults:
		return err, false
	case <-stateChanged:
		cancelAttempt()
		return <-runResults, true
	case <-ctx.Done():
		cancelAttempt()
		<-runResults
		return nil, false
	}
}

// watchStateChanges reports a change of the recovery-relevant Agent state
// (config, platform secret store, or mutation journal) on the returned
// channel, and stops when the returned cancel function is called or ctx is
// done. It is the streaming counterpart of waitForStateChange, used while a
// tunnel loop is live so an operator mutation is picked up without waiting for
// the session to fail.
func (sup *Supervisor) watchStateChanges(ctx context.Context) (<-chan struct{}, context.CancelFunc) {
	watchCtx, cancel := context.WithCancel(ctx)
	changed := make(chan struct{}, 1)
	watched := agent.RecoveryWatchPaths(sup.opts.StateDir)
	before := stateFingerprint(watched)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				if stateFingerprint(watched) != before {
					changed <- struct{}{}
					return
				}
			}
		}
	}()
	return changed, cancel
}

// waitForStateChange blocks until the watched state files change or ctx is
// done. A positive bound additionally returns errRecoveryWindowElapsed when it
// expires with no change.
//
// The watched set covers the WHOLE state (config, secret store, and the
// mutation journal), not just config.json: a recovery that rewrites only the
// secret — `hooshix-agent rotate`, or the rollback of an interrupted mutation
// — must wake the supervisor too. Volatile files are excluded so the
// supervisor's own status ticks do not look like a recovery.
func (sup *Supervisor) waitForStateChange(ctx context.Context, bound time.Duration) error {
	watched := agent.RecoveryWatchPaths(sup.opts.StateDir)
	before := stateFingerprint(watched)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var deadline <-chan time.Time
	if bound > 0 {
		timer := time.NewTimer(bound)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return errRecoveryWindowElapsed
		case <-ticker.C:
			if stateFingerprint(watched) != before {
				return nil
			}
		}
	}
}

// stateFingerprint summarizes the size, modification time and kind of each
// watched path, including paths that are currently absent.
func stateFingerprint(paths []string) string {
	var builder strings.Builder
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(&builder, "%s=absent;", filepath.Base(path))
			continue
		}
		fmt.Fprintf(&builder, "%s=%d:%d:%t;", filepath.Base(path), info.Size(), info.ModTime().UnixNano(), info.IsDir())
	}
	return builder.String()
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
