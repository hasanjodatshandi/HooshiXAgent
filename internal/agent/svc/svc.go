//go:build windows

// Package svc implements the HooshiX Edge Agent Windows service runtime.
//
// The service runs under LocalSystem and owns the complete Agent lifecycle:
// supervisor reconnect-forever loop, the loopback pairing UI (so pairing
// works before login), and status.json for the tray app. DPAPI secrets are
// therefore created by the service account itself, which keeps the
// current-user protection semantics intact for the service context.
package svc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	mgr "golang.org/x/sys/windows/svc/mgr"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/supervisor"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

// ServiceName is the registered Windows service name. It aliases the shared
// constant so the persistence definition the Agent binary reports through
// `service-spec` and the service this package registers cannot drift apart.
const ServiceName = agent.WindowsServiceName

// Per-operation service access rights. mgr.Mgr.OpenService requests
// windows.SERVICE_ALL_ACCESS for every call, which the install-time DACL
// deliberately does not grant interactive users: a LeastPrivilege tray task
// therefore got ERROR_ACCESS_DENIED from every SCM call and could only ever
// display "status unavailable". Each operation now opens the service with the
// single right it needs.
const (
	serviceQueryAccess = windows.SERVICE_QUERY_STATUS
	serviceStartAccess = windows.SERVICE_START
	serviceStopAccess  = windows.SERVICE_STOP
)

// StateDir is the LocalSystem service state directory. It delegates to the
// shared resolver in package agent so the service and the CLI can never
// disagree about where machine-wide state lives.
func StateDir() string {
	return agent.ServiceStateDir()
}

// PairingListenAddr is the loopback-only pairing UI address.
const PairingListenAddr = "127.0.0.1:8799"

// Runner implements svc.Handler.
type Runner struct{}

// Execute is the SCM entry point.
func (runner *Runner) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	cancel, done, runErr := startAgent()
	if runErr != nil {
		// Initialization failed: exit nonzero so SCM failure recovery
		// (restart on error) can act instead of leaving a "Running"
		// service with no active agent.
		cancel()
		<-done
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	return false, controlLoop(requests, status, cancel, done)
}

// controlLoop services SCM requests until the service is asked to stop or the
// agent goroutine exits on its own. The returned value is the exit code
// reported to SCM, and the two cases differ deliberately:
//
//   - operator-initiated Stop/Shutdown, and a closed request channel, are
//     SUCCESS (0). A non-zero code here is handed to the restart-on-failure
//     policy installed by Install, which restarts the service ~5s later — so
//     "Stop service" from the tray could never actually stop it.
//   - the supervisor terminating on its own is a genuine failure (1) so SCM
//     failure recovery acts instead of showing a hollow Running state.
func controlLoop(requests <-chan svc.ChangeRequest, status chan<- svc.Status, cancel context.CancelFunc, agentDone <-chan struct{}) uint32 {
	for {
		select {
		case request, ok := <-requests:
			if !ok {
				return 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-agentDone
				return 0
			}
		case <-agentDone:
			return 1
		}
	}
}

// startAgent boots the supervisor and the loopback pairing UI.
func startAgent() (context.CancelFunc, <-chan struct{}, error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	stateDir := StateDir()
	// Installers establish the directory DACL first. Create owned state and
	// capability before opening agent.log, which is deliberately not an
	// adoption marker. DPAPI identity creation stays in the service account.
	if err := initializeServiceIdentity(stateDir); err != nil {
		cancel()
		close(done)
		return cancel, done, err
	}
	logger := newServiceLogger(stateDir)

	// Remove any legacy plaintext token record from older installations: the
	// credential must live only in the DPAPI secret store.
	if err := agent.RemoveTokenCopy(stateDir); err != nil {
		logger.Warn("legacy token.txt cleanup failed", "error", err)
	}

	sup, err := supervisor.New(supervisor.Options{StateDir: stateDir, Logger: logger})
	if err != nil {
		logger.Error("supervisor init failed", "error", err)
		cancel()
		close(done)
		return cancel, done, err
	}

	go func() {
		defer close(done)
		go sup.LoopStatusWriter(ctx, 2*time.Second)
		go func() {
			app, appErr := webapp.NewApp(stateDir, logger)
			if appErr != nil {
				logger.Error("pairing ui unavailable", "error", appErr)
				return
			}
			listener, listenErr := app.Listen(PairingListenAddr)
			if listenErr != nil {
				// The fixed port is taken. Either a stale instance or a local
				// process is squatting on it to intercept the pairing
				// capability, so never hand the capability to that address:
				// log loudly and move the real listener to an ephemeral port
				// that is published in pairing.endpoint.json.
				logger.Error("pairing ui fixed port unavailable — the port may be squatted",
					"addr", PairingListenAddr, "error", listenErr)
				listener, listenErr = app.Listen("127.0.0.1:0")
				if listenErr != nil {
					logger.Error("pairing ui unavailable: no loopback port could be bound", "error", listenErr)
					return
				}
				logger.Warn("pairing ui moved to an ephemeral loopback port", "addr", listener.Addr().String())
			}
			if serveErr := app.ServeListener(ctx, listener, logger); serveErr != nil {
				logger.Error("pairing ui stopped", "error", serveErr)
			}
		}()
		if runErr := sup.Run(ctx); runErr != nil {
			logger.Error("supervisor stopped", "error", runErr)
		}
	}()
	return cancel, done, nil
}

func initializeServiceIdentity(stateDir string) error {
	if _, err := agent.EnsurePairingCapability(stateDir); err != nil {
		return fmt.Errorf("initialize service pairing capability: %w", err)
	}
	if _, _, err := agent.LoadOrCreateIdentity(agent.NewPlatformSecretStore(stateDir)); err != nil {
		return fmt.Errorf("initialize service identity: %w", err)
	}
	return nil
}

// agentLogMaxBytes bounds agent.log before rotation. One retained previous
// file keeps recent history while preventing unbounded growth from
// persistent reconnect loops.
const (
	agentLogMaxBytes = 5 * 1024 * 1024
	agentLogMaxFiles = 2
)

// rotatingFile is a size-bounded append writer. When the active file
// reaches maxBytes it is closed, rotated into <name>.1, and reopened.
type rotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	written  int64
}

func newRotatingFile(path string, maxBytes int64) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &rotatingFile{path: path, maxBytes: maxBytes, file: file, written: info.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		// A previous open failed. Retry instead of reporting success forever:
		// the lock that made the open fail (an installer renaming agent.log, a
		// scanner holding it) is transient, and silently swallowing every
		// diagnostic for the rest of the service's life would remove the only
		// record of why.
		if err := r.openLocked(); err != nil {
			return 0, fmt.Errorf("agent log unavailable: %w", err)
		}
	}
	if r.written+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			// Rotation failure must not drop diagnostics: keep appending to
			// whatever file is open. The counter is re-synced to that file's
			// real length rather than zeroed, so the bound stays honest and the
			// next write retries the rotation at once. Growth past the bound is
			// the cost of keeping the diagnostics, and it is only ever temporary
			// — as soon as the rename becomes possible the file is rotated.
			r.syncWrittenLocked()
		}
		if r.file == nil {
			if err := r.openLocked(); err != nil {
				return 0, fmt.Errorf("agent log unavailable: %w", err)
			}
		}
	}
	n, err := r.file.Write(p)
	r.written += int64(n)
	return n, err
}

// openLocked (re)opens the active log file for append and re-syncs the size
// counter to what is actually on disk.
func (r *rotatingFile) openLocked() error {
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		r.file = nil
		return err
	}
	r.file = file
	r.syncWrittenLocked()
	return nil
}

// syncWrittenLocked makes the counter report the active file's real length. A
// counter that lies downwards is what lets the log outrun its bound.
func (r *rotatingFile) syncWrittenLocked() {
	if r.file == nil {
		r.written = 0
		return
	}
	info, err := r.file.Stat()
	if err != nil {
		r.written = 0
		return
	}
	r.written = info.Size()
}

func (r *rotatingFile) rotateLocked() error {
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
	backup := r.path + ".1"
	_ = os.Remove(backup)
	if err := os.Rename(r.path, backup); err != nil {
		// The rename failed: reopen the original so the diagnostics keep
		// flowing, and report the failure so Write re-syncs and retries.
		openErr := r.openLocked()
		if openErr != nil {
			return fmt.Errorf("rotate agent log: %w (and reopening it failed too: %w)", err, openErr)
		}
		return err
	}
	if err := r.openLocked(); err != nil {
		return fmt.Errorf("rotate agent log succeeded but the new active file is unavailable: %w", err)
	}
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	return r.file.Close()
}

// newServiceLogger writes agent diagnostics to a size-bounded agent.log in
// the service state directory (SCM does not capture stdout/stderr). A log that
// cannot be opened does not stop the tunnel, and it is not a permanent loss of
// diagnostics either: the writer is kept with its file closed, so every later
// log line retries the open and a directory that becomes usable mid-upgrade
// starts logging again.
func newServiceLogger(stateDir string) *slog.Logger {
	logger, _ := newServiceLoggerWithWriter(stateDir)
	return logger
}

// newServiceLoggerWithWriter is the same construction with the bounded writer
// kept, for callers that must inspect or close it. The service itself never
// closes it: it holds agent.log for the whole life of the process.
func newServiceLoggerWithWriter(stateDir string) (*slog.Logger, *rotatingFile) {
	path := filepath.Join(stateDir, "agent.log")
	writer, err := newRotatingFile(path, agentLogMaxBytes)
	if err != nil {
		writer = &rotatingFile{path: path, maxBytes: agentLogMaxBytes}
	}
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})), writer
}

// IsWindowsService reports whether the current process is running as a
// Windows service.
func IsWindowsService() bool {
	inService, err := svc.IsWindowsService()
	return err == nil && inService
}

// Install registers the service with SCM, configures auto-start and failure
// recovery, and grants interactive users the limited right to start/stop it
// (so the tray works without elevation). It is idempotent: an existing
// HooshiXAgent service is stopped and recreated with the current binary.
func Install(execPath string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()

	openRegistered := func() error {
		service, err := manager.OpenService(ServiceName)
		if err != nil {
			return err
		}
		service.Close()
		return nil
	}

	if existing, openErr := manager.OpenService(ServiceName); openErr == nil {
		if status, queryErr := existing.Query(); queryErr == nil && status.State != svc.Stopped {
			_, _ = existing.Control(svc.Stop)
			waitStopped(existing)
		}
		if deleteErr := existing.Delete(); deleteErr != nil {
			existing.Close()
			return fmt.Errorf("replace existing service: delete: %w", deleteErr)
		}
		existing.Close()
		// Wait for SCM to actually drop the record before recreating.
		if err := awaitRemoved(openRegistered); err != nil {
			return fmt.Errorf("replace existing service: %w", err)
		}
	}

	service, err := manager.CreateService(ServiceName, execPath, mgr.Config{
		StartType:        mgr.StartAutomatic,
		DisplayName:      "HooshiX Edge Agent",
		Description:      "HooshiX tunnel agent: keeps an always-on reverse tunnel to the HooshiX Gateway.",
		Dependencies:     []string{"Tcpip", "Dnscache"},
		DelayedAutoStart: false,
	}, "service", "run-service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer service.Close()

	if err := applyRecoveryPolicy(service.Handle); err != nil {
		return fmt.Errorf("configure recovery: %w", err)
	}
	if err := grantUserStartStop(service.Handle); err != nil {
		return fmt.Errorf("grant start/stop rights: %w", err)
	}
	return nil
}

// SCM removes a deleted service only once the last handle to it closes, and the
// process that has one is the service itself: an in-place upgrade stops it and
// then races its exit. Budget is how long a replacement waits for that, and
// pause how often it asks. They are vars so a test can watch a whole timeout
// elapse without waiting for one.
var (
	scmRemovalBudget = 10 * time.Second
	scmRemovalPause  = 200 * time.Millisecond
)

// serviceRemoved reports whether an OpenService result means the name is free
// again. Every other error means the opposite: a service marked for deletion
// still fails to open, with ERROR_SERVICE_MARKED_FOR_DELETE, and creating the
// replacement at that moment is refused with the same code. Treating any open
// failure as "gone" is what made an upgrade recreate a service that SCM had not
// finished removing, fail, and roll back onto a registration it had already
// destroyed.
func serviceRemoved(err error) bool {
	return err != nil && errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST)
}

// awaitRemoved polls open until SCM has really dropped the registration or the
// budget runs out, reporting the last state it saw.
func awaitRemoved(open func() error) error {
	deadline := time.Now().Add(scmRemovalBudget)
	for {
		err := open()
		if serviceRemoved(err) {
			return nil
		}
		if !time.Now().Add(scmRemovalPause).Before(deadline) {
			if err == nil {
				return fmt.Errorf("%s is still registered while being replaced — close the process holding it and run setup again", ServiceName)
			}
			return fmt.Errorf("%s is still being removed by SCM: %w — close the process holding it and run setup again", ServiceName, err)
		}
		time.Sleep(scmRemovalPause)
	}
}

// Uninstall stops and removes the service. It is idempotent: a service that is
// not registered (already removed, or never installed on this device) is a
// valid uninstall state, so the packaged uninstaller can report success
// instead of "uninstall incomplete" on a second run.
func Uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()

	status, err := service.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = service.Control(svc.Stop)
		waitStopped(service)
	}
	return service.Delete()
}

// Start starts the registered service. An already-running service is success:
// setup starts the service after `service install`, and SCM reports
// ERROR_SERVICE_ALREADY_RUNNING for a service that is already up.
func Start() error {
	err := withServiceHandle(serviceStartAccess, func(handle windows.Handle) error {
		return windows.StartService(handle, 0, nil)
	})
	if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return nil
	}
	return err
}

// Stop stops the registered service.
func Stop() error {
	return withServiceHandle(serviceStopAccess, func(handle windows.Handle) error {
		var status windows.SERVICE_STATUS
		return windows.ControlService(handle, uint32(svc.Stop), &status)
	})
}

// restartStopTimeout bounds how long Restart waits for a stop-pending service
// to reach stopped. The supervisor shuts down gracefully (flushing its state)
// before SCM reports the transition complete.
const restartStopTimeout = 30 * time.Second

// Restart stops the registered service, waits for SCM to report it stopped,
// and starts it again. A service that is already stopped is started directly,
// and a stop already in progress is waited out rather than reported as a
// failure. It needs only the rights the tray already holds: QUERY_STATUS,
// STOP and START.
func Restart() error {
	state, err := QueryStatus()
	if err != nil {
		return err
	}
	if state != "stopped" {
		if err := Stop(); err != nil &&
			!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) &&
			!errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
			return fmt.Errorf("stop service: %w", err)
		}
		if err := waitForServiceState(QueryStatus, "stopped", restartStopTimeout); err != nil {
			return err
		}
	}
	if err := Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// waitForServiceState polls query until it reports want or timeout elapses,
// returning the last observed state in the timeout error so a stuck stop is
// diagnosable from the tray log.
func waitForServiceState(query func() (string, error), want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		state, err := query()
		if err != nil {
			return err
		}
		if state == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("service did not reach %s within %s (still %s)", want, timeout, state)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// QueryStatus returns the SCM state name for the service.
func QueryStatus() (string, error) {
	var status windows.SERVICE_STATUS_PROCESS
	err := withServiceHandle(serviceQueryAccess, func(handle windows.Handle) error {
		var needed uint32
		return windows.QueryServiceStatusEx(handle, windows.SC_STATUS_PROCESS_INFO,
			(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	})
	if err != nil {
		return "", fmt.Errorf("query service: %w", err)
	}
	switch svc.State(status.CurrentState) {
	case svc.Stopped:
		return "stopped", nil
	case svc.StartPending:
		return "start-pending", nil
	case svc.StopPending:
		return "stop-pending", nil
	case svc.Running:
		return "running", nil
	case svc.ContinuePending:
		return "continue-pending", nil
	case svc.PausePending:
		return "pause-pending", nil
	case svc.Paused:
		return "paused", nil
	default:
		return "unknown", nil
	}
}

// withServiceHandle opens the service with exactly the requested access rights
// and runs fn with the handle, so no caller needs SERVICE_ALL_ACCESS.
func withServiceHandle(access uint32, fn func(windows.Handle) error) error {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, access)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer windows.CloseServiceHandle(service)
	return fn(service)
}

func waitStopped(service *mgr.Service) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil || status.State == svc.Stopped {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
