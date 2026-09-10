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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	mgr "golang.org/x/sys/windows/svc/mgr"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/supervisor"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

// ServiceName is the registered Windows service name.
const ServiceName = "HooshiXAgent"

// StateDir is the LocalSystem service state directory.
func StateDir() string {
	if programData := os.Getenv("ProgramData"); programData != "" {
		return filepath.Join(programData, "HooshiXAgent")
	}
	return `C:\ProgramData\HooshiXAgent`
}

// PairingListenAddr is the loopback-only pairing UI address.
const PairingListenAddr = "127.0.0.1:8799"

// Runner implements svc.Handler.
type Runner struct{}

// Execute is the SCM entry point.
func (runner *Runner) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	cancel, done := startAgent()
	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		}
	}
	return false, 0
}

// startAgent boots the supervisor and the loopback pairing UI.
func startAgent() (context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	stateDir := StateDir()
	logger := slog.New(slog.NewTextHandler(nopWriter{}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sup, err := supervisor.New(supervisor.Options{StateDir: stateDir, Logger: logger})
	if err != nil {
		logger.Error("supervisor init failed", "error", err)
		cancel()
		close(done)
		return cancel, done
	}

	go func() {
		defer close(done)
		go sup.LoopStatusWriter(ctx, 2*time.Second)
		go func() {
			app, appErr := webapp.NewApp(stateDir, logger)
			if appErr != nil {
				logger.Warn("pairing ui unavailable", "error", appErr)
				return
			}
			if serveErr := app.Serve(ctx, PairingListenAddr, logger); serveErr != nil {
				logger.Info("pairing ui stopped", "error", serveErr)
			}
		}()
		if runErr := sup.Run(ctx); runErr != nil {
			logger.Error("supervisor stopped", "error", runErr)
		}
	}()
	return cancel, done
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
		// Wait for SCM to fully release the mark before recreating.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, openErr := manager.OpenService(ServiceName); openErr != nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
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

// Uninstall stops and removes the service.
func Uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
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

// Start starts the registered service.
func Start() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	return service.Start()
}

// Stop stops the registered service.
func Stop() error {
	return controlService(svc.Stop)
}

// QueryStatus returns the SCM state name for the service.
func QueryStatus() (string, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return "", fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("query service: %w", err)
	}
	switch status.State {
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

func controlService(control svc.Cmd) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	if _, err := service.Control(control); err != nil {
		return fmt.Errorf("control service: %w", err)
	}
	return nil
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

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

