//go:build windows

package svc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/supervisor"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

// RunService is the SCM entry mode: under SCM it services the control
// channel; in a console it runs the same supervisor in the foreground for
// debugging.
func RunService(stateDir string) error {
	if !IsWindowsService() {
		return runSupervisorForeground(resolveServiceStateDir(stateDir))
	}
	return svc.Run(ServiceName, &Runner{})
}

// PairingUI runs the loopback pairing UI in the foreground (diagnostics and
// tray fallback when the service is not installed).
func PairingUI(stateDir string, stdout, stderr io.Writer) error {
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	resolvedStateDir := resolveServiceStateDir(stateDir)
	if _, err := agent.EnsurePairingCapability(resolvedStateDir); err != nil {
		return err
	}
	app, err := webapp.NewApp(resolvedStateDir, logger)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "pairing ui: http://%s\n", PairingListenAddr)
	if inService, svcErr := svc.IsWindowsService(); svcErr == nil && inService {
		return errors.New("pairing-ui already served by the service in service context")
	}
	return app.Serve(signalContext(), PairingListenAddr, logger)
}

func runSupervisorForeground(stateDir string) error {
	sup, err := supervisor.New(supervisor.Options{
		StateDir: stateDir,
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		return err
	}
	ctx := signalContext()
	go sup.LoopStatusWriter(ctx, statusInterval)
	if err := sup.Run(ctx); err != nil {
		return fmt.Errorf("supervisor: %w", err)
	}
	return nil
}

func resolveServiceStateDir(stateDir string) string {
	if stateDir != "" {
		if _, err := agent.NormalizeStateDir(stateDir); err == nil {
			return stateDir
		}
	}
	return StateDir()
}
