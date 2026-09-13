//go:build !windows

package svc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/supervisor"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

// ServiceName mirrors the Windows registration for shared status output.
const ServiceName = "HooshiXAgent"

// StateDir falls back to the portable default on non-Windows platforms.
func StateDir() string {
	dir, err := agent.DefaultStateDir()
	if err != nil {
		return "."
	}
	return dir
}

// PairingListenAddr is the loopback pairing UI address.
const PairingListenAddr = "127.0.0.1:8799"

// RunService runs the supervisor in the foreground on non-Windows platforms.
func RunService(stateDir string) error {
	if stateDir == "" {
		stateDir = StateDir()
	}
	sup, err := supervisor.New(supervisor.Options{
		StateDir: stateDir,
		Logger:   slog.New(slog.NewTextHandler(logOutput{}, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		return err
	}
	ctx := signalContext()
	go sup.LoopStatusWriter(ctx, statusInterval)
	return sup.Run(ctx)
}

// PairingUI serves the pairing UI on the loopback listener.
func PairingUI(stateDir string, stdout, stderr io.Writer) error {
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if _, err := agent.EnsurePairingCapability(stateDir); err != nil {
		return err
	}
	app, err := webapp.NewApp(stateDir, logger)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "pairing ui: http://"+PairingListenAddr)
	return app.Serve(signalContext(), PairingListenAddr, logger)
}

// SCM management commands are Windows-only.
func Install(string) error         { return errors.New("service install requires Windows") }
func Uninstall() error             { return errors.New("service uninstall requires Windows") }
func Start() error                 { return errors.New("service start requires Windows") }
func Stop() error                  { return errors.New("service stop requires Windows") }
func QueryStatus() (string, error) { return "", errors.New("service status requires Windows") }
func IsWindowsService() bool       { return false }

type logOutput struct{}

func (logOutput) Write(p []byte) (int, error) { return len(p), nil }
