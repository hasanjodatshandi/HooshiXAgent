//go:build windows

// Package tray implements the HooshiX Agent system-tray application.
//
// It is deliberately dependency-free: the tray icon and menu are driven via
// the Win32 Shell_NotifyIcon API and a hidden window, and all tunnel state
// comes from the service's status.json plus SCM queries. The tray never
// holds credentials: pairing lives in the loopback pairing UI served by the
// service, and start/stop go through SCM (granted to interactive users at
// service install time).
package tray

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentsvc "github.com/hasanjodatshandi/HooshiXAgent/internal/agent/svc"
)

// TrayState mirrors the service status.json snapshot.
type TrayState struct {
	Phase        string `json:"phase"`
	State        string `json:"state"`
	Reconnects   int64  `json:"reconnects"`
	LastError    string `json:"last_error,omitempty"`
	LastUpdateAt string `json:"last_update_at"`
}

// App owns the tray lifecycle.
type App struct {
	logger *slog.Logger
	menu   *menuHost
	state  TrayState

	mu sync.Mutex
}

// Run starts the tray app and blocks until the message loop ends.
func Run() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	app := &App{logger: logger}

	host, err := newMenuHost(app)
	if err != nil {
		return err
	}
	app.menu = host

	go app.pollLoop()
	defer host.dispose()
	return host.run()
}

// pollLoop refreshes SCM state and status.json into the tray state.
func (app *App) pollLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		app.refresh()
	}
}

func (app *App) refresh() {
	scmState, err := agentsvc.QueryStatus()
	if err != nil {
		return
	}
	state := TrayState{Phase: "service:" + scmState}
	if status, readErr := os.ReadFile(filepath.Join(agentsvc.StateDir(), "status.json")); readErr == nil {
		var parsed TrayState
		if jsonErr := json.Unmarshal(status, &parsed); jsonErr == nil {
			state.State = parsed.State
			state.Reconnects = parsed.Reconnects
			state.LastError = parsed.LastError
		}
	}
	app.mu.Lock()
	app.state = state
	app.mu.Unlock()
	app.menu.refreshMenu(state)
}

// Menu actions (invoked from the Win32 menu on the UI thread).

func (app *App) openPairing() {
	if err := openBrowser("http://" + agentsvc.PairingListenAddr); err != nil {
		app.logger.Warn("open pairing page failed", "error", err)
	}
}

func (app *App) serviceStart() {
	if err := agentsvc.Start(); err != nil {
		app.logger.Warn("service start failed", "error", err)
	}
	app.refresh()
}

func (app *App) serviceStop() {
	if err := agentsvc.Stop(); err != nil {
		app.logger.Warn("service stop failed", "error", err)
	}
	app.refresh()
}

func (app *App) exit() {
	app.mu.Lock()
	app.state = TrayState{Phase: "exiting"}
	app.mu.Unlock()
	if app.menu != nil {
		app.menu.quit()
	}
}

var (
	_ = fmt.Sprintf
)


