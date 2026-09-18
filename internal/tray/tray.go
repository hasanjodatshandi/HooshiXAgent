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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	agentsvc "github.com/hasanjodatshandi/HooshiXAgent/internal/agent/svc"
	"golang.org/x/sys/windows"
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
	logger   *slog.Logger
	menu     *menuHost
	state    TrayState
	settings *settingsStore

	mu sync.Mutex
}

// currentTrayLogger returns the package logger for helpers outside App.
func currentTrayLogger() *slog.Logger {
	if packageLogger == nil {
		return nil
	}
	return packageLogger
}

// packageLogger is set at startup for non-App helpers (settings store).
var packageLogger *slog.Logger

// Run starts the tray app and blocks until the message loop ends.
func Run() error {
	// The window, its message pump, and every TrackPopupMenu call must run
	// on ONE OS thread: Windows delivers a window's messages to the thread
	// that created it. Without thread pinning the Go scheduler can resume
	// the pump goroutine on a different thread, so the tray window's
	// messages (icon clicks!) are delivered to a thread nobody pumps —
	// the menu then appears only when the scheduler happens to cooperate.
	// This is the root cause of the "menu sometimes never shows" report.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !acquireSingletonLock() {
		// Another tray instance already owns the session tray slot (login
		// task racing a manual launch, or a double start). Silently exit:
		// the existing instance keeps the icon.
		return nil
	}
	logDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "HooshiXAgent")
	logger := newTrayLogger(logDir)
	packageLogger = logger
	app := &App{logger: logger, settings: newSettingsStore(logDir)}

	host, err := newMenuHost(app)
	if err != nil {
		logger.Error("create tray menu failed", "error", err)
		return err
	}
	app.menu = host

	logger.Info("tray started")
	go app.pollLoop()
	defer host.dispose()
	defer releaseSingletonLock()
	err = host.run()
	logger.Info("tray exited")
	return err
}

// trayLogMaxBytes bounds tray.log before rotation (one retained previous
// file) so a long-lived session cannot grow the log without limit.
const trayLogMaxBytes = 1 << 20

func newTrayLogger(logDir string) *slog.Logger {
	fallback := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fallback
	}
	logPath := filepath.Join(logDir, "tray.log")
	info, err := os.Stat(logPath)
	if err == nil && info.Size() >= trayLogMaxBytes {
		_ = os.Remove(logPath + ".1")
		_ = os.Rename(logPath, logPath+".1")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fallback
	}
	return slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// acquireSingletonLock takes a best-effort exclusive lock for this tray
// instance. The lock lives in LOCALAPPDATA (per user, per machine): a second
// tray in the same account exits instead of stacking duplicate icons.
func acquireSingletonLock() bool {
	name, err := windows.UTF16PtrFromString(`Local\HooshiXAgentTray`)
	if err != nil {
		return true
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(handle)
		return false
	}
	if err != nil {
		return true
	}
	singletonMutex = handle
	return true
}

var singletonMutex windows.Handle

func releaseSingletonLock() {
	if singletonMutex == 0 {
		return
	}
	_ = windows.CloseHandle(singletonMutex)
	singletonMutex = 0
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
		// SCM query failed (service removed, transient access failure):
		// surface it in state instead of silently keeping stale data.
		state := TrayState{Phase: "service:unknown", State: "status-unavailable"}
		app.mu.Lock()
		app.state = state
		app.mu.Unlock()
		app.menu.refreshMenu(state)
		return
	}
	state := TrayState{Phase: "service:" + scmState}
	var parsed TrayState
	parsedOK := false
	if status, readErr := os.ReadFile(filepath.Join(agentsvc.StateDir(), "status.json")); readErr == nil {
		if jsonErr := json.Unmarshal(status, &parsed); jsonErr == nil {
			parsedOK = true
		}
	}
	state = mergeAgentStatus(scmState, parsed, parsedOK)
	app.mu.Lock()
	app.state = state
	app.mu.Unlock()
	app.menu.refreshMenu(state)
}

// mergeAgentStatus combines the SCM service state with the agent's own
// status.json snapshot.
//
// The agent phase is adopted only while SCM reports the service running: a
// stopped service leaves its last status.json behind, and a stale phase must
// never be shown as current — "service:stopped" has to win. Before this, the
// agent phase was dropped entirely and only its state name was kept, so the
// menu rendered the internal token of the unpaired agent ("init") instead of
// "not paired yet", and every agent-phase branch in statusDisplayText was
// unreachable.
func mergeAgentStatus(scmState string, parsed TrayState, parsedOK bool) TrayState {
	state := TrayState{Phase: "service:" + scmState}
	if !parsedOK {
		return state
	}
	state.State = parsed.State
	state.Reconnects = parsed.Reconnects
	state.LastError = parsed.LastError
	if scmState == "running" && parsed.Phase != "" {
		state.Phase = parsed.Phase
	}
	return state
}

// Menu actions (invoked from the Win32 menu on the UI thread).

// openPairing opens the loopback pairing page in the default browser.
//
// The pairing capability is a full-control credential for the pairing UI, and
// the loopback port is bindable by ANY local process. The URL is therefore
// built only after the listener has been attributed to the agent service (see
// pairingLaunchPlan), so a port squatter never receives the capability.
func (app *App) openPairing() {
	launchURL, err := pairingLaunchPlan(agentsvc.StateDir())
	if err != nil {
		app.logger.Error("refusing to open the pairing page", "error", err)
		return
	}
	if err := openBrowser(launchURL); err != nil {
		app.logger.Warn("open pairing page failed", "error", err)
	}
}

// pairingLaunchPlan resolves the published pairing endpoint, challenges the
// listener that holds the port, and only then builds the capability URL.
//
// Before this check the tray concatenated "http://127.0.0.1:8799/?cap=<token>"
// unconditionally: any local process that bound that port first (the service
// stopped, a lost boot race) received the capability in the query string, and
// the capability can re-point this device at an attacker-controlled gateway.
func pairingLaunchPlan(stateDir string) (string, error) {
	endpoint, err := agent.LoadPairingEndpoint(stateDir)
	if err != nil {
		return "", err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(endpoint.Port))
	if err := verifyPairingListener(address, endpoint.Token); err != nil {
		return "", fmt.Errorf("the loopback port is not served by the agent service: %w", err)
	}
	capability, err := agent.LoadPairingCapability(stateDir)
	if err != nil {
		return "", fmt.Errorf("read pairing capability: %w", err)
	}
	return "http://" + address + "/?cap=" + url.QueryEscape(capability), nil
}

// pairingVerifyTimeout bounds the identity challenge so a squatted port that
// simply never answers cannot block the tray.
const pairingVerifyTimeout = 3 * time.Second

// verifyPairingListener requests the listener identity and compares it with the
// published token in constant time.
func verifyPairingListener(address, expectedToken string) error {
	client := &http.Client{Timeout: pairingVerifyTimeout}
	response, err := client.Get("http://" + address + "/pairing/identity")
	if err != nil {
		return fmt.Errorf("challenge listener identity: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("listener identity probe status=%d", response.StatusCode)
	}
	var identity struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&identity); err != nil {
		return fmt.Errorf("decode listener identity: %w", err)
	}
	if len(expectedToken) != 43 || len(identity.Token) != len(expectedToken) ||
		subtle.ConstantTimeCompare([]byte(expectedToken), []byte(identity.Token)) != 1 {
		return errors.New("listener identity mismatch")
	}
	return nil
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
