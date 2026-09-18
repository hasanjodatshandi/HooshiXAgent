//go:build windows

package tray

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"golang.org/x/sys/windows"
)

// menuItemIDs returns every command id present in a popup menu.
func menuItemIDs(t *testing.T, menu windows.Handle) []int32 {
	t.Helper()
	getMenuItemCount := user32.NewProc("GetMenuItemCount")
	getMenuItemID := user32.NewProc("GetMenuItemID")
	count, _, _ := getMenuItemCount.Call(uintptr(menu))
	ids := make([]int32, 0, count)
	for position := 0; position < int(count); position++ {
		id, _, _ := getMenuItemID.Call(uintptr(menu), uintptr(position))
		ids = append(ids, int32(id))
	}
	return ids
}

func menuItemCount(t *testing.T, menu windows.Handle) int {
	t.Helper()
	getMenuItemCount := user32.NewProc("GetMenuItemCount")
	count, _, _ := getMenuItemCount.Call(uintptr(menu))
	return int(count)
}

// TestSetNotifyVersionRequestsVersion4 proves the tray asks the shell for the
// NOTIFYICON_VERSION_4 callback layout. That request is what makes the shell
// deliver icon clicks at all: without it the icon is registered and painted
// while every click vanishes, which is exactly the regression that broke the
// owner's tray (visible icon, and tray.log not containing a single
// "tray callback" line despite repeated clicks).
func TestSetNotifyVersionRequestsVersion4(t *testing.T) {
	host := &menuHost{window: windows.Handle(0x1234), iconToken: 7}
	var (
		gotOp   uint32
		gotData notifyIconData
		calls   int
	)
	host.notifyIcon = func(op uint32, data *notifyIconData) error {
		calls++
		gotOp, gotData = op, *data
		return nil
	}
	if err := host.setNotifyVersion(); err != nil {
		t.Fatalf("setNotifyVersion: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one Shell_NotifyIcon call, got %d", calls)
	}
	if gotOp != nimSetVersion {
		t.Fatalf("Shell_NotifyIcon op = %#x, want NIM_SETVERSION (%#x)", gotOp, nimSetVersion)
	}
	if nimSetVersion != 0x04 {
		t.Fatalf("NIM_SETVERSION constant drifted: %#x", nimSetVersion)
	}
	if gotData.VersionOrTimeout != notifyIconVersion4 {
		t.Fatalf("uVersion = %d, want NOTIFYICON_VERSION_4 (%d)", gotData.VersionOrTimeout, notifyIconVersion4)
	}
	if notifyIconVersion4 != 4 {
		t.Fatalf("NOTIFYICON_VERSION_4 drifted: %d", notifyIconVersion4)
	}
	if gotData.Window != host.window || gotData.ID != host.iconToken {
		t.Fatalf("payload addressed window=%v id=%d, want window=%v id=%d",
			gotData.Window, gotData.ID, host.window, host.iconToken)
	}
	if gotData.Size != uint32(unsafe.Sizeof(notifyIconData{})) {
		t.Fatalf("cbSize = %d, want %d", gotData.Size, unsafe.Sizeof(notifyIconData{}))
	}
}

func TestApplyNotifyVersionReportsLegacyFallback(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	host := &menuHost{
		app:       &App{logger: logger},
		window:    windows.Handle(0x4321),
		iconToken: 1,
	}
	app := host.app
	app.menu = host
	app.state = TrayState{Phase: "pending_config", State: "init"}

	host.notifyIcon = func(uint32, *notifyIconData) error {
		return errors.New("Shell_NotifyIcon(4): the operation completed successfully")
	}
	host.applyNotifyVersion()

	if !host.legacyNotifications.Load() {
		t.Fatal("a refused NIM_SETVERSION must record legacy fallback")
	}
	logged := logs.String()
	if !strings.Contains(logged, "level=WARN") {
		t.Fatalf("refusal was not logged at Warn level: %q", logged)
	}
	if !strings.Contains(logged, "NIM_SETVERSION") {
		t.Fatalf("refusal did not name NIM_SETVERSION: %q", logged)
	}
	if !strings.Contains(logged, "Ctrl+Alt+H") {
		t.Fatalf("refusal did not point at the hotkey fallback: %q", logged)
	}
	lines := strings.Join(app.statusTextLines(), "\n")
	if !strings.Contains(lines, "Legacy tray events") {
		t.Fatalf("menu does not report legacy fallback: %q", lines)
	}

	// A later successful (re-)application clears the marker and the menu row.
	host.notifyIcon = func(uint32, *notifyIconData) error { return nil }
	host.applyNotifyVersion()
	if host.legacyNotifications.Load() {
		t.Fatal("a successful NIM_SETVERSION must clear the legacy marker")
	}
	if lines := strings.Join(app.statusTextLines(), "\n"); strings.Contains(lines, "Legacy tray events") {
		t.Fatalf("menu still reports legacy fallback after a successful version call: %q", lines)
	}
}

// TestRegisterIconSetsVersionAfterAdd pins the wiring, not just the helper:
// registration must add the icon and then install the v4 click layout, and a
// failed NIM_ADD must abort before any version call.
func TestRegisterIconSetsVersionAfterAdd(t *testing.T) {
	host := &menuHost{
		app:       &App{logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		window:    windows.Handle(0x99),
		iconToken: 1,
	}
	var ops []uint32
	host.notifyIcon = func(op uint32, data *notifyIconData) error {
		ops = append(ops, op)
		if op == nimSetVersion && data.VersionOrTimeout != notifyIconVersion4 {
			t.Errorf("NIM_SETVERSION carried uVersion=%d, want %d", data.VersionOrTimeout, notifyIconVersion4)
		}
		return nil
	}
	if err := host.registerIcon(); err != nil {
		t.Fatalf("registerIcon: %v", err)
	}
	if len(ops) != 2 || ops[0] != nimAdd || ops[1] != nimSetVersion {
		t.Fatalf("registration ops = %#x, want [NIM_ADD NIM_SETVERSION]", ops)
	}

	// A failed NIM_ADD means there is no icon to version: report the failure
	// and do not call NIM_SETVERSION.
	ops = nil
	host.notifyIcon = func(op uint32, _ *notifyIconData) error {
		ops = append(ops, op)
		if op == nimAdd {
			return errors.New("Shell_NotifyIcon(0): access denied")
		}
		return nil
	}
	if err := host.registerIcon(); err == nil {
		t.Fatal("registerIcon accepted a failed NIM_ADD")
	}
	if len(ops) != 1 || ops[0] != nimAdd {
		t.Fatalf("failed NIM_ADD still attempted further shell calls: %#x", ops)
	}
}

// TestStatusRowsNeverConsumeCommandItems proves the menu-refresh invariant:
// however many status lines a poll produces (statusTextLines returns 1..3
// depending on reconnects and last-error presence), repeated refreshes must
// leave every static command item in place. The pre-fix code deleted a FIXED
// three rows per poll, so within a few rounds the menu contained only disabled
// status rows — no "Open pairing page", no start/stop, no Exit.
func TestStatusRowsNeverConsumeCommandItems(t *testing.T) {
	createPopupMenu := user32.NewProc("CreatePopupMenu")
	menu, _, menuErr := createPopupMenu.Call()
	if menu == 0 {
		t.Fatalf("CreatePopupMenu: %v", menuErr)
	}
	defer user32.NewProc("DestroyMenu").Call(menu) //nolint:errcheck // best-effort cleanup

	// Mirror appendStaticMenuItems: the leading separator plus five commands.
	appendMenu := user32.NewProc("AppendMenuW")
	appendMenu.Call(menu, mfSeparator, 0, uintptr(unsafe.Pointer(menuSepLabel)))
	commands := []uintptr{menuPairing, menuNotifications, menuStart, menuStop, menuExit}
	for _, id := range commands {
		appendMenu.Call(menu, mfString, id, uintptr(unsafe.Pointer(pairingLabel)))
	}
	const staticItems = 6

	// Every status-line count the app can produce, cycled so a refresh always
	// follows a different count than the previous one.
	plans := [][]string{
		{"Tunnel: connected"},
		{"Tunnel: reconnecting", "Reconnects: 4"},
		{"Tunnel: stopped (error)", "Reconnects: 118", "Last error: dial timeout"},
		{"Tunnel: waiting for pairing"},
		{"Tunnel: connected", "Reconnects: 3"},
	}
	rows := 0
	for round := 0; round < 25; round++ {
		lines := plans[round%len(plans)]
		applyStatusRows(windows.Handle(menu), &rows, lines)
		if rows != len(lines) {
			t.Fatalf("round %d: tracked status rows=%d want=%d", round, rows, len(lines))
		}
		if count := menuItemCount(t, windows.Handle(menu)); count != staticItems+len(lines) {
			t.Fatalf("round %d: menu has %d items, want %d", round, count, staticItems+len(lines))
		}
		present := menuItemIDs(t, windows.Handle(menu))
		for _, id := range commands {
			found := false
			for _, got := range present {
				if int32(id) == got {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("round %d: command item %d was deleted by a refresh (menu=%v)", round, id, present)
			}
		}
	}
}

// TestPairingLaunchPlanRefusesSquattedPort proves the tray never hands the
// pairing capability to a listener it cannot attribute to the service. Before
// the fix the tray built "http://127.0.0.1:8799/?cap=<capability>" with no
// check at all, so a local process that bound the port received the capability
// and could re-point the device at its own gateway.
func TestPairingLaunchPlanRefusesSquattedPort(t *testing.T) {
	stateDir := t.TempDir()
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingCapability(stateDir, capability); err != nil {
		t.Fatal(err)
	}

	// No published endpoint record: refuse rather than guess the fixed port.
	if launchURL, err := pairingLaunchPlan(stateDir); err == nil {
		t.Fatalf("launch plan accepted a missing endpoint record: %s", launchURL)
	} else if strings.Contains(err.Error(), capability) {
		t.Fatalf("refusal message leaked the capability: %v", err)
	}

	// A squatter on the published port answers with a token it does not hold.
	squatter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": strings.Repeat("B", 43)})
	}))
	defer squatter.Close()
	squatterPort, err := strconv.Atoi(strings.TrimPrefix(squatter.URL, "http://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingEndpoint(stateDir, agent.PairingEndpoint{
		Port:      squatterPort,
		Token:     strings.Repeat("A", 43),
		PID:       1,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if launchURL, err := pairingLaunchPlan(stateDir); err == nil {
		t.Fatalf("launch plan trusted a squatted port: %s", launchURL)
	} else if strings.Contains(err.Error(), capability) {
		t.Fatalf("refusal message leaked the capability: %v", err)
	}

	// A listener that does hold the published token is trusted: the URL is
	// built with the capability.
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pairing/identity" {
			t.Errorf("unexpected probe path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": strings.Repeat("A", 43)})
	}))
	defer real.Close()
	realPort, err := strconv.Atoi(strings.TrimPrefix(real.URL, "http://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingEndpoint(stateDir, agent.PairingEndpoint{
		Port:      realPort,
		Token:     strings.Repeat("A", 43),
		PID:       1,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	launchURL, err := pairingLaunchPlan(stateDir)
	if err != nil {
		t.Fatalf("launch plan rejected the real listener: %v", err)
	}
	if !strings.HasPrefix(launchURL, "http://127.0.0.1:"+strconv.Itoa(realPort)+"/?cap=") {
		t.Fatalf("launch URL %q is not the verified loopback URL", launchURL)
	}
	if !strings.Contains(launchURL, url.QueryEscape(capability)) {
		t.Fatalf("launch URL %q does not carry the escaped capability", launchURL)
	}
	if strings.Contains(launchURL, "8799") {
		t.Fatalf("launch URL %q ignored the published port", launchURL)
	}
}

// TestVerifyPairingListenerRejectsBadResponses proves the challenge fails
// closed for every non-conforming answer, including a non-answering port.
func TestVerifyPairingListenerRejectsBadResponses(t *testing.T) {
	token := strings.Repeat("A", 43)
	cases := map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"empty body": func(w http.ResponseWriter, r *http.Request) {},
		"missing token": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{}`)
		},
		"short token": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "A"})
		},
	}
	for name, handler := range cases {
		server := httptest.NewServer(handler)
		address := strings.TrimPrefix(server.URL, "http://")
		if err := verifyPairingListener(address, token); err == nil {
			t.Errorf("%s: challenge accepted a non-conforming listener", name)
		}
		server.Close()
	}
	// A listener that never answers must fail within the timeout instead of
	// blocking the tray.
	deadline := time.Now().Add(pairingVerifyTimeout + 5*time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(pairingVerifyTimeout + 2*time.Second)
	}))
	if err := verifyPairingListener(strings.TrimPrefix(server.URL, "http://"), token); err == nil {
		t.Error("challenge accepted a listener that never answered")
	}
	if time.Now().After(deadline) {
		t.Fatal("the challenge did not respect its timeout")
	}
	server.Close()
}

// TestStopFlashIsSafeUnderConcurrentCalls proves the flash channel cannot be
// closed twice. stopFlash is reachable from the 2s poll goroutine and from the
// UI thread (menu action / notification toggle); before the fix both could
// close host.flashStop, panicking the tray process.
func TestStopFlashIsSafeUnderConcurrentCalls(t *testing.T) {
	previousHost := currentHost
	host := &menuHost{app: &App{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	currentHost = host
	defer func() { currentHost = previousHost }()

	for round := 0; round < 20; round++ {
		host.startFlash()
		var waitGroup sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				host.stopFlash()
			}()
		}
		waitGroup.Wait()
		host.flashMu.Lock()
		stopped := host.flashStop == nil
		host.flashMu.Unlock()
		if !stopped {
			t.Fatal("stopFlash left the flash channel in place")
		}
	}
}

// TestApplyStatusRowsTracksInsertedRows pins the bookkeeping the refresh
// invariant depends on: the delete count is the number of rows actually
// inserted, not a fixed three.
func TestApplyStatusRowsTracksInsertedRows(t *testing.T) {
	createPopupMenu := user32.NewProc("CreatePopupMenu")
	menu, _, _ := createPopupMenu.Call()
	if menu == 0 {
		t.Fatal("CreatePopupMenu failed")
	}
	defer user32.NewProc("DestroyMenu").Call(menu) //nolint:errcheck // best-effort cleanup
	rows := 0
	for _, lines := range [][]string{nil, {"one"}, {"one", "two"}, {"one", "two", "three"}, nil} {
		applyStatusRows(windows.Handle(menu), &rows, lines)
		if rows != len(lines) {
			t.Fatalf("rows=%d want=%d", rows, len(lines))
		}
		if count := menuItemCount(t, windows.Handle(menu)); count != len(lines) {
			t.Fatalf("menu has %d items, want %d", count, len(lines))
		}
	}
}
