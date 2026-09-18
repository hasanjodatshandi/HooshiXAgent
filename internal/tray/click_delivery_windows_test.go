//go:build windows

package tray

import (
	"io"
	"log/slog"
	"testing"

	"golang.org/x/sys/windows"
)

// Model the shell's documented NIF_MESSAGE update semantics across every
// modification path, not just the initial NIM_ADD registration.
func TestIconUpdatesPreserveClickCallback(t *testing.T) {
	app := &App{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), settings: newSettingsStore(t.TempDir())}
	host := &menuHost{app: app, iconToken: 1}
	app.menu = host
	previous := currentHost
	currentHost = host
	t.Cleanup(func() { currentHost = previous })
	callback := uint32(wmTrayCallback)
	modifications := 0
	host.notifyIcon = func(op uint32, data *notifyIconData) error {
		if op == nimModify {
			modifications++
			if data.Flags&nifMessage != 0 {
				callback = data.CallbackMessage
			}
			if callback != wmTrayCallback {
				t.Errorf("icon modification flags=%#x disabled click callback: %#x", data.Flags, callback)
			}
		}
		return nil
	}
	host.showBalloon("test", "test", 0)
	setTrayIcon(windows.Handle(1))
	host.refreshMenu(TrayState{})
	if modifications != 3 {
		t.Fatalf("exercised %d modification paths, want 3", modifications)
	}
}

func TestTrayMouseAndKeyboardEventsQueueMenu(t *testing.T) {
	previous := currentHost
	t.Cleanup(func() { currentHost = previous })
	for _, code := range []uint32{ninSelect, ninKeySelect, wmContextMenu, wmLButtonUp, wmRButtonUp} {
		host := &menuHost{app: &App{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
		currentHost = host
		trayWndProc(0, wmTrayCallback, 0, uintptr(code|1<<16))
		if len(host.uiWork) != 1 {
			t.Errorf("event %#x queued %d menu actions", code, len(host.uiWork))
		}
	}
	if ninKeySelect != 0x401 {
		t.Fatal("NIN_KEYSELECT must be NIN_SELECT | NINF_KEY")
	}
	host := &menuHost{app: &App{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	currentHost = host
	trayWndProc(0, wmTrayCallback, 0, uintptr(0x402|1<<16)) // NIN_BALLOONSHOW
	if len(host.uiWork) != 0 {
		t.Fatal("a balloon must not open the menu")
	}
}
