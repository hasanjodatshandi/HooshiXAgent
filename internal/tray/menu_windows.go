//go:build windows

package tray

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
) // menuHost owns the hidden window, tray icon, context menu, and message pump.
type menuHost struct {
	app            *App
	instance       uintptr
	window         windows.Handle
	menu           windows.Handle
	iconToken      uint32
	taskbarCreated uint32

	// notifyIcon issues the Shell_NotifyIconW calls that register the icon and
	// set its notification version. It is a field rather than a direct
	// shellProc.Call so a test can prove the NIM_SETVERSION request is really
	// made — and force its failure — without a live taskbar. A nil field falls
	// back to the real shell call.
	notifyIcon func(op uint32, data *notifyIconData) error

	// legacyNotifications records a refused version upgrade. The callback
	// still receives legacy events, which the window procedure also handles.
	legacyNotifications atomic.Bool

	// uiWork serializes menu/window work onto the message-loop thread.
	// TrackPopupMenu must run on the thread that pumps the owner window's
	// messages; calling it from another thread (the wndproc callback runs
	// on the message thread, but prior versions dispatched into goroutines)
	// made the menu fail to appear or vanish instantly.
	uiMu   sync.Mutex
	uiWork []func()

	// balloon persistence: when enabled, a state-change balloon is re-issued
	// on a timer until the user dismisses it or the repeat cap is reached.
	balloonMu      sync.Mutex
	balloonTimer   *time.Timer
	balloonTitle   string
	balloonMessage string
	balloonFlags   uint32
	balloonRounds  int

	// icon flash state (reconnect blink). flashMu guards flashStop so the poll
	// goroutine and the UI thread can both start/stop the blink; closing the
	// same channel twice panicked before.
	flashMu   sync.Mutex
	flashStop chan struct{}

	// statusRows is how many status rows the tray currently has inserted at
	// the top of the context menu. Deleting a FIXED count instead (the old
	// bug) ate the static command items whenever statusTextLines() returned
	// fewer than three lines, until the menu held only disabled status rows.
	statusRows int

	// hotkeyRegistered tracks whether Ctrl+Alt+H is currently owned by this
	// process so it can be released exactly once.
	hotkeyMu         sync.Mutex
	hotkeyRegistered bool
}

// runOnUi queues a closure to execute on the message-loop thread and posts
// the UI-work message so the pump picks it up on the next iteration.
func (host *menuHost) runOnUi(work func()) {
	host.uiMu.Lock()
	host.uiWork = append(host.uiWork, work)
	host.uiMu.Unlock()
	postMessageProc := user32.NewProc("PostMessageW")
	postMessageProc.Call(uintptr(host.window), wmUiWork, 0, 0)
}

// drainUiWork runs every queued closure on the message-loop thread. Called
// from trayWndProc when the UI-work message arrives.
func (host *menuHost) drainUiWork() {
	for {
		host.uiMu.Lock()
		if len(host.uiWork) == 0 {
			host.uiMu.Unlock()
			return
		}
		work := host.uiWork[0]
		host.uiWork = host.uiWork[1:]
		host.uiMu.Unlock()
		work()
	}
}

const (
	wmTrayCallback = 0x8000 // WM_APP
	wmUiWork       = 0x8001 // WM_APP+1: run a queued UI-thread closure
	wmDestroy      = 0x0002
	wmEndSession   = 0x0016
	wmClose        = 0x0010
)

var (
	shell32   = windows.NewLazySystemDLL("shell32.dll")
	user32    = windows.NewLazySystemDLL("user32.dll")
	kernel32  = windows.NewLazySystemDLL("kernel32.dll")
	shellProc = shell32.NewProc("Shell_NotifyIconW")
)

// notifyIconData is NOTIFYICONDATAW as documented by the Windows SDK.
type notifyIconData struct {
	Size             uint32
	Window           windows.Handle
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             windows.Handle
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	VersionOrTimeout uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUIDItem         windows.GUID
	BalloonIcon      windows.Handle
}

const (
	nifMessage  = 0x01
	nifIcon     = 0x02
	nifTip      = 0x04
	nifInfo     = 0x10
	nifRealtime = 0x40
	nimAdd      = 0x00
	nimModify   = 0x01
	nimDelete   = 0x02

	// Select the v4 event layout; legacy mouse notifications remain handled.
	nimSetVersion      = 0x04
	notifyIconVersion4 = 4

	// Hotkey fallback: Ctrl+Alt+H opens the tray menu even when the shell
	// fails to forward icon clicks (seen on Windows 11 insider builds).
	// MOD_CONTROL|MOD_ALT|MOD_NOREPEAT + 'H', delivered as wmHotkey.
	hotkeyID    = 1
	modAlt      = 0x0001
	modControl  = 0x0002
	modNoRepeat = 0x4000
	vkH         = 0x48
	wmHotkey    = 0x0312 // WM_HOTKEY

	// NIIF_* balloon modifiers (partial set actually used).
	niifWarning = 0x00000002
	niifError   = 0x00000003

	// Windows shows a balloon for ~10s then fades it. Re-issuing the same
	// balloon at this interval keeps the notice on screen until the user
	// interacts with it (click, ESC, or it times out after several rounds
	// on builds where Windows caps repeats).
	balloonRepeatInterval = 9 * time.Second
	// balloonMaxRepeats caps a persistent notice so a genuinely unattended
	// session does not pop a balloon forever; 6 rounds ≈ 1 minute.
	balloonMaxRepeats = 6

	// reconnectFlashDuration is how long the icon blinks between the old
	// and new color after a reconnect, so the transition is visible.
	reconnectFlashDuration = 4 * time.Second
	reconnectFlashInterval = 300 * time.Millisecond

	// NOTIFYICON_VERSION_4 notification codes delivered in LOWORD(lParam)
	// of the callback message (uVersion=4 changes the payload layout:
	// wParam packs icon id + x/y, lParam packs notification code + bounds).
	ninSelect           = 0x0400 // left click (v4 replaces WM_LBUTTONDOWN/UP)
	ninKeySelect        = 0x0401 // NIN_SELECT | NINF_KEY; 0x0402 is NIN_BALLOONSHOW
	wmContextMenu       = 0x007B // right click (v4 replaces WM_RBUTTONUP)
	ninBalloonTimeout   = 0x0404
	ninBalloonUserClick = 0x0405
	wmLButtonUp         = 0x0202 // legacy (versions 0-3) raw mouse messages
	wmLButtonDblClk     = 0x0203
	wmRButtonUp         = 0x0205
	wmRButtonDblClk     = 0x0206
)

var (
	className          = syscall.StringToUTF16Ptr("HooshiXAgentTray")
	windowTitle        = syscall.StringToUTF16Ptr("HooshiX Agent Tray")
	pairingLabel       = syscall.StringToUTF16Ptr("Open pairing page")
	notificationsLabel = syscall.StringToUTF16Ptr("Show balloon notifications")
	startLabel         = syscall.StringToUTF16Ptr("Start service")
	stopLabel          = syscall.StringToUTF16Ptr("Stop service")
	exitLabel          = syscall.StringToUTF16Ptr("Exit")
	menuSepLabel       = syscall.StringToUTF16Ptr("-")
)

// wndClassEx mirrors the Win32 WNDCLASSEXW structure exactly.
type wndClassEx struct {
	Size        uint32
	Style       uint32
	WndProc     uintptr
	ClassExtra  int32
	WindowExtra int32
	Instance    uintptr
	Icon        uintptr
	Cursor      uintptr
	Background  uintptr
	MenuName    uintptr
	ClassName   uintptr
	IconSm      uintptr
}

func newMenuHost(app *App) (*menuHost, error) {
	host := &menuHost{app: app}

	instance, _, err := kernel32.NewProc("GetModuleHandleW").Call(0)
	if instance == 0 {
		return nil, fmt.Errorf("GetModuleHandle: %w", err)
	}
	host.instance = uintptr(instance)
	registerWindowMessage := user32.NewProc("RegisterWindowMessageW")
	taskbarCreatedName := syscall.StringToUTF16Ptr("TaskbarCreated")
	taskbarCreated, _, registerErr := registerWindowMessage.Call(uintptr(unsafe.Pointer(taskbarCreatedName)))
	if taskbarCreated == 0 {
		return nil, fmt.Errorf("RegisterWindowMessage(TaskbarCreated): %w", registerErr)
	}
	host.taskbarCreated = uint32(taskbarCreated)

	// Register the window class with our tray callback procedure.
	registerClass := user32.NewProc("RegisterClassExW")
	routine := syscall.NewCallback(trayWndProc)
	currentHost = host
	cursor := uintptr(loadCursor())
	class := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   routine,
		Instance:  host.instance,
		Icon:      uintptr(loadAppIcon(host.instance)),
		Cursor:    cursor,
		IconSm:    uintptr(loadAppIcon(host.instance)),
		ClassName: uintptr(unsafe.Pointer(className)),
	}
	atom, _, classErr := registerClass.Call(uintptr(unsafe.Pointer(&class)))
	if atom == 0 {
		return nil, fmt.Errorf("RegisterClassEx: %w", classErr)
	}

	createWindow := user32.NewProc("CreateWindowExW")
	window, _, createErr := createWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		0, // not visible
		0, 0, 0, 0,
		0, 0,
		uintptr(host.instance),
		0,
	)
	if window == 0 {
		return nil, fmt.Errorf("CreateWindow: %w", createErr)
	}
	host.window = windows.Handle(window)

	// Build the context menu.
	createMenu := user32.NewProc("CreatePopupMenu")
	menu, _, menuErr := createMenu.Call()
	if menu == 0 {
		return nil, fmt.Errorf("CreatePopupMenu: %w", menuErr)
	}
	host.menu = windows.Handle(menu)
	host.rebuildMenu()

	host.iconToken = 1
	host.notifyIcon = shellNotifyIconCall
	// Register the callback, then select its v4 layout. Later modifications
	// must not carry NIF_MESSAGE unless they also supply the same callback.
	if err := host.registerIcon(); err != nil {
		return nil, err
	}
	// Hotkey fallback: Ctrl+Alt+H opens the same menu. Registered on the
	// message-loop thread so WM_HOTKEY arrives on the pump thread, and released
	// in dispose/wmDestroy so the combo is not left stolen system-wide.
	// Failures are logged at Error: this hotkey is the only remaining way to
	// reach the menu when icon-click delivery is broken, so losing it silently
	// would leave the user with a decorative icon.
	registerHotkey := user32.NewProc("RegisterHotKey")
	if ok, _, hkErr := registerHotkey.Call(
		uintptr(host.window), hotkeyID, uintptr(modControl|modAlt|modNoRepeat), uintptr(vkH)); ok == 0 {
		app.logger.Error("register menu hotkey failed: Ctrl+Alt+H cannot open the tray menu", "error", hkErr)
	} else {
		host.hotkeyMu.Lock()
		host.hotkeyRegistered = true
		host.hotkeyMu.Unlock()
		app.logger.Info("menu hotkey registered", "combo", "Ctrl+Alt+H")
	}
	return host, nil
}

// Menu command IDs (fixed, dispatched in dispatchMenu) and MF_* flags.
const (
	mfString          = 0x0000
	mfSeparator       = 0x0800
	mfGrayed          = 0x0002
	mfChecked         = 0x0008
	mfByposition      = 0x400
	mfBycommand       = 0x000 // MF_BYCOMMAND (CheckMenuItem's default lookup mode)
	menuStatus        = 1000
	menuPairing       = 1001
	menuStart         = 1002
	menuStop          = 1003
	menuExit          = 1004
	menuNotifications = 1005
)

var currentHost *menuHost

// rebuildMenu updates the live status rows in place. The static items are
// appended exactly once at startup; only the disabled status header rows
// (which change) are replaced per poll, via DeleteMenu+InsertMenu with fixed
// positions. Rebuilding the WHOLE menu from scratch on every poll was the
// second menu bug: RemoveMenu iterating by position while a TrackPopupMenu
// was opening (right-click) truncated the menu, so later clicks hit a menu
// with zero items and nothing appeared. TrackPopupMenu only ever runs on
// the UI thread and refreshMenu marshals here, so mutation is serialized.
func (host *menuHost) rebuildMenu() {
	appendMenu := user32.NewProc("AppendMenuW")
	getMenuItemCount := user32.NewProc("GetMenuItemCount")

	count, _, _ := getMenuItemCount.Call(uintptr(host.menu))
	if count == 0 {
		host.appendStaticMenuItems(appendMenu)
	}
	applyStatusRows(host.menu, &host.statusRows, host.app.statusTextLines())
	// Keep the notification check mark in step with the persisted preference:
	// the static rows are appended once and never rebuilt, so without this the
	// tick would freeze at its startup value.
	host.applyNotificationCheck()
}

// applyStatusRows replaces the leading status block of menu with lines. It
// removes exactly the rows it inserted last time (rows, updated in place) and
// leaves every static command item untouched, whatever the line count.
func applyStatusRows(menu windows.Handle, rows *int, lines []string) {
	deleteMenu := user32.NewProc("DeleteMenu")
	insertMenu := user32.NewProc("InsertMenuW")
	for index := 0; index < *rows; index++ {
		// Always delete position 0: the status block sits at the top of the
		// menu, so each removal shifts the next row into position 0.
		deleteMenu.Call(uintptr(menu), 0, mfByposition)
	}
	*rows = 0
	for index, line := range lines {
		utf16Line := syscall.StringToUTF16Ptr(line)
		// MF_BYPOSITION is required: without it InsertMenuW interprets
		// uPosition as a COMMAND ID, so the status rows landed next to whatever
		// item happened to carry that id (separators carry id 0) instead of at
		// the top of the menu, and the subsequent positional deletes then ate
		// static command rows.
		insertMenu.Call(uintptr(menu), uintptr(index), uintptr(mfByposition|mfString|mfGrayed), menuStatus, uintptr(unsafe.Pointer(utf16Line)))
	}
	*rows = len(lines)
}

// applyNotificationCheck syncs the notification row's check mark with the
// persisted preference.
func (host *menuHost) applyNotificationCheck() {
	checkMenuItem := user32.NewProc("CheckMenuItem")
	flags := uintptr(mfBycommand)
	if host.app.settings.enabled() {
		flags |= mfChecked
	}
	checkMenuItem.Call(uintptr(host.menu), uintptr(menuNotifications), flags)
}

// appendStaticMenuItems adds the fixed items exactly once: pairing,
// notification toggle, service start/stop, and exit.
func (host *menuHost) appendStaticMenuItems(appendMenu *windows.LazyProc) {
	appendMenu.Call(uintptr(host.menu), mfSeparator, 0, uintptr(unsafe.Pointer(menuSepLabel)))
	appendMenu.Call(uintptr(host.menu), mfString, menuPairing, uintptr(unsafe.Pointer(pairingLabel)))
	// Notification preference: checked when balloons are enabled. The check
	// mark renders by MF_CHECKED; the label never changes so the menu row
	// stays stable for the user.
	notifyFlags := uintptr(mfString)
	if host.app.settings.enabled() {
		notifyFlags |= uintptr(mfChecked)
	}
	appendMenu.Call(uintptr(host.menu), notifyFlags, menuNotifications, uintptr(unsafe.Pointer(notificationsLabel)))
	appendMenu.Call(uintptr(host.menu), mfSeparator, 0, uintptr(unsafe.Pointer(menuSepLabel)))
	appendMenu.Call(uintptr(host.menu), mfString, menuStart, uintptr(unsafe.Pointer(startLabel)))
	appendMenu.Call(uintptr(host.menu), mfString, menuStop, uintptr(unsafe.Pointer(stopLabel)))
	appendMenu.Call(uintptr(host.menu), mfSeparator, 0, uintptr(unsafe.Pointer(menuSepLabel)))
	appendMenu.Call(uintptr(host.menu), mfString, menuExit, uintptr(unsafe.Pointer(exitLabel)))
}

func trayWndProc(window windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
	host := currentHost
	if host == nil {
		return 0
	}
	if message == wmTrayCallback {
		host.app.logger.Debug("tray callback", "code", fmt.Sprintf("0x%04x", uint32(lParam)&0xFFFF))
	}
	if message == host.taskbarCreated {
		// Explorer was restarted (or the taskbar crashed): its tray icon table
		// is empty, so the icon must be re-added. A silent failure here leaves
		// only Explorer's cached NotifyIconSettings snapshot on screen — an
		// icon that shows but swallows every click. Log the outcome so this
		// never happens invisibly again, and retry once before giving up.
		host.app.logger.Info("taskbar recreated; re-adding tray icon")
		var err error
		for attempt := 1; attempt <= 2; attempt++ {
			// registerIcon re-adds the icon AND re-installs the v4 click
			// layout: a freshly registered icon starts on the default
			// (version 0) layout, so without the second half the re-added icon
			// would be click-dead while looking perfectly healthy.
			if err = host.registerIcon(); err == nil {
				break
			}
			host.app.logger.Warn("re-add tray icon failed", "attempt", attempt, "error", err)
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			host.app.logger.Error("tray icon re-add failed after taskbar recreation", "error", err)
		}
		return 0
	}
	switch message {
	case wmUiWork:
		host.drainUiWork()
		return 0
	case wmHotkey:
		if uint32(wParam) == hotkeyID {
			host.app.logger.Info("hotkey menu trigger")
			host.runOnUi(host.showMenu)
		}
		return 0
	case wmTrayCallback:
		// NOTIFYICON_VERSION_4 delivers NOTIFICATION CODES in LOWORD(lParam),
		// not the raw mouse messages of versions 0-3: left-click arrives as
		// NIN_SELECT, keyboard activation as NIN_KEYSELECT, right-click as
		// WM_CONTEXTMENU. Balloon lifecycle arrives as NIN_BALLOONTIMEOUT and
		// NIN_BALLOONUSERCLICK. Matching only the legacy raw messages (e.g.
		// WM_LBUTTONUP) meant real icon clicks were silently dropped and the
		// menu appeared only when a balloon event happened to masquerade as a
		// click. Keyboard selection (0x0401) is distinct from balloon show
		// (0x0402); balloon lifecycle events must never open the menu.
		switch code := uint32(lParam) & 0xFFFF; code {
		case ninSelect, ninKeySelect, wmContextMenu, // version 4 clicks
			wmLButtonUp, wmLButtonDblClk, // legacy clicks (versions 0-3)
			wmRButtonUp, wmRButtonDblClk:
			host.runOnUi(host.showMenu)
		case ninBalloonUserClick: // user dismissed the balloon
			host.stopBalloonRepeat()
		case ninBalloonTimeout: // persistence timer re-issues
		default:
			_ = code
		}
	case wmDestroy:
		host.stopBalloonRepeat()
		host.stopFlash()
		host.unregisterHotkey()
		_ = host.notify(nimDelete)
		postQuitMessage()
		return 0
	case wmClose:
		destroyWindow := user32.NewProc("DestroyWindow")
		destroyWindow.Call(uintptr(window))
		return 0
	case wmEndSession:
		postQuitMessage()
		return 0
	}
	defWindowProc := user32.NewProc("DefWindowProcW")
	result, _, _ := defWindowProc.Call(uintptr(window), uintptr(message), wParam, lParam)
	return result
}

func (host *menuHost) showMenu() {
	const (
		tpmRightAlign  = 0x0008
		tpmBottomAlign = 0x0020
		tpmReturnCmd   = 0x0100
		tpmNonotify    = 0x0080
		tpmLeftBtn     = 0x0000
		wmNull         = 0x0000
	)
	user32Once := user32.NewProc("SetForegroundWindow")
	trackPopupMenu := user32.NewProc("TrackPopupMenu")
	postMessage := user32.NewProc("PostMessageW")
	getCursor := user32.NewProc("GetCursorPos")

	// Standard tray-menu pattern (Microsoft KB135238): make the owner
	// window foreground BEFORE showing the menu so the menu dismisses when
	// the user clicks elsewhere or presses ESC, then post WM_NULL after.
	if _, _, fgErr := user32Once.Call(uintptr(host.window)); fgErr != nil {
		host.app.logger.Debug("set foreground for tray menu failed", "error", fgErr)
	}

	var point struct{ x, y int32 }
	getCursor.Call(uintptr(unsafe.Pointer(&point)))

	chosen, _, trackErr := trackPopupMenu.Call(
		uintptr(host.menu),
		uintptr(tpmRightAlign|tpmBottomAlign|tpmReturnCmd|tpmNonotify|tpmLeftBtn),
		uintptr(int64(point.x)), // x (screen)
		uintptr(int64(point.y)), // y (screen)
		0,
		uintptr(host.window),
		0,
	)
	host.app.logger.Debug("tray menu closed", "chosen", chosen, "trackErr", trackErr)
	postMessage.Call(uintptr(host.window), uintptr(wmNull), 0, 0)
	// Dispatch on the UI thread itself (we are already there — showMenu runs
	// through the wmUiWork queue): the previous "go dispatchMenu" raced the
	// next tray click and could handle the chosen item after the menu was
	// already rebuilt for a newer snapshot.
	host.dispatchMenu(uint32(chosen))
}

func (host *menuHost) dispatchMenu(id uint32) {
	switch id {
	case 1001:
		host.app.openPairing()
	case 1002:
		host.app.serviceStart()
	case 1003:
		host.app.serviceStop()
	case 1004:
		host.app.exit()
	case 1005:
		host.toggleNotifications()
	}
}

// toggleNotifications flips the persisted balloon preference and refreshes
// the menu check mark. Disabling also cancels any pending balloon repeat
// and the reconnect blink so the change applies immediately.
func (host *menuHost) toggleNotifications() {
	newValue := !host.app.settings.enabled()
	host.app.settings.setEnabled(newValue)
	if !newValue {
		host.stopBalloonRepeat()
		host.stopFlash()
	}
	host.app.refresh()
}

func (host *menuHost) run() error {
	getMessage := user32.NewProc("GetMessageW")
	translateMessage := user32.NewProc("TranslateMessage")
	dispatchMessage := user32.NewProc("DispatchMessageW")
	var msg struct {
		Window   windows.Handle
		Message  uint32
		WParam   uintptr
		LParam   uintptr
		Time     uint32
		Point    struct{ x, y int32 }
		LPrivate uint32
	}
	for {
		result, _, err := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			return fmt.Errorf("GetMessage: %w", err)
		}
		if result == 0 {
			return nil
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// shellNotifyIconCall performs one Shell_NotifyIconW call, reporting a FALSE
// return as an error. It is the default implementation behind
// menuHost.notifyIcon.
func shellNotifyIconCall(op uint32, data *notifyIconData) error {
	result, _, err := shellProc.Call(uintptr(op), uintptr(unsafe.Pointer(data)))
	if result == 0 {
		return fmt.Errorf("Shell_NotifyIcon(%d): %w", op, err)
	}
	return nil
}

// shellNotifyIcon routes a Shell_NotifyIconW call through the host's seam,
// falling back to the real shell call when no seam was installed.
func (host *menuHost) shellNotifyIcon(op uint32, data *notifyIconData) error {
	if host.notifyIcon == nil {
		return shellNotifyIconCall(op, data)
	}
	return host.notifyIcon(op, data)
}

// registerIcon adds the icon to the shell and installs the v4 click layout.
// Both halves are mandatory and are always done together: an icon without the
// version call is registered and painted but never receives a click, which is
// indistinguishable from a working icon until the user tries to use it.
func (host *menuHost) registerIcon() error {
	if err := host.notify(nimAdd); err != nil {
		return fmt.Errorf("Shell_NotifyIcon add: %w", err)
	}
	host.applyNotifyVersion()
	return nil
}

// setNotifyVersion requests the NOTIFYICON_VERSION_4 callback layout.
func (host *menuHost) setNotifyVersion() error {
	data := notifyIconData{
		Window:           host.window,
		ID:               host.iconToken,
		VersionOrTimeout: notifyIconVersion4,
	}
	data.Size = uint32(unsafe.Sizeof(data))
	return host.shellNotifyIcon(nimSetVersion, &data)
}

// applyNotifyVersion requests v4 and reports fallback to legacy events.
func (host *menuHost) applyNotifyVersion() {
	if err := host.setNotifyVersion(); err != nil {
		host.legacyNotifications.Store(true)
		host.app.logger.Warn("Shell_NotifyIcon(NIM_SETVERSION) failed; using legacy tray events; Ctrl+Alt+H remains available", "error", err)
		return
	}
	host.legacyNotifications.Store(false)
	host.app.logger.Info("tray notification version configured", "notification_version", notifyIconVersion4)
}

func (host *menuHost) notify(op uint32) error {
	data := notifyIconData{
		Window:          host.window,
		ID:              host.iconToken,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmTrayCallback,
		Icon:            statusIcon(readinessFromState(host.app.currentState())),
	}
	copy(data.Tip[:], syscall.StringToUTF16("HooshiX Agent"))
	data.Size = uint32(unsafe.Sizeof(data))
	return host.shellNotifyIcon(op, &data)
}

func (host *menuHost) dispose() {
	host.unregisterHotkey()
	_ = host.notify(nimDelete)
}

// unregisterHotkey releases the Ctrl+Alt+H fallback hotkey. The system-wide
// hotkey stayed registered after the tray exited before, so the combo remained
// stolen from every other application until logoff.
func (host *menuHost) unregisterHotkey() {
	host.hotkeyMu.Lock()
	defer host.hotkeyMu.Unlock()
	if !host.hotkeyRegistered {
		return
	}
	unregisterHotKey := user32.NewProc("UnregisterHotKey")
	if result, _, err := unregisterHotKey.Call(uintptr(host.window), hotkeyID); result == 0 {
		host.app.logger.Warn("unregister menu hotkey failed", "error", err)
		return
	}
	host.hotkeyRegistered = false
}

func (host *menuHost) quit() {
	postMessage := user32.NewProc("PostMessageW")
	if result, _, err := postMessage.Call(uintptr(host.window), wmClose, 0, 0); result == 0 {
		host.app.logger.Error("request tray shutdown failed", "error", err)
	}
}

// statusTextLines renders the current tunnel health as short tray-menu
// header rows: connection state, reconnect count, and the last error when
// present. Tray menu strings should stay short (no CRLF); long errors are
// truncated so the menu does not become unusable.
func (app *App) statusTextLines() []string {
	app.mu.Lock()
	state := app.state
	app.mu.Unlock()
	lines := []string{"Tunnel: " + statusDisplayText(state)}
	if state.Reconnects > 0 {
		lines = append(lines, fmt.Sprintf("Reconnects: %d", state.Reconnects))
	}
	if errText := strings.TrimSpace(state.LastError); errText != "" {
		const maxLen = 60
		if len(errText) > maxLen {
			errText = errText[:maxLen] + "..."
		}
		lines = append(lines, "Last error: "+errText)
	}
	if app.menu != nil && app.menu.legacyNotifications.Load() {
		lines = append(lines, "Legacy tray events — shortcut: Ctrl+Alt+H")
	}
	return lines
}

// statusDisplayText converts the raw phase/state pair into a compact,
// user-friendly tunnel status string.
//
// Phase is the agent's own phase ("pending_config", "running", "terminal", ...)
// while the service is running, and the service-scoped "service:<scm>" form
// when the service is not running (see mergeAgentStatus). The two must read
// differently: "the service is not running" is an operator problem, while
// "running but not paired yet" is a setup step the owner can complete.
func statusDisplayText(state TrayState) string {
	// Service-scoped phases first: they describe the service itself and must
	// never be shadowed by a tunnel-phase suffix match.
	switch state.Phase {
	case "service:unknown":
		return "service status unavailable"
	case "service:stopped":
		return "service stopped"
	case "exiting":
		return "exiting"
	}
	switch {
	case isUpState(state):
		return "connected"
	case strings.HasSuffix(state.Phase, "pending_config"):
		// The service is running and healthy; the device simply has no
		// pairing yet. It used to render as the bare internal state name
		// ("init"), which read as a failure to the owner.
		return "not paired yet (service running)"
	case strings.HasSuffix(state.Phase, "terminal"):
		return "stopped (error)"
	case strings.HasSuffix(state.Phase, "reconnecting"):
		return "reconnecting"
	case strings.HasSuffix(state.Phase, "recovering"):
		return "recovering"
	case strings.HasSuffix(state.Phase, "running"):
		return agentStateText(state.State)
	default:
		return state.Phase
	}
}

// agentStateText names the agent's tunnel state in operator language. The raw
// tokens ("init", "shutdown", "revoked") are internal; showing them made the
// menu unreadable, and an unrecognised token is passed through unchanged
// rather than hidden.
func agentStateText(state string) string {
	switch state {
	case "":
		return "unknown"
	case "init":
		return "starting"
	case "shutdown":
		return "stopped"
	case "revoked":
		return "revoked by gateway"
	default:
		return state
	}
}

// showBalloon displays a tray balloon notification with the given title,
// message, and NIIF severity icon. Balloons are fire-and-forget: Windows
// decides whether to render them (Focus Assist / policy may suppress), so
// they are an addition to, never a replacement for, the menu status rows.
func (host *menuHost) showBalloon(title, message string, infoFlags uint32) {
	var data notifyIconData
	data.Window = host.window
	data.ID = host.iconToken
	// NIF_MESSAGE would replace the registered callback with this struct's
	// zero value. Only update the balloon; preserve click delivery.
	data.Flags = nifInfo
	data.InfoFlags = infoFlags
	copy(data.InfoTitle[:], syscall.StringToUTF16(title))
	copy(data.Info[:], syscall.StringToUTF16(message))
	data.Size = uint32(unsafe.Sizeof(data))
	if err := host.shellNotifyIcon(nimModify, &data); err != nil {
		host.app.logger.Debug("show tray balloon failed", "error", err)
	}
}

// showPersistentBalloon keeps a balloon on screen until the user dismisses
// it: Windows auto-fades a balloon after ~10 seconds, so while the user has
// not closed it we re-issue the identical balloon on a timer, up to a cap
// (balloonMaxRepeats) so an unattended desktop does not pop forever.
// Dismissal detection: Windows posts NIN_BALLOONUSERCLICK (user clicked) or
// NIN_BALLOONTIMEOUT. The wndproc cancels repeats on user click; on plain
// timeout the timer naturally re-issues.
func (host *menuHost) showPersistentBalloon(title, message string, infoFlags uint32) {
	host.balloonMu.Lock()
	defer host.balloonMu.Unlock()
	// Identical content already cycling: nothing to do.
	if host.balloonTimer != nil && host.balloonTitle == title && host.balloonMessage == message {
		return
	}
	host.stopBalloonRepeatLocked()
	host.balloonTitle = title
	host.balloonMessage = message
	host.balloonFlags = infoFlags
	host.balloonRounds = 1
	host.showBalloon(title, message, infoFlags)
	host.scheduleBalloonRepeatLocked()
}

// scheduleBalloonRepeatLocked arms the re-issue timer. Caller holds balloonMu.
func (host *menuHost) scheduleBalloonRepeatLocked() {
	if host.balloonRounds >= balloonMaxRepeats {
		host.clearBalloonStateLocked()
		return
	}
	title, message, flags := host.balloonTitle, host.balloonMessage, host.balloonFlags
	host.balloonTimer = time.AfterFunc(balloonRepeatInterval, func() {
		host.balloonMu.Lock()
		defer host.balloonMu.Unlock()
		if host.balloonTitle == "" {
			return // dismissed
		}
		host.balloonRounds++
		host.showBalloon(title, message, flags)
		host.scheduleBalloonRepeatLocked()
	})
}

// stopBalloonRepeat cancels any pending balloon re-issue (user dismissed or
// the state changed). Safe to call from any goroutine.
func (host *menuHost) stopBalloonRepeat() {
	host.balloonMu.Lock()
	defer host.balloonMu.Unlock()
	host.stopBalloonRepeatLocked()
}

// stopBalloonRepeatLocked is stopBalloonRepeat with balloonMu held.
func (host *menuHost) stopBalloonRepeatLocked() {
	if host.balloonTimer != nil {
		host.balloonTimer.Stop()
		host.balloonTimer = nil
	}
	host.clearBalloonStateLocked()
}

// clearBalloonStateLocked resets the balloon cycle state. Caller holds balloonMu.
func (host *menuHost) clearBalloonStateLocked() {
	host.balloonTitle = ""
	host.balloonMessage = ""
	host.balloonFlags = 0
	host.balloonRounds = 0
}

// notifyTunnelEvent posts a balloon for a tunnel state transition. Called
// on the poll goroutine via refreshMenu; Shell_NotifyIcon is thread-safe.
func (host *menuHost) notifyTunnelEvent(from, to TrayState) {
	if !host.app.settings.enabled() {
		host.stopBalloonRepeat()
		host.stopFlash()
		return
	}
	// A zero Phase means no previous snapshot (tray just started): treat it
	// as "unknown", which is down — the user must be told the tunnel is
	// not connected at startup instead of only when it later drops. The
	// reconnect case below fires the moment the tunnel first connects,
	// which also proves the notification path works end to end.
	fromKnown := from.Phase != ""
	fromDown := !fromKnown || isDownState(from)
	toDown := isDownState(to)
	fromUp := fromKnown && isUpState(from)
	switch {
	case toDown && fromUp:
		host.showPersistentBalloon("HooshiX tunnel disconnected", disconnectText(to), niifWarning)
	case toDown && fromDown && (!fromKnown || to.Phase != from.Phase):
		// On startup (unknown → down) tell the user why the icon is yellow;
		// afterwards only escalate stopped → terminal, keeping churn between
		// reconnecting/waiting states silent.
		if !fromKnown || strings.HasSuffix(to.Phase, "terminal") {
			host.showPersistentBalloon("HooshiX tunnel not connected", disconnectText(to), niifWarning)
		}
	case fromDown && isUpState(to):
		host.stopBalloonRepeat()
		host.startFlash()
		host.showBalloon("HooshiX tunnel reconnected", "The tunnel is connected again.", 0)
	}
}

// isUpState reports whether the tunnel is (service running +) connected.
func isUpState(state TrayState) bool {
	return strings.HasSuffix(state.Phase, "running") && state.State == "connected"
}

// isDownState reports whether the tunnel is degraded: the supervisor is alive
// but not connected, or the supervisor itself failed. A running+connected
// snapshot is up, not down; so is a snapshot that only says the tray is
// shutting down, and the empty snapshot before the first poll.
//
// Every other phase counts as down, including phases this function used to
// miss. Enumerating suffixes ("running", "reconnecting", "terminal") silently
// classified the agent's "pending_config" — the unpaired state — as NOT down,
// so once the tray started using the agent's real phase the operator would
// have got a yellow icon with no explanation at all.
func isDownState(state TrayState) bool {
	if isUpState(state) {
		return false
	}
	switch state.Phase {
	case "", "exiting":
		return false
	default:
		return true
	}
}

// disconnectText summarizes the reason shown in disconnect balloons.
func disconnectText(state TrayState) string {
	if errText := strings.TrimSpace(state.LastError); errText != "" {
		const maxLen = 180
		if len(errText) > maxLen {
			errText = errText[:maxLen] + "..."
		}
		return errText
	}
	return statusDisplayText(state)
}

// currentState returns the latest status snapshot (thread-safe read).
func (app *App) currentState() TrayState {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.state
}

// startFlash blinks the tray icon between the current and adjacent color
// for reconnectFlashDuration so the transition is visible. The blink cycle
// ends on the target color (the icon settles on the new state color).
func (host *menuHost) startFlash() {
	host.flashMu.Lock()
	defer host.flashMu.Unlock()
	host.stopFlashLocked()
	stop := make(chan struct{})
	host.flashStop = stop
	state := host.app.currentState()
	target := statusIcon(readinessFromState(state))
	// The alternate color is the same-hue dimmed variant: reuse the yellow
	// icon for contrast against green/red endpoints.
	alternate := statusIcon(readinessYellow)
	if readinessFromState(state) == readinessYellow {
		alternate = statusIcon(readinessGreen)
	}
	go func() {
		ticker := time.NewTicker(reconnectFlashInterval)
		defer ticker.Stop()
		deadline := time.After(reconnectFlashDuration)
		showAlternate := true
		for {
			select {
			case <-stop:
				setTrayIcon(target)
				return
			case <-deadline:
				setTrayIcon(target)
				return
			case <-ticker.C:
				if showAlternate {
					setTrayIcon(alternate)
				} else {
					setTrayIcon(target)
				}
				showAlternate = !showAlternate
			}
		}
	}()
}

// stopFlash cancels any running blink and settles the icon on the state color.
// Reachable from both the poll goroutine and the UI thread, so the channel
// swap is guarded: an unguarded double close panicked.
func (host *menuHost) stopFlash() {
	host.flashMu.Lock()
	defer host.flashMu.Unlock()
	host.stopFlashLocked()
}

// stopFlashLocked is stopFlash with flashMu held.
func (host *menuHost) stopFlashLocked() {
	if host.flashStop != nil {
		close(host.flashStop)
		host.flashStop = nil
		setTrayIcon(statusIcon(readinessFromState(host.app.currentState())))
	}
}

// setTrayIcon swaps only the icon portion of the tray entry.
func setTrayIcon(icon windows.Handle) {
	if icon == 0 || currentHost == nil {
		return
	}
	var data notifyIconData
	data.Window = currentHost.window
	data.ID = currentHost.iconToken
	data.Flags = nifIcon
	data.Icon = icon
	data.Size = uint32(unsafe.Sizeof(data))
	_ = currentHost.shellNotifyIcon(nimModify, &data)
}

// refreshMenu applies state to the tray icon, tooltip, and menu so tunnel
// health is visible at a glance and up to date on every poll.
//
// It runs on the 2s poll goroutine AND on the UI thread (after a menu action),
// so every MENU mutation is marshalled onto the message-loop thread: DeleteMenu
// and InsertMenu otherwise race a TrackPopupMenu that is opening on the UI
// thread and can truncate the menu mid-display. app.state and the icon/tooltip
// update stay on the caller because Shell_NotifyIcon is thread-safe.
func (host *menuHost) refreshMenu(state TrayState) {
	host.app.mu.Lock()
	previous := host.app.state
	host.app.state = state
	host.app.mu.Unlock()
	host.notifyTunnelEvent(previous, state)
	host.runOnUi(host.rebuildMenu)
	var tip [128]uint16
	copy(tip[:], syscall.StringToUTF16("HooshiX Agent — "+statusDisplayText(state)))
	data := notifyIconData{
		Window: host.window,
		ID:     host.iconToken,
		Flags:  nifIcon | nifTip,
		Icon:   statusIcon(readinessFromState(state)),
		Tip:    tip,
	}
	data.Size = uint32(unsafe.Sizeof(data))
	if err := host.shellNotifyIcon(nimModify, &data); err != nil {
		// A failing NIM_MODIFY means the icon on screen may be a dead Explorer
		// cache entry: the state color and tooltip silently freeze. Logged at
		// Debug because this runs on every poll tick.
		host.app.logger.Debug("update tray icon failed", "error", err)
	}
}

func loadAppIcon(instance uintptr) windows.Handle {
	loadIcon := user32.NewProc("LoadIconW")
	if icon, _, _ := loadIcon.Call(instance, 1); icon != 0 {
		return windows.Handle(icon)
	}
	icon, _, _ := loadIcon.Call(0, 32512) // IDI_APPLICATION
	return windows.Handle(icon)
}

func loadCursor() windows.Handle {
	loadCursorProc := user32.NewProc("LoadCursorW")
	cursor, _, _ := loadCursorProc.Call(0, 32512) // IDC_ARROW
	return windows.Handle(cursor)
}

func postQuitMessage() {
	postQuit := user32.NewProc("PostQuitMessage")
	postQuit.Call(0)
}
