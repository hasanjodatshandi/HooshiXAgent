//go:build windows

package tray

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// menuHost owns the hidden window, tray icon, context menu, and message pump.
type menuHost struct {
	app            *App
	instance       uintptr
	window         windows.Handle
	menu           windows.Handle
	iconToken      uint32
	taskbarCreated uint32

	// balloon persistence: when enabled, a state-change balloon is re-issued
	// on a timer until the user dismisses it or the repeat cap is reached.
	balloonMu      sync.Mutex
	balloonTimer   *time.Timer
	balloonTitle   string
	balloonMessage string
	balloonFlags   uint32
	balloonRounds  int

	// icon flash state (reconnect blink).
	flashStop chan struct{}
}

const (
	wmTrayCallback = 0x8000 // WM_APP
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
	nifMessage         = 0x01
	nifIcon            = 0x02
	nifTip             = 0x04
	nifInfo            = 0x10
	nifRealtime        = 0x40
	nimAdd             = 0x00
	nimModify          = 0x01
	nimDelete          = 0x02
	nimSetVersion      = 0x04
	notifyIconVersion4 = 4

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
	if err := host.notify(nimAdd); err != nil {
		return nil, fmt.Errorf("Shell_NotifyIcon add: %w", err)
	}
	if err := host.setNotifyVersion(); err != nil {
		app.logger.Warn("set tray notification version failed", "error", err)
	}
	return host, nil
}

var currentHost *menuHost

func (host *menuHost) rebuildMenu() {
	removeMenu := user32.NewProc("RemoveMenu")
	for {
		result, _, _ := removeMenu.Call(uintptr(host.menu), 0, 0x400) // MF_BYPOSITION
		if result == 0 {
			break
		}
	}
	appendMenu := user32.NewProc("AppendMenuW")
	const mfString = 0x0000
	const mfSeparator = 0x0800
	const mfGrayed = 0x0002
	const mfChecked = 0x0008
	const menuStatus = 1000
	const menuPairing = 1001
	const menuStart = 1002
	const menuStop = 1003
	const menuExit = 1004
	const menuNotifications = 1005

	// Disabled header rows surface the live tunnel health (connection
	// state, reconnect count, and last error) without opening a window.
	for _, line := range host.app.statusTextLines() {
		utf16Line := syscall.StringToUTF16Ptr(line)
		appendMenu.Call(uintptr(host.menu), mfString|mfGrayed, menuStatus, uintptr(unsafe.Pointer(utf16Line)))
	}
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
	if message == host.taskbarCreated {
		_ = host.notify(nimAdd)
		_ = host.setNotifyVersion()
		return 0
	}
	switch message {
	case wmTrayCallback:
		// Tray mouse events arrive in the LOWORD of lParam: WM_LBUTTONUP,
		// WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_RBUTTONDBLCLK (and NIN_SELECT /
		// NIN_KEYSELECT for keyboard-invoked tray activation). Balloon
		// interaction arrives as NIN_BALLOONUSERCLICK (user click) and
		// NIN_BALLOONTIMEUP (auto-hide): both end the persistence cycle.
		switch code := uint32(lParam) & 0xFFFF; code {
		case 0x0202, 0x0203, 0x0206, // WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONDBLCLK
			0x0205: // WM_RBUTTONUP
			host.showMenu()
		case 0x0406: // NIN_BALLOONUSERCLICK
			host.stopBalloonRepeat()
		case 0x0403: // NIN_BALLOONTIMEUP
			// Plain auto-hide: persistence timer re-issues (unless the
			// user already dismissed, in which case the cycle is cleared).
		default:
			_ = code
		}
	case wmDestroy:
		host.stopBalloonRepeat()
		host.stopFlash()
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
	user32Once.Call(uintptr(host.window))

	var point struct{ x, y int32 }
	getCursor.Call(uintptr(unsafe.Pointer(&point)))

	chosen, _, _ := trackPopupMenu.Call(
		uintptr(host.menu),
		uintptr(tpmRightAlign|tpmBottomAlign|tpmReturnCmd|tpmNonotify|tpmLeftBtn),
		uintptr(int64(point.x)), // x (screen)
		uintptr(int64(point.y)), // y (screen)
		0,
		uintptr(host.window),
		0,
	)
	postMessage.Call(uintptr(host.window), uintptr(wmNull), 0, 0)
	go host.dispatchMenu(uint32(chosen))
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

func (host *menuHost) setNotifyVersion() error {
	data := notifyIconData{Window: host.window, ID: host.iconToken, VersionOrTimeout: notifyIconVersion4}
	data.Size = uint32(unsafe.Sizeof(data))
	result, _, err := shellProc.Call(nimSetVersion, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return fmt.Errorf("Shell_NotifyIcon(NIM_SETVERSION): %w", err)
	}
	return nil
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
	result, _, err := shellProc.Call(uintptr(op), uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return fmt.Errorf("Shell_NotifyIcon(%d): %w", op, err)
	}
	return nil
}

func (host *menuHost) dispose() {
	_ = host.notify(nimDelete)
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
	return lines
}

// statusDisplayText converts the raw phase/state pair into a compact,
// user-friendly tunnel status string.
func statusDisplayText(state TrayState) string {
	switch {
	case state.Phase == "service:unknown":
		return "service status unavailable"
	case state.Phase == "exiting":
		return "exiting"
	case strings.HasSuffix(state.Phase, "running") && state.State == "connected":
		return "connected"
	case strings.HasSuffix(state.Phase, "running"):
		return state.State
	case strings.HasSuffix(state.Phase, "pending_config"):
		return "waiting for pairing"
	case strings.HasSuffix(state.Phase, "reconnecting"):
		return "reconnecting"
	case strings.HasSuffix(state.Phase, "terminal"):
		return "stopped (error)"
	case strings.HasSuffix(state.Phase, "stopped"):
		return "stopped"
	default:
		return state.Phase
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
	data.Flags = nifMessage | nifInfo
	data.InfoFlags = infoFlags
	copy(data.InfoTitle[:], syscall.StringToUTF16(title))
	copy(data.Info[:], syscall.StringToUTF16(message))
	data.Size = uint32(unsafe.Sizeof(data))
	result, _, err := shellProc.Call(nimModify, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
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
	fromDown, toDown := isDownState(from), isDownState(to)
	fromUp := isUpState(from)
	switch {
	case toDown && fromUp:
		host.showPersistentBalloon("HooshiX tunnel disconnected", disconnectText(to), niifWarning)
	case toDown && fromDown && to.Phase != from.Phase:
		// Escalation only: stopped → terminal gets one balloon; silent
		// churn between disconnected and reconnecting stays silent.
		if strings.HasSuffix(to.Phase, "terminal") {
			host.showPersistentBalloon("HooshiX Agent stopped", disconnectText(to), niifError)
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

// isDownState reports whether the tunnel is service-running but not
// connected (reconnecting, waiting for pairing, terminal, ...).
// isDownState reports whether the tunnel is degraded: the supervisor is
// alive but not connected (or the supervisor itself failed). A running+
// connected snapshot is up, not down.
func isDownState(state TrayState) bool {
	if isUpState(state) {
		return false
	}
	return strings.HasSuffix(state.Phase, "running") ||
		strings.HasSuffix(state.Phase, "reconnecting") ||
		strings.HasSuffix(state.Phase, "terminal")
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
	host.stopFlash()
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
func (host *menuHost) stopFlash() {
	if host.flashStop != nil {
		close(host.flashStop)
		host.flashStop = nil
		setTrayIcon(statusIcon(readinessFromState(host.app.currentState())))
	}
}

// setTrayIcon swaps only the icon portion of the tray entry.
func setTrayIcon(icon windows.Handle) {
	if icon == 0 {
		return
	}
	var data notifyIconData
	data.Window = currentHost.window
	data.ID = currentHost.iconToken
	data.Flags = nifMessage | nifIcon
	data.Icon = icon
	data.Size = uint32(unsafe.Sizeof(data))
	shellProc.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

// refreshMenu applies state to the tray icon, tooltip, and menu so tunnel
// health is visible at a glance and up to date on every poll.
func (host *menuHost) refreshMenu(state TrayState) {
	host.app.mu.Lock()
	previous := host.app.state
	host.app.state = state
	host.app.mu.Unlock()
	host.notifyTunnelEvent(previous, state)
	host.rebuildMenu()
	var tip [128]uint16
	copy(tip[:], syscall.StringToUTF16("HooshiX Agent — "+statusDisplayText(state)))
	data := notifyIconData{
		Window: host.window,
		ID:     host.iconToken,
		Flags:  nifMessage | nifIcon | nifTip,
		Icon:   statusIcon(readinessFromState(state)),
		Tip:    tip,
	}
	data.Size = uint32(unsafe.Sizeof(data))
	result, _, err := shellProc.Call(nimModify, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
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
