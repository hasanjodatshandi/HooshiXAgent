//go:build windows

// Command hooshix-connect is the Windows GUI for a HooshiX Connector session:
// paste the connect bundle the Panel issued, press Connect, then open Remote
// Desktop against the loopback address the app reports. All session logic lives
// in internal/connectgui; this file is window plumbing only.
package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connectgui"
)

// Win32 constants used here, named instead of magic.
const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmTimer   = 0x0113
	wmSetFont = 0x0030
	wmSetText = 0x000C

	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsBorder      = 0x00800000
	wsVScroll     = 0x00200000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esWantReturn  = 0x1000

	bsDefaultPush = 0x0001
	csRedraw      = 0x0003 // CS_HREDRAW|CS_VREDRAW

	bnClicked = 0

	swHide        = 0
	swpNoMove     = 0x0002
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	mbIconWarning   = 0x00000030
	whiteBrushStock = 0 // GetStockObject(WHITE_BRUSH)
	swShow          = 5

	statusTimer = uintptr(1)
	statusPoll  = 200 * time.Millisecond
	noticeTimer = uintptr(2)
	noticeDelay = 400 * time.Millisecond

	// The layout is authored at 96 DPI and scaled by the window DPI.
	clientWidth = 560
	// hintHeight is four lines of the saved-bundle hint. Both numbers come from the
	// rendered window, not from a text-measuring API: at 150% scaling the hint's
	// lines start 25 device pixels apart, which is 16.7 DIP, so a line is budgeted
	// at 18 DIP. A STATIC offers no scroll and no ellipsis, so a box one line too
	// short loses its last sentence's lower half silently.
	hintHeight       = 72
	hintCharsPerLine = 94
	hintLineHeight   = 18
	hintTop          = 286
	clientHeight     = hintTop + hintHeight + 6
	fontHeightDIP    = 9 // Segoe UI point size

	// Once a saved bundle makes the paste area unnecessary, every row below it
	// moves up into that space and the window shrinks by the same amount.
	compactLift = 106
)

// Control ids, dispatched in command().
const (
	idBundleCaption = iota + 101
	idBundle
	idConnect
	idDisconnect
	idOpenRDP
	idStatusLabel
	idMessageLabel
	idHint
	idRevealBundle
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// appWindow is the only window this process shows. The window procedure is a
	// syscall callback and cannot capture state, so it reaches the host through
	// this package-level pointer; wndProc only ever runs on the message-loop
	// thread, which is also the only thread that touches these fields.
	appWindow *host
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

// spec is one control, positioned in 96-DPI units and scaled at creation.
// visible says whether the shape this list was built for shows it: the two
// shapes share one control set and differ only in which half of it the operator
// can see, which is what lets the window switch shapes without rebuilding it.
type spec struct {
	id            int
	class         string
	title         string
	style         uint32
	x, y          int
	width, height int
	visible       bool
}

// specs lays the window out for one of its two shapes. The compact shape lifts
// every row under the paste area by compactLift and swaps the bundle caption and
// edit for the button that brings them back: an operator who already has a saved
// bundle does not need a text box they are never going to use.
func specs(compact bool) []spec {
	lift := 0
	if compact {
		lift = compactLift
	}
	child := uint32(wsChild | wsVisible)
	return []spec{
		{idBundleCaption, "STATIC", "Connect bundle", child, 16, 16, clientWidth - 32, 18, !compact},
		{idBundle, "EDIT", "", child | wsBorder | wsVScroll | esMultiline | esAutoVScroll | esWantReturn, 16, 40, clientWidth - 32, 110, !compact},
		{idRevealBundle, "BUTTON", revealSavedTitle(""), child, 16, 16, clientWidth - 32, 26, compact},
		{idConnect, "BUTTON", "Connect", child | bsDefaultPush, 16, 164 - lift, 120, 30, true},
		{idDisconnect, "BUTTON", "Disconnect", child, 146, 164 - lift, 120, 30, true},
		{idOpenRDP, "BUTTON", "Open Remote Desktop", child, 276, 164 - lift, 190, 30, true},
		{idStatusLabel, "STATIC", "Status: idle", child, 16, 212 - lift, clientWidth - 32, 20, true},
		{idMessageLabel, "STATIC", "", child, 16, 236 - lift, clientWidth - 32, 44, true},
		{idHint, "STATIC", hintText(compact), child, 16, hintTop - lift, clientWidth - 32, hintHeight, true},
	}
}

// clientHeightFor is the authored client height of one shape.
func clientHeightFor(compact bool) int {
	if compact {
		return clientHeight - compactLift
	}
	return clientHeight
}

// revealSavedTitle names the button that brings the paste area back and says
// which credential the window is running from. The saved date matters: a bundle
// outlives nobody's guess about whether the grant behind it is still current, and
// a window with no paste area must still tell the operator what it is holding.
func revealSavedTitle(savedAt string) string {
	date := savedAtDate(savedAt)
	if date == "" {
		return "Use a different bundle"
	}
	return "Use a different bundle (last saved " + date + ")"
}

// savedAtDate keeps the day out of an RFC 3339 timestamp. Anything that does not
// look like one is dropped rather than shown: the date is a hint, not a record
// the operator has to parse.
func savedAtDate(savedAt string) string {
	if len(savedAt) < 10 || savedAt[10] != 'T' {
		return ""
	}
	return savedAt[:10]
}

// singleClientHint is the rule the compact shape shares with the full one.
const singleClientHint = "One Remote Desktop client at a time: a second window steals the session, and Windows then reconnects the first. Revoke the grant in the Panel to end this tunnel. Closing this window ends it."

// hintText is the on-screen explanation for the current shape. The compact shape
// adds where the credential came from, because a window that shows no paste area
// still has to explain how to get one and how to stop saving it.
func hintText(compact bool) string {
	if compact {
		return "The bundle is saved beside hooshix-connect.exe, so this window has no paste area. Use the button above for another bundle, or delete hooshix-connect.cfg to forget it. " + singleClientHint
	}
	return singleClientHint
}

// messageFor is the instruction line the window shows for one status snapshot.
// Only the idle sentence depends on the shape: a compact window has hidden the
// paste area, so it must not ask for a bundle the operator cannot type. Idle is
// the state the app has before its first Connect, so every other message was
// written by a session or an action and is shown as it came.
func messageFor(status connectgui.Status, compact bool) string {
	if status.State == connectgui.StateIdle {
		return connectgui.IdleMessage(compact)
	}
	return status.Message
}

// host is the application window and its controls.
type host struct {
	app      *connectgui.App
	instance uintptr
	hwnd     windows.Handle
	handlers map[int]windows.Handle
	font     windows.Handle
	scale    float64

	// disconnecting marks a session teardown that is still in flight. The
	// closure runs on a worker goroutine because App.Disconnect waits for the
	// serving goroutine to release the loopback port and the window must stay
	// responsive while it does; disconnectDone is closed when it returns.
	disconnecting  bool
	disconnectDone chan struct{}

	// lastStatus/lastLabel cache what is already rendered so a poll that changes
	// nothing does not repaint the statics, which visibly flickers.
	lastStatus string
	lastLabel  string

	// bundle is the last connect bundle that started a session. The edit control
	// is cleared after a successful Connect so a live connector credential stops
	// sitting in a window the operator leaves open or records; the value stays
	// here so a reconnect after Disconnect needs no re-paste.
	bundle string

	// store keeps that bundle for the next run, in the cfg beside this
	// executable, and savedAt records when the file was last written ("" while
	// nothing is stored). compact is the shape currently on screen.
	store   *connectgui.BundleStore
	savedAt string
	compact bool

	// problem is why a saved bundle could not be used on this run. It is reported
	// from the message loop, after the first paint, rather than as a modal box in
	// front of a window that has not drawn yet.
	problem error
}

func main() {
	// This binary is built with -H windowsgui, so a panic has no console to
	// report to: the window would simply never appear and the process would
	// vanish. Every failure the operator can see goes through the same box.
	defer func() {
		if recovered := recover(); recovered != nil {
			fatal(fmt.Errorf("unexpected failure: %v", recovered))
		}
	}()
	// The message loop must own the thread it pumps on.
	runtime.LockOSThread()
	instance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	executable, executableErr := os.Executable()
	saved := openSavedBundleStore(executable)
	if executableErr != nil && saved.problem == nil {
		saved.problem = executableErr
	}
	application, err := newHost(connectgui.New(), uintptr(instance), saved)
	if err != nil {
		fatal(err)
		return
	}
	appWindow = application
	application.run()
	appWindow = nil
}

// fatal reports a startup failure without a console: this binary is built with
// -H windowsgui, so the only channel the operator has is a message box.
func fatal(err error) {
	message := syscall.StringToUTF16Ptr("HooshiX Connect could not start: " + err.Error())
	title := syscall.StringToUTF16Ptr("HooshiX Connect")
	user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), mbIconWarning)
	os.Exit(1)
}

func newHost(app *connectgui.App, instance uintptr, saved savedBundleState) (*host, error) {
	// A window that already holds a usable credential opens without the paste
	// area it does not need.
	compact := saved.compact()
	host := &host{
		app:      app,
		instance: instance,
		handlers: map[int]windows.Handle{},
		store:    saved.store,
		bundle:   saved.bundle,
		savedAt:  saved.savedAt,
		compact:  compact,
		problem:  saved.problem,
	}

	background, _, _ := gdi32.NewProc("GetStockObject").Call(whiteBrushStock)
	registerClass := user32.NewProc("RegisterClassExW")
	className := syscall.StringToUTF16Ptr("HooshiXConnectWindow")
	class := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		Style:      csRedraw,
		WndProc:    syscall.NewCallback(wndProc),
		Instance:   instance,
		Icon:       uintptr(loadIcon(instance)),
		Cursor:     uintptr(loadCursor()),
		Background: background,
		ClassName:  uintptr(unsafe.Pointer(className)),
	}
	class.IconSm = class.Icon
	if atom, _, err := registerClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return nil, fmt.Errorf("RegisterClassEx: %w", err)
	}

	dpi, _, _ := user32.NewProc("GetDpiForSystem").Call()
	if dpi == 0 {
		dpi = 96
	}
	host.scale = float64(dpi) / 96

	// The client area is the authored layout times the DPI factor, then
	// AdjustWindowRect adds the caption and borders. Scaling only the children
	// left the bottom rows outside a 96-DPI-sized client on a scaled desktop,
	// where the status line and hint become unreachable.
	style := uintptr(wsCaption | wsSysMenu | wsMinimizeBox)
	rect := struct{ left, top, right, bottom int32 }{0, 0, unit(clientWidth, host.scale), unit(clientHeightFor(compact), host.scale)}
	user32.NewProc("AdjustWindowRect").Call(uintptr(unsafe.Pointer(&rect)), style, 0)
	width := uintptr(int(rect.right) - int(rect.left))
	height := uintptr(int(rect.bottom) - int(rect.top))

	// Centre on the primary screen, clamped so a tiny or unusual desktop cannot
	// push the window off screen where its buttons become unreachable.
	getSystemMetrics := user32.NewProc("GetSystemMetrics")
	screenWidth, _, _ := getSystemMetrics.Call(0)  // SM_CXSCREEN
	screenHeight, _, _ := getSystemMetrics.Call(1) // SM_CYSCREEN
	x, y := uintptr(0), uintptr(0)
	if screenWidth > width {
		x = (screenWidth - width) / 2
	}
	if screenHeight > height {
		y = (screenHeight - height) / 3
	}

	title := syscall.StringToUTF16Ptr("HooshiX Connect")
	createWindow := user32.NewProc("CreateWindowExW")
	hwnd, _, err := createWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		style,
		x, y, width, height,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return nil, fmt.Errorf("CreateWindowEx: %w", err)
	}
	host.hwnd = windows.Handle(hwnd)

	host.font = createFont(dpi)
	for _, control := range specs(compact) {
		child, err := host.createControl(control)
		if err != nil {
			return nil, err
		}
		host.handlers[control.id] = child
	}
	// applyLayout renders the shape this window was built for: which controls are
	// live, where they sit, and the idle snapshot instead of whatever the window
	// defaults allowed, so the disabled state is correct from the first paint.
	host.applyLayout(compact)

	user32.NewProc("SetTimer").Call(uintptr(host.hwnd), statusTimer, uintptr(statusPoll.Milliseconds()), 0)
	user32.NewProc("ShowWindow").Call(uintptr(host.hwnd), swShow)
	user32.NewProc("UpdateWindow").Call(uintptr(host.hwnd))
	if host.problem != nil {
		// One shot, after the first paint: the operator learns why nothing will be
		// remembered, instead of meeting a modal box in front of a blank client.
		user32.NewProc("SetTimer").Call(uintptr(host.hwnd), noticeTimer, uintptr(noticeDelay.Milliseconds()), 0)
	}
	return host, nil
}

func (host *host) createControl(control spec) (windows.Handle, error) {
	scale := host.scale
	class := syscall.StringToUTF16Ptr(control.class)
	title := syscall.StringToUTF16Ptr(control.title)
	hwnd, _, err := user32.NewProc("CreateWindowExW").Call(
		0,
		uintptr(unsafe.Pointer(class)),
		uintptr(unsafe.Pointer(title)),
		uintptr(control.style),
		uintptr(unit(control.x, scale)),
		uintptr(unit(control.y, scale)),
		uintptr(unit(control.width, scale)),
		uintptr(unit(control.height, scale)),
		uintptr(host.hwnd),
		uintptr(control.id),
		host.instance,
		0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("CreateWindowEx(%s %d): %w", control.class, control.id, err)
	}
	user32.NewProc("SendMessageW").Call(hwnd, wmSetFont, uintptr(host.font), 1)
	return windows.Handle(hwnd), nil
}

func loadIcon(instance uintptr) windows.Handle {
	loadIconProc := user32.NewProc("LoadIconW")
	// Resource id 1 is the icon the build embeds through rsrc's .syso.
	if icon, _, _ := loadIconProc.Call(instance, 1); icon != 0 {
		return windows.Handle(icon)
	}
	icon, _, _ := loadIconProc.Call(0, 32512) // IDI_APPLICATION
	return windows.Handle(icon)
}

func loadCursor() windows.Handle {
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512) // IDC_ARROW
	return windows.Handle(cursor)
}

// createFont returns an HFONT for the interface font at the system DPI. A
// negative height asks GDI for the character height, which is what a point size
// means.
func createFont(dpi uintptr) windows.Handle {
	height := -int32(mulDiv(fontHeightDIP, int(dpi), 72))
	name := syscall.StringToUTF16Ptr("Segoe UI")
	font, _, _ := gdi32.NewProc("CreateFontW").Call(
		uintptr(height), 0, 0, 0,
		400, // FW_NORMAL
		0, 0, 0,
		1,    // DEFAULT_CHARSET
		0,    // OUT_TT_PRECIS
		0,    // CLIP_DEFAULT_PRECIS
		1,    // ANTIALIASED_QUALITY
		0x31, // FF_DONTCARE|DEFAULT_PITCH
		uintptr(unsafe.Pointer(name)),
	)
	return windows.Handle(font)
}

func mulDiv(value, numerator, denominator int) int {
	result, _, _ := kernel32.NewProc("MulDiv").Call(uintptr(value), uintptr(numerator), uintptr(denominator))
	return int(int32(result))
}

// unit converts one authored 96-DPI dimension to device units.
func unit(value int, scale float64) int32 {
	return int32(math.Round(float64(value) * scale))
}

func (host *host) run() {
	var msg struct {
		Window   windows.Handle
		Message  uint32
		WParam   uintptr
		LParam   uintptr
		Time     uint32
		Point    struct{ x, y int32 }
		LPrivate uint32
	}
	getMessage := user32.NewProc("GetMessageW")
	translateMessage := user32.NewProc("TranslateMessage")
	dispatchMessage := user32.NewProc("DispatchMessageW")
	for {
		result, _, err := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			fatal(fmt.Errorf("GetMessage: %w", err))
			return
		}
		if result == 0 {
			return
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func wndProc(hwnd windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
	if appWindow != nil {
		switch message {
		case wmTimer:
			switch wParam {
			case statusTimer:
				appWindow.render(appWindow.app.Status())
				return 0
			case noticeTimer:
				appWindow.reportProblem()
				return 0
			}
		case wmCommand:
			if wParam>>16 == bnClicked {
				appWindow.command(int(wParam & 0xFFFF))
				return 0
			}
		case wmClose:
			user32.NewProc("DestroyWindow").Call(uintptr(hwnd))
			return 0
		case wmDestroy:
			appWindow.shutdown()
			user32.NewProc("PostQuitMessage").Call(0)
			return 0
		}
	}
	result, _, _ := user32.NewProc("DefWindowProcW").Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return result
}

// render updates the labels and button states from a session snapshot. It runs
// only on the message-loop thread, from the poll timer and after each action.
func (host *host) render(status connectgui.Status) {
	if host.disconnecting {
		select {
		case <-host.disconnectDone:
			host.disconnecting = false
			host.disconnectDone = nil
		default:
		}
	}
	label := "Status: " + connectgui.StatusLabel(status, host.disconnecting)
	if label != host.lastStatus {
		host.lastStatus = label
		host.setText(idStatusLabel, label)
	}
	message := messageFor(status, host.compact)
	if message != host.lastLabel {
		host.lastLabel = message
		host.setText(idMessageLabel, message)
	}
	buttons := connectgui.ButtonsFor(status, host.disconnecting)
	host.enable(idConnect, buttons.Connect)
	host.enable(idDisconnect, buttons.Disconnect)
	host.enable(idOpenRDP, buttons.OpenClient)
}

// applyLayout switches between the two window shapes. Every control exists in
// both, so a shape change only shows and moves what the shape uses, then resizes
// the frame to the matching client height.
func (host *host) applyLayout(compact bool) {
	host.compact = compact
	for _, control := range specs(compact) {
		hwnd, ok := host.handlers[control.id]
		if !ok {
			continue
		}
		show := uintptr(swHide)
		if control.visible {
			show = uintptr(swShow)
		}
		user32.NewProc("ShowWindow").Call(uintptr(hwnd), show)
		user32.NewProc("SetWindowPos").Call(
			uintptr(hwnd), 0,
			uintptr(unit(control.x, host.scale)), uintptr(unit(control.y, host.scale)),
			uintptr(unit(control.width, host.scale)), uintptr(unit(control.height, host.scale)),
			uintptr(swpNoZOrder|swpNoActivate),
		)
	}
	host.setText(idRevealBundle, revealSavedTitle(host.savedAt))
	host.setText(idHint, hintText(compact))

	// The frame has to follow the shape. Leaving a full-height client area over
	// lifted rows is how a window ends up with its hint floating in blank space.
	style := uintptr(wsCaption | wsSysMenu | wsMinimizeBox)
	rect := struct{ left, top, right, bottom int32 }{0, 0, unit(clientWidth, host.scale), unit(clientHeightFor(compact), host.scale)}
	user32.NewProc("AdjustWindowRect").Call(uintptr(unsafe.Pointer(&rect)), style, 0)
	user32.NewProc("SetWindowPos").Call(
		uintptr(host.hwnd), 0, 0, 0,
		uintptr(int(rect.right)-int(rect.left)), uintptr(int(rect.bottom)-int(rect.top)),
		uintptr(swpNoMove|swpNoZOrder),
	)
	if !compact {
		user32.NewProc("SetFocus").Call(uintptr(host.handlers[idBundle]))
	}
	// Both statics cache what they already show, and this changed what they show.
	host.lastStatus = ""
	host.lastLabel = ""
	host.render(host.app.Status())
}

func (host *host) command(id int) {
	switch id {
	case idConnect:
		pasted, err := host.bundleText()
		if err != nil {
			host.warn(err)
			return
		}
		bundle, err := launchBundle(pasted, host.bundle)
		if err != nil {
			host.warn(err)
			return
		}
		// App.Connect records its own failure into the snapshot, so re-rendering
		// the status is enough to show the reason; the returned error is only used
		// to decide whether the pasted credential is safe to erase from the edit.
		if err := host.app.Connect(bundle); err != nil {
			host.render(host.app.Status())
			return
		}
		host.bundle = bundle
		host.setText(idBundle, "")
		host.rememberBundle(bundle)
		host.render(host.app.Status())
	case idRevealBundle:
		host.applyLayout(false)
	case idDisconnect:
		if host.disconnecting {
			return
		}
		host.disconnecting = true
		host.disconnectDone = make(chan struct{})
		done := host.disconnectDone
		go func() {
			host.app.Disconnect()
			close(done)
		}()
		host.render(host.app.Status())
	case idOpenRDP:
		target, err := connectgui.RDPTarget(host.app.Status())
		if err != nil {
			host.warn(err)
			return
		}
		if err := launchRemoteDesktop(target); err != nil {
			host.warn(err)
		}
	}
}

// warn surfaces a failure the status line would not explain on its own.
func (host *host) warn(err error) {
	message := syscall.StringToUTF16Ptr(err.Error())
	title := syscall.StringToUTF16Ptr("HooshiX Connect")
	user32.NewProc("MessageBoxW").Call(uintptr(host.hwnd), uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), mbIconWarning)
}

// reportProblem surfaces, once, why this run cannot use a saved bundle. A tunnel
// still works without one, so this is not a fatal condition, but an operator who
// expects the bundle to be remembered has to hear that it will not be: the
// alternative is a paste area that reappears every launch with no explanation.
func (host *host) reportProblem() {
	user32.NewProc("KillTimer").Call(uintptr(host.hwnd), noticeTimer)
	problem := host.problem
	host.problem = nil
	if problem == nil {
		return
	}
	host.warn(fmt.Errorf("the tunnel still works, but HooshiX Connect cannot use a saved bundle: %w", problem))
}

// remoteDesktopSpec is the launch request for the Remote Desktop client,
// separated from starting it so a test can pin the exact command line and the
// window behaviour without ever spawning mstsc.
type remoteDesktopSpec struct {
	path        string
	args        []string
	sysProcAttr *syscall.SysProcAttr
}

// newRemoteDesktopSpec builds that request. sysProcAttr is deliberately left
// nil: a value with HideWindow set becomes STARTF_USESHOWWINDOW|SW_HIDE, and
// mstsc honours it for its main window. The session then connects invisibly —
// no window, no taskbar button, nothing in Alt+Tab — which reads as "the button
// did nothing" and pushes the operator to click it again. A second client makes
// Windows arbitrate its one interactive session away from the first.
func newRemoteDesktopSpec(root, target string) remoteDesktopSpec {
	return remoteDesktopSpec{
		path: filepath.Join(root, "System32", "mstsc.exe"),
		args: []string{"/v:" + target},
	}
}

// launchRemoteDesktop starts mstsc against the tunnel's loopback endpoint. The
// target comes from connectgui.RDPTarget, which has already proved it is a
// loopback host:port, so no operator text reaches the command line.
func launchRemoteDesktop(target string) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	spec := newRemoteDesktopSpec(root, target)
	if _, err := os.Stat(spec.path); err != nil {
		return fmt.Errorf("remote desktop client is not available at %s: %w", spec.path, err)
	}
	command := exec.Command(spec.path, spec.args...)
	command.SysProcAttr = spec.sysProcAttr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start remote desktop: %w", err)
	}
	// Start() without Wait() leaves the child unreaped for as long as this app
	// runs, which outlives mstsc. Nobody needs its exit status, so reap it in the
	// background instead of blocking the message loop on a remote session.
	go func() { _ = command.Wait() }()
	return nil
}

// launchBundle chooses the credential for a session: what the edit control holds
// now, otherwise the last bundle that opened a tunnel. A successful Connect
// erases the edit so the bearer token stops being visible on screen, and this is
// what keeps a reconnect after Disconnect from demanding a re-paste.
func launchBundle(pasted, remembered string) (string, error) {
	if pasted != "" {
		return pasted, nil
	}
	if remembered != "" {
		return remembered, nil
	}
	return "", errors.New("paste the connect bundle the Panel issued first")
}

// rememberBundle stores the credential that just opened a tunnel so the next run
// starts from it, then drops the paste area that the stored bundle replaced. A
// store that cannot write is reported and not retried: the session is live, and
// the operator's work outranks the convenience of the next launch.
func (host *host) rememberBundle(bundle string) {
	if host.store == nil {
		return
	}
	saved, err := host.store.Save(bundle)
	if err != nil {
		host.warn(fmt.Errorf("the tunnel is up, but the bundle was not saved beside the program: %w", err))
		return
	}
	host.savedAt = saved.SavedAt
	host.applyLayout(true)
}

func (host *host) bundleText() (string, error) {
	length, _, _ := user32.NewProc("GetWindowTextLengthW").Call(uintptr(host.handlers[idBundle]))
	if length == 0 {
		return "", nil
	}
	buffer := make([]uint16, length+1)
	copied, _, err := user32.NewProc("GetWindowTextW").Call(
		uintptr(host.handlers[idBundle]),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if copied == 0 {
		return "", fmt.Errorf("read the bundle from the window: %w", err)
	}
	return syscall.UTF16ToString(buffer[:copied]), nil
}

func (host *host) setText(id int, value string) {
	pointer := syscall.StringToUTF16Ptr(value)
	user32.NewProc("SendMessageW").Call(uintptr(host.handlers[id]), wmSetText, 0, uintptr(unsafe.Pointer(pointer)))
}

func (host *host) enable(id int, enabled bool) {
	var value uintptr
	if enabled {
		value = 1
	}
	user32.NewProc("EnableWindow").Call(uintptr(host.handlers[id]), value)
}

// shutdown stops the session and releases the font. The process is leaving
// anyway, but a live Connector would keep the loopback port bound and any
// connected client hanging on a socket that is about to disappear.
func (host *host) shutdown() {
	user32.NewProc("KillTimer").Call(uintptr(host.hwnd), statusTimer)
	user32.NewProc("KillTimer").Call(uintptr(host.hwnd), noticeTimer)
	host.app.Disconnect()
	if host.font != 0 {
		gdi32.NewProc("DeleteObject").Call(uintptr(host.font))
		host.font = 0
	}
}
