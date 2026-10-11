//go:build windows

// Command hooshix-connect is the Windows GUI for a HooshiX Connector session:
// paste the connect bundle the Panel issued, press Connect, then open Remote
// Desktop against the loopback address the app reports. All session logic lives
// in internal/connectgui; this file is window plumbing only.
package main

import (
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

	mbIconWarning   = 0x00000030
	whiteBrushStock = 0 // GetStockObject(WHITE_BRUSH)
	swShow          = 5

	statusTimer = uintptr(1)
	statusPoll  = 200 * time.Millisecond

	// The layout is authored at 96 DPI and scaled by the window DPI.
	clientWidth   = 560
	clientHeight  = 316
	fontHeightDIP = 9 // Segoe UI point size
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
type spec struct {
	id            int
	class         string
	title         string
	style         uint32
	x, y          int
	width, height int
}

func specs() []spec {
	return []spec{
		{idBundleCaption, "STATIC", "Connect bundle", wsChild | wsVisible, 16, 16, clientWidth - 32, 18},
		{idBundle, "EDIT", "", wsChild | wsVisible | wsBorder | wsVScroll | esMultiline | esAutoVScroll | esWantReturn, 16, 40, clientWidth - 32, 110},
		{idConnect, "BUTTON", "Connect", wsChild | wsVisible | bsDefaultPush, 16, 164, 120, 30},
		{idDisconnect, "BUTTON", "Disconnect", wsChild | wsVisible, 146, 164, 120, 30},
		{idOpenRDP, "BUTTON", "Open Remote Desktop", wsChild | wsVisible, 276, 164, 190, 30},
		{idStatusLabel, "STATIC", "Status: idle", wsChild | wsVisible, 16, 212, clientWidth - 32, 20},
		{idMessageLabel, "STATIC", "", wsChild | wsVisible, 16, 236, clientWidth - 32, 44},
		{idHint, "STATIC", "The grant's own lifetime controls this tunnel. Closing this window ends it.", wsChild | wsVisible, 16, 286, clientWidth - 32, 20},
	}
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
	application, err := newHost(connectgui.New(), uintptr(instance))
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

func newHost(app *connectgui.App, instance uintptr) (*host, error) {
	host := &host{app: app, instance: instance, handlers: map[int]windows.Handle{}}

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
	rect := struct{ left, top, right, bottom int32 }{0, 0, unit(clientWidth, host.scale), unit(clientHeight, host.scale)}
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
	for _, control := range specs() {
		child, err := host.createControl(control)
		if err != nil {
			return nil, err
		}
		host.handlers[control.id] = child
	}
	// Render the idle snapshot rather than leaving the controls at whatever the
	// window defaults allowed, so the disabled state is correct from the first
	// paint.
	host.render(host.app.Status())

	user32.NewProc("SetTimer").Call(uintptr(host.hwnd), statusTimer, uintptr(statusPoll.Milliseconds()), 0)
	user32.NewProc("ShowWindow").Call(uintptr(host.hwnd), swShow)
	user32.NewProc("UpdateWindow").Call(uintptr(host.hwnd))
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
			if wParam == statusTimer {
				appWindow.render(appWindow.app.Status())
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
	if status.Message != host.lastLabel {
		host.lastLabel = status.Message
		host.setText(idMessageLabel, status.Message)
	}
	buttons := connectgui.ButtonsFor(status, host.disconnecting)
	host.enable(idConnect, buttons.Connect)
	host.enable(idDisconnect, buttons.Disconnect)
	host.enable(idOpenRDP, buttons.OpenClient)
}

func (host *host) command(id int) {
	switch id {
	case idConnect:
		bundle, err := host.bundleText()
		if err != nil {
			host.warn(err)
			return
		}
		// App.Connect records its own failure into the snapshot, so re-rendering
		// the status is enough to show the reason; the returned error is the same
		// value the operator would otherwise have to dig out of a log.
		_ = host.app.Connect(bundle)
		host.render(host.app.Status())
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

// launchRemoteDesktop starts mstsc against the tunnel's loopback endpoint. The
// target comes from connectgui.RDPTarget, which has already proved it is a
// loopback host:port, so no operator text reaches the command line.
func launchRemoteDesktop(target string) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "System32", "mstsc.exe")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("remote desktop client is not available at %s: %w", path, err)
	}
	command := exec.Command(path, "/v:"+target)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start remote desktop: %w", err)
	}
	return nil
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
	host.app.Disconnect()
	if host.font != 0 {
		gdi32.NewProc("DeleteObject").Call(uintptr(host.font))
		host.font = 0
	}
}
