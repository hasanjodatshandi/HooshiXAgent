//go:build windows

package tray

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// menuHost owns the hidden window, tray icon, context menu, and message pump.
type menuHost struct {
	app       *App
	instance  windows.Handle
	window    windows.Handle
	menu      windows.Handle
	iconToken uint32
	quitFlag  bool
}

const (
	wmTrayCallback  = 0x8000 // WM_APP
	wmDestroy       = 0x0002
	wmEndSession    = 0x0016
	wmTaskbarCreated = 0x1E // "TaskbarCreated" broadcast for re-add
)

var (
	shell32   = windows.NewLazySystemDLL("shell32.dll")
	user32    = windows.NewLazySystemDLL("user32.dll")
	kernel32  = windows.NewLazySystemDLL("kernel32.dll")
	shellProc = shell32.NewProc("Shell_NotifyIconW")
)

// notifyIconData mirrors the fixed NOTIFYICONDATAW layout we need.
type notifyIconData struct {
	Size            uint32
	Window          windows.Handle
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
}

const (
	nifMessage = 0x01
	nifIcon   = 0x02
	nifTip    = 0x04
	nimAdd    = 0x00
	nimDelete = 0x02
)

var (
	className      = syscall.StringToUTF16Ptr("HooshiXAgentTray")
	windowTitle    = syscall.StringToUTF16Ptr("HooshiX Agent Tray")
	pairingLabel   = syscall.StringToUTF16Ptr("Open pairing page")
	startLabel     = syscall.StringToUTF16Ptr("Start service")
	stopLabel      = syscall.StringToUTF16Ptr("Stop service")
	exitLabel      = syscall.StringToUTF16Ptr("Exit")
	menuSepLabel   = syscall.StringToUTF16Ptr("-")
)

type wndClass struct {
	style         uint32
	wndProc       uintptr
	classExtra    int32
	windowExtra   int32
	instance      windows.Handle
	icon          windows.Handle
	cursor        windows.Handle
	background    windows.Handle
	menuName      *uint16
	className     *uint16
}

func newMenuHost(app *App) (*menuHost, error) {
	host := &menuHost{app: app}

	instance, _, err := kernel32.NewProc("GetModuleHandleW").Call(0)
	if instance == 0 {
		return nil, fmt.Errorf("GetModuleHandle: %w", err)
	}
	host.instance = windows.Handle(instance)

	// Register the window class with our tray callback procedure.
	registerClass := user32.NewProc("RegisterClassExW")
	routine := syscall.NewCallback(trayWndProc)
	// Store the host pointer per-process; single instance assumption is fine
	// for one tray app.
	currentHost = host
	class := wndClass{
		wndProc:   routine,
		instance:  host.instance,
		className: className,
		icon:      loadDefaultIcon(),
	}
	registerClass.Call(uintptr(unsafe.Pointer(&class)))

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
	const menuPairing = 1001
	const menuStart = 1002
	const menuStop = 1003
	const menuExit = 1004

	appendMenu.Call(uintptr(host.menu), mfString, menuPairing, uintptr(unsafe.Pointer(pairingLabel)))
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
	switch message {
	case wmTaskbarCreated:
		_ = host.notify(nimAdd)
	case wmTrayCallback:
		switch lParam {
		case 0x0203: // WM_CONTEXTMENU (right click); 0x0202 = WM_LBUTTONUP (left click)
			fallthrough
		case 0x0202:
			host.showMenu()
		}
	case wmDestroy:
		_ = host.notify(nimDelete)
	case wmEndSession:
		postQuitMessage()
		return 0
	}
	defWindowProc := user32.NewProc("DefWindowProcW")
	result, _, _ := defWindowProc.Call(uintptr(window), uintptr(message), wParam, lParam)
	return result
}

func (host *menuHost) showMenu() {
	setForegroundWindow := user32.NewProc("SetForegroundWindow")
	trackPopupMenu := user32.NewProc("TrackPopupMenu")
	const tpmRightAlign = 0x0008
	const tpmBottomAlign = 0x0020
	const tpmReturnCmd = 0x0100
	const tpmNonotify = 0x0080
	const tpmLeftBtn = 0x0000

	setForegroundWindow.Call(uintptr(host.window))
	chosen, _, _ := trackPopupMenu.Call(
		uintptr(host.menu),
		uintptr(tpmRightAlign|tpmBottomAlign|tpmReturnCmd|tpmNonotify|tpmLeftBtn),
		wParamFromMessage(),
		0,
		0,
		uintptr(host.window),
		0,
	)
	go host.dispatchMenu(uint32(chosen))
}

func wParamFromMessage() uintptr {
	getCursor := user32.NewProc("GetCursorPos")
	var point struct{ x, y int32 }
	getCursor.Call(uintptr(unsafe.Pointer(&point)))
	return uintptr(uint32(point.x)) | uintptr(uint32(point.y))<<16
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
	}
}

func (host *menuHost) run() error {
 getMessage := user32.NewProc("GetMessageW")
 translateMessage := user32.NewProc("TranslateMessage")
 dispatchMessage := user32.NewProc("DispatchMessageW")
 var msg struct {
	Window  windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Point   struct{ x, y int32 }
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
		if host.quitFlag {
			postQuitMessage()
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (host *menuHost) notify(op uint32) error {
	data := notifyIconData{
		Window:          host.window,
		ID:              host.iconToken,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmTrayCallback,
		Icon:            loadDefaultIcon(),
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
	host.quitFlag = true
	postQuitMessage()
}

// refreshMenu applies state to the tray tooltip (cheap, non-blocking).
func (host *menuHost) refreshMenu(state TrayState) {
	host.app.mu.Lock()
	defer host.app.mu.Unlock()
	// The static tooltip keeps the implementation simple; dynamic per-state
	// balloons can be layered on later without protocol changes.
}

func loadDefaultIcon() windows.Handle {
	loadIcon := user32.NewProc("LoadIconW")
	icon, _, _ := loadIcon.Call(0, 32512) // IDI_APPLICATION
	return windows.Handle(icon)
}

func postQuitMessage() {
	postQuit := user32.NewProc("PostQuitMessage")
	postQuit.Call(0)
}
