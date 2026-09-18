//go:build windows

package tray

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Status-tinted icon variants are generated at build time from the brand
// ICO (scripts/tint_ico.py via build-setup.ps1) and embedded so the tray
// shows tunnel health at a glance without any runtime asset dependencies.
var (
	//go:embed hooshix-green.ico
	iconGreen []byte
	//go:embed hooshix-yellow.ico
	iconYellow []byte
	//go:embed hooshix-red.ico
	iconRed []byte
)

// readiness describes how well the tunnel is doing, mapped to a color:
//
//   - green: the tunnel is connected;
//   - yellow: the agent service is running but the tunnel is not connected
//     (starting, reconnecting, or not paired yet);
//   - red: the tunnel is unusable — a terminal failure, or the agent service
//     itself is not running / cannot be queried.
//
// Service availability maps to red deliberately. This file always documented
// "red = terminal failure or the service being unreachable", but the code sent
// `service:unknown` and `service:stopped` to yellow along with every
// running-but-not-connected state, so the operator could not tell "the service
// is down" from "the service is up and merely unpaired" — the owner read the
// yellow of an unpaired agent as "the service failed to start".
type readiness int

const (
	readinessGreen readiness = iota
	readinessYellow
	readinessRed
)

// readinessFromState classifies a status snapshot into an icon color.
func readinessFromState(state TrayState) readiness {
	switch {
	case isUpState(state):
		return readinessGreen
	case serviceUnavailable(state) || hasSuffix(state.Phase, "terminal"):
		return readinessRed
	default:
		return readinessYellow
	}
}

// serviceUnavailable reports whether the snapshot says the agent service
// itself is unusable: SCM could not be queried, or the service is not running.
// An empty phase is the pre-first-poll snapshot, which is unknown rather than
// known-bad, so it is not reported as unavailable.
func serviceUnavailable(state TrayState) bool {
	return state.Phase == "service:unknown" || state.Phase == "service:stopped"
}

// hasSuffix is strings.HasSuffix without re-importing strings in a file that
// mostly deals with Win32 plumbing.
func hasSuffix(value, suffix string) bool {
	return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
}

// iconCache turns embedded ICO bytes into HICONs once and reuses them for
// every state change; icon creation is expensive and Shell_NotifyIcon only
// needs the handle. Handles live for the tray process lifetime, matching
// the icon they replace (the class icon is never freed either).
type iconCache struct {
	mu     sync.Mutex
	icons  map[readiness]windows.Handle
	logger *slog.Logger
}

var trayIcons = &iconCache{icons: make(map[readiness]windows.Handle), logger: nil}

// hiconFor returns the cached HICON for the readiness, creating it from the
// embedded ICO bytes on first use (small size: the tray draws 16×16).
func (cache *iconCache) hiconFor(level readiness) windows.Handle {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if icon, ok := cache.icons[level]; ok && icon != 0 {
		return icon
	}
	var data []byte
	switch level {
	case readinessGreen:
		data = iconGreen
	case readinessRed:
		data = iconRed
	default:
		data = iconYellow
	}
	icon, err := createHIconFromICO(data, 16)
	if err != nil {
		if cache.logger != nil {
			cache.logger.Warn("decode status icon failed; keeping application icon", "error", err)
		}
		cache.icons[level] = 0
		return 0
	}
	cache.icons[level] = icon
	return icon
}

// createHIconFromICO picks the best frame from an ICO container and creates
// an HICON via CreateIconFromResourceEx (no filesystem or GDI file loading).
func createHIconFromICO(data []byte, size int) (windows.Handle, error) {
	if len(data) < 6 {
		return 0, fmt.Errorf("ico truncated")
	}
	reserved, iconType, count := uint16(data[0])|uint16(data[1])<<8, uint16(data[2])|uint16(data[3])<<8, uint16(data[4])|uint16(data[5])<<8
	_ = reserved
	if iconType != 1 {
		return 0, fmt.Errorf("not an ICO container")
	}
	if count == 0 {
		return 0, fmt.Errorf("ico has no frames")
	}
	best := -1
	bestDelta := int(^uint(0) >> 1) // max int
	for index := 0; index < int(count); index++ {
		entry := data[6+16*index : 6+16*(index+1)]
		width := int(entry[0])
		if width == 0 {
			width = 256
		}
		delta := width - size
		if delta < 0 {
			delta = -delta
		}
		if delta < bestDelta {
			bestDelta = delta
			best = index
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("no usable ico frame")
	}
	entry := data[6+16*best : 6+16*(best+1)]
	imgOff := uint32(entry[12]) | uint32(entry[13])<<8 | uint32(entry[14])<<16 | uint32(entry[15])<<24
	imgSize := uint32(entry[8]) | uint32(entry[9])<<8 | uint32(entry[10])<<16 | uint32(entry[11])<<24
	if int(imgOff+imgSize) > len(data) {
		return 0, fmt.Errorf("ico frame out of range")
	}
	frame := data[imgOff : imgOff+imgSize]
	if !bytes.HasPrefix(frame, []byte("\x89PNG\r\n\x1a\n")) {
		// BMP frames carry a doubled height; CreateIconFromResourceEx does
		// not accept them directly. All build-generated frames are PNG, so
		// this only guards against a hand-authored source file.
		return 0, fmt.Errorf("unsupported bmp ico frame")
	}
	var pngHeader [8]byte
	copy(pngHeader[:], frame)
	createIcon := user32.NewProc("CreateIconFromResourceEx")
	icon, _, callErr := createIcon.Call(
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)),
		1, // fIcon
		0x00030000,
		uintptr(size),
		uintptr(size),
		0x00000080, // LR_DEFAULTCOLOR
	)
	if icon == 0 {
		return 0, fmt.Errorf("CreateIconFromResourceEx: %w", callErr)
	}
	_ = pngHeader
	return windows.Handle(icon), nil
}

// statusIcon returns the HICON for the readiness level, falling back to the
// embedded application icon when tinted variants are unavailable.
func statusIcon(level readiness) windows.Handle {
	if icon := trayIcons.hiconFor(level); icon != 0 {
		return icon
	}
	return loadAppIcon(0)
}
