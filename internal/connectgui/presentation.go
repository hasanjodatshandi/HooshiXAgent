package connectgui

import (
	"errors"
	"fmt"
	"net"
)

// Buttons is which window controls are live. The shell renders from it instead
// of deciding policy itself, so the rules are testable without Windows.
type Buttons struct {
	Connect    bool
	Disconnect bool
	OpenClient bool
}

// ButtonsFor derives the control state from the session snapshot.
//
// UDP never enables the Remote Desktop button: mstsc speaks TCP, and a tunnel
// that cannot carry the client the button launches must not offer it.
func ButtonsFor(status Status, disconnecting bool) Buttons {
	live := status.State == StateListening && !disconnecting
	return Buttons{
		Connect:    status.State != StateListening && !disconnecting,
		Disconnect: live,
		OpenClient: live && status.Protocol == "tcp",
	}
}

// StatusLabel is the short first line of the status area.
func StatusLabel(status Status, disconnecting bool) string {
	switch {
	case disconnecting:
		return "disconnecting"
	case status.State == StateListening:
		return fmt.Sprintf("listening on %s (%s)", status.Listen, status.Protocol)
	default:
		return string(status.State)
	}
}

// RDPTarget returns the address mstsc should dial for the active session. It
// re-checks loopback rather than trusting the snapshot: the string is handed to
// an external program, and only the local tunnel endpoint is safe to dial.
func RDPTarget(status Status) (string, error) {
	if status.State != StateListening {
		return "", errors.New("no active tunnel")
	}
	if status.Protocol != "tcp" {
		return "", fmt.Errorf("remote desktop needs a tcp tunnel, this one is %s", status.Protocol)
	}
	host, port, err := net.SplitHostPort(status.Listen)
	if err != nil {
		return "", fmt.Errorf("tunnel address %q is not host:port: %w", status.Listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("tunnel address %q is not loopback", status.Listen)
	}
	if port == "" {
		return "", fmt.Errorf("tunnel address %q has no port", status.Listen)
	}
	if ip.To4() == nil {
		// mstsc parses bare colons as IPv6 prefixes, so the literal must be bracketed.
		return "[" + host + "]:" + port, nil
	}
	return host + ":" + port, nil
}
