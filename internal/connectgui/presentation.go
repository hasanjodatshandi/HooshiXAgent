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
//
// The button also goes away while a client is already attached. A second
// Remote Desktop window against the same tunnel makes Windows arbitrate its one
// interactive session away from the first, which the operator experiences as a
// session that dies and reconnects every few seconds.
func ButtonsFor(status Status, disconnecting bool) Buttons {
	live := status.State == StateListening && !disconnecting
	return Buttons{
		Connect:    status.State != StateListening && !disconnecting,
		Disconnect: live,
		OpenClient: live && status.Protocol == "tcp" && status.Flows == 0,
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

// IdleMessage is the instruction line for a tunnel that has never been started.
// There are two because the window has two shapes: an operator who arrived with
// nothing has to paste a bundle, while one whose saved bundle opened has no text
// box on screen, and telling them to paste into it would describe a control they
// cannot see.
func IdleMessage(hasSaved bool) string {
	if hasSaved {
		return "press Connect to open the tunnel with the saved bundle"
	}
	return "paste a connect bundle and press Connect"
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
