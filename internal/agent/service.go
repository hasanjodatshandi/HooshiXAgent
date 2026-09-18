package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// WindowsServiceName is the SCM name of the Windows Agent service. It lives
// here, not only in internal/agent/svc, so the persistence spec the shipped
// binary emits and the service the runtime installer actually registers can
// never drift apart; internal/agent/svc.ServiceName aliases it.
const WindowsServiceName = "HooshiXAgent"

type ServiceSpec struct {
	OS       string `json:"os"`
	Name     string `json:"name"`
	Binary   string `json:"binary"`
	StateDir string `json:"state_dir"`
	Native   string `json:"native"`
}

func NativeServiceSpec(goos, binary, stateDir string) (ServiceSpec, error) {
	if strings.TrimSpace(binary) == "" || strings.TrimSpace(stateDir) == "" {
		return ServiceSpec{}, errors.New("binary and state directory are required")
	}
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return ServiceSpec{}, err
	}
	absoluteState, err := filepath.Abs(stateDir)
	if err != nil {
		return ServiceSpec{}, err
	}
	spec := ServiceSpec{OS: goos, Name: "hooshix-agent", Binary: absoluteBinary, StateDir: absoluteState}
	switch goos {
	case "linux":
		spec.Native = fmt.Sprintf(`[Unit]
Description=HooshiX Edge Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --state-dir %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=default.target
`, strconv.Quote(absoluteBinary), strconv.Quote(absoluteState), strconv.Quote(absoluteState))
	case "darwin":
		// Keep the emitted launchd foundation deterministic and inspectable rather than installing it here.
		spec.Native = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.hooshix.agent</string>
<key>ProgramArguments</key><array><string>%s</string><string>run</string><string>--state-dir</string><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
`, xmlEscape(absoluteBinary), xmlEscape(absoluteState))
	case "windows":
		// Windows Agent persistence is the LocalSystem SCM service registered by
		// `hooshix-agent service install` (internal/agent/svc.Install), started
		// by SCM at boot — NOT a logon-triggered task. An edge tunnel agent has
		// to serve its assigned routes on a device that may have no interactive
		// logon session, which a per-user logon task cannot do; a second
		// persistence mechanism on the same device would also race the service
		// for the state tree and the fixed loopback pairing port. This is
		// ADR-0014's accepted model, and this string is what the shipped binary
		// reports as its native persistence definition.
		//
		// The service command line deliberately carries no --state-dir: the
		// service resolves the machine-wide state directory itself through
		// ServiceStateDir(), so a second, per-invocation state path cannot exist.
		spec.Native = "sc.exe create " + WindowsServiceName + " binPath= " +
			scBinPath(absoluteBinary) + " start= auto DisplayName= \"HooshiX Edge Agent\" depend= Tcpip/Dnscache" +
			"\nsc.exe failure " + WindowsServiceName + " reset= 86400 actions= restart/5000"
	default:
		return ServiceSpec{}, fmt.Errorf("unsupported service platform %q", goos)
	}
	return spec, nil
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

// scBinPath renders the SCM service command line for `sc.exe create binPath=`.
// sc.exe parses the value itself, so a quoting backslash is required rather
// than Go string quoting, and the binary path must be quoted because it
// normally contains spaces (C:\Program Files\...).
func scBinPath(binary string) string {
	return `\"` + binary + `\" service run-service`
}
