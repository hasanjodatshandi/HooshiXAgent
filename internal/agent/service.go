package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

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
	quotedCommand := strconv.Quote(absoluteBinary) + " run --state-dir " + strconv.Quote(absoluteState)

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
		spec.Native = "sc.exe create HooshiXAgent start= auto binPath= " + strconv.Quote(quotedCommand)
	default:
		return ServiceSpec{}, fmt.Errorf("unsupported service platform %q", goos)
	}
	return spec, nil
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}
