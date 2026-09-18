//go:build windows

package agent

import (
	"os"
	"path/filepath"
)

// ServiceStateDir returns the machine-wide state directory owned by the
// HooshiXAgent Windows service (LocalSystem). It is the authoritative location
// once a service installation exists.
func ServiceStateDir() string {
	if programData := os.Getenv("ProgramData"); programData != "" {
		return filepath.Join(programData, "HooshiXAgent")
	}
	return `C:\ProgramData\HooshiXAgent`
}

// serviceInstallationPresent reports whether an installed service already owns
// state at ServiceStateDir. The bare directory is not proof (a failed install
// can leave an empty one), so a state marker or config.json must be present.
func serviceInstallationPresent() bool {
	dir := ServiceStateDir()
	for _, name := range []string{stateMarkerName, "config.json"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
