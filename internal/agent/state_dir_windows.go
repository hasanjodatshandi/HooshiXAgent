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
// can leave an empty one), so a state marker, a config.json, or a settings
// pointer must be present. The pointer counts because Setup.exe writes it while
// redirecting the settings file into the installation directory: after that,
// ProgramData legitimately holds no config.json of its own.
func serviceInstallationPresent() bool {
	dir := ServiceStateDir()
	for _, name := range []string{stateMarkerName, settingsFileName, settingsLocationName} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
