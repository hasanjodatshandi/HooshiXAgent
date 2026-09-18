//go:build !windows

package agent

// ServiceStateDir mirrors the per-user default off Windows: there is no
// separate service account with its own state root.
func ServiceStateDir() string {
	dir, err := defaultLocalStateDir()
	if err != nil {
		return "."
	}
	return dir
}

// serviceInstallationPresent is always false off Windows.
func serviceInstallationPresent() bool { return false }
