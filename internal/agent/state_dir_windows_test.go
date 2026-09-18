//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultStateDirPrefersInstalledServiceStateDir pins the CLI's default
// state resolution. Before the fix the CLI always defaulted to
// %LOCALAPPDATA%\HooshiXAgent while the service used
// %ProgramData%\HooshiXAgent, so an operator following the CLI help on a
// machine with the service installed silently created a SECOND identity in
// their profile and registered the wrong public key with the panel.
func TestDefaultStateDirPrefersInstalledServiceStateDir(t *testing.T) {
	programData := t.TempDir()
	localAppData := t.TempDir()
	t.Setenv("ProgramData", programData)
	t.Setenv("LOCALAPPDATA", localAppData)

	perUser := filepath.Join(localAppData, "HooshiXAgent")
	serviceDir := ServiceStateDir()
	if serviceDir != filepath.Join(programData, "HooshiXAgent") {
		t.Fatalf("ServiceStateDir()=%q want under %q", serviceDir, programData)
	}

	// No service installation: the per-user directory is the default.
	got, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != perUser {
		t.Fatalf("DefaultStateDir()=%q want the per-user directory %q", got, perUser)
	}

	// A bare directory (a failed install) is not an installation.
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err = DefaultStateDir(); err != nil || got != perUser {
		t.Fatalf("an empty service directory changed the default: %q %v", got, err)
	}

	// A service installation owns state there: that directory wins.
	if err := os.WriteFile(filepath.Join(serviceDir, stateMarkerName), stateMarkerContents, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = DefaultStateDir(); err != nil || got != serviceDir {
		t.Fatalf("DefaultStateDir()=%q want the service directory %q (err=%v)", got, serviceDir, err)
	}
	// NormalizeStateDir("") must route through the same decision: it is what
	// every CLI command calls when --state-dir is omitted.
	normalized, err := NormalizeStateDir("")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != serviceDir {
		t.Fatalf("NormalizeStateDir(\"\")=%q want %q", normalized, serviceDir)
	}

	// An explicit --state-dir always wins over the service directory.
	explicit := t.TempDir()
	normalized, err = NormalizeStateDir(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(normalized, explicit) {
		t.Fatalf("NormalizeStateDir(explicit)=%q want %q", normalized, explicit)
	}
}
