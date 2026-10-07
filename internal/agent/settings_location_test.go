package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSettingsPointerMovesTheEditableFileNextToTheProgram is the core of the
// operator workflow: Setup.exe redirects the settings file into the
// installation directory, and every read and write path follows that pointer.
func TestSettingsPointerMovesTheEditableFileNextToTheProgram(t *testing.T) {
	stateDir := t.TempDir()
	installDir := t.TempDir()
	if err := validateStateDirectoryPath(installDir, true); err != nil {
		t.Skipf("this machine's temp directory cannot host an installation directory: %v", err)
	}
	target := filepath.Join(installDir, settingsFileName)

	if err := WriteSettingsLocation(stateDir, target); err != nil {
		t.Fatal(err)
	}
	if got := ConfigPath(stateDir); !samePath(got, target) {
		t.Fatalf("ConfigPath = %q, want the redirected %q", got, target)
	}

	// A writer that only knows the state directory must land on the settings
	// file, not create a second one the running Agent never reads.
	err := MutateConfig(stateDir, func(config *Config) error {
		config.GatewayURL = "wss://tunnel.hooshix-agent.ir/agent/v1/connect"
		config.DeviceID = "device-pointer-001"
		config.AuthorizationID = "auth-pointer-001"
		config.TokenID = "token-pointer-001"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the settings file was not written next to the program: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsFileName)); !os.IsNotExist(err) {
		t.Fatalf("a second settings file appeared inside the state directory: %v", err)
	}

	config, err := LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "wss://tunnel.hooshix-agent.ir/agent/v1/connect" {
		t.Fatalf("redirected settings were not read back: %+v", config)
	}

	// The redirected file is replaced in place, and the pointer itself stays
	// inside the protected state directory.
	if err := WriteSettingsLocation(stateDir, target); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(installDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != settingsFileName {
			t.Fatalf("the settings write left %q behind in the installation directory", entry.Name())
		}
	}
}

// TestSettingsPointerIsOnlyObeyedWhenItIsUnambiguous proves a bad pointer
// degrades to the state directory instead of silently moving configuration:
// the Agent must never trust a path it would not have accepted at install time.
func TestSettingsPointerIsOnlyObeyedWhenItIsUnambiguous(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"relative path", "config.json"},
		{"wrong file name", filepath.Join(t.TempDir(), "settings.json")},
		{"empty", "   "},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(stateDir, settingsLocationName), []byte(testCase.value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ConfigPath(stateDir); !samePath(got, filepath.Join(stateDir, settingsFileName)) {
				t.Fatalf("an unusable pointer redirected the settings file to %q", got)
			}
		})
	}

	// A pointer that names the state directory's own settings file is a no-op,
	// and must not be mistaken for a redirect.
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, settingsLocationName), []byte(filepath.Join(stateDir, settingsFileName)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ConfigPath(stateDir); !samePath(got, filepath.Join(stateDir, settingsFileName)) {
		t.Fatalf("a self-referential pointer resolved to %q", got)
	}
}

func TestWriteSettingsLocationRefusesPathsItCannotTrust(t *testing.T) {
	stateDir := t.TempDir()
	rejected := []string{
		"relative/config.json",
		filepath.Join(t.TempDir(), "agent.json"),
		"",
	}
	for _, path := range rejected {
		if err := WriteSettingsLocation(stateDir, path); err == nil {
			t.Fatalf("WriteSettingsLocation accepted %q", path)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsLocationName)); !os.IsNotExist(err) {
		t.Fatal("a rejected pointer must not be persisted")
	}
}

// TestRestoreStateFileHonoursTheRedirectedLocation is the rollback half: a state
// transaction that snapshots the settings file must restore it to the
// redirected path, because writing it back into the state directory would
// silently leave the running Agent on the pre-mutation settings.
func TestRestoreStateFileHonoursTheRedirectedLocation(t *testing.T) {
	stateDir := t.TempDir()
	installDir := t.TempDir()
	if err := validateStateDirectoryPath(installDir, true); err != nil {
		t.Skipf("this machine's temp directory cannot host an installation directory: %v", err)
	}
	target := filepath.Join(installDir, settingsFileName)
	if err := WriteSettingsLocation(stateDir, target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"version":1,"update_channel":"stable","gateway_url":"wss://tunnel.hooshix-agent.ir/agent/v1/connect"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	transactionDir := t.TempDir()
	backup := filepath.Join(transactionDir, "config.before")
	existed, err := snapshotStateFile(target, backup)
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Fatal("the redirected settings file was not snapshotted")
	}
	if err := os.WriteFile(target, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreStateFile(stateDir, target, backup, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "tunnel.hooshix-agent.ir") {
		t.Fatalf("rollback did not restore the redirected settings file: %q", data)
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsFileName)); !os.IsNotExist(err) {
		t.Fatal("rollback wrote a settings file into the state directory")
	}
}
