package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteSettingsOutsideStateReplacesTheFileAndKeepsTheDirectoryClean covers
// the redirected settings file: it lives beside the installed binaries, not in
// the state directory, so it is written by its own path and must never leave a
// temp file behind in the installation directory.
func TestWriteSettingsOutsideStateReplacesTheFileAndKeepsTheDirectoryClean(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(root, "config.json")
	for _, payload := range []string{"first\n", "second\n"} {
		if err := writeStateFile(stateDir, settings, []byte(payload)); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		data, err := os.ReadFile(settings)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != payload {
			t.Fatalf("settings after replace = %q, want %q", data, payload)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-hooshix-settings-") {
			t.Fatalf("settings writer left %q in the installation directory", entry.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("the redirected write also touched the state directory: %v", err)
	}
}

// TestWriteSettingsOutsideStateRefusesUnusableTargets pins the fail-closed
// checks that protect the installed binaries' directory from a planted link or
// a colliding directory, and the size bound that keeps the file readable by
// the same bounded reader that loads it.
func TestWriteSettingsOutsideStateRefusesUnusableTargets(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(root, "looks-like-settings")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStateFile(stateDir, directory, []byte("x\n")); err == nil {
		t.Fatal("the writer replaced a directory")
	}

	oversized := make([]byte, maxSettingsFileBytes+1)
	if err := writeStateFile(stateDir, filepath.Join(root, "config.json"), oversized); err == nil {
		t.Fatal("an oversized settings file was accepted")
	} else if !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized error %q does not name the bound", err)
	}
	if _, err := os.Stat(filepath.Join(root, "config.json")); !os.IsNotExist(err) {
		t.Fatal("a refused write still created the settings file")
	}

	link := filepath.Join(root, "link-settings")
	if err := os.Symlink(filepath.Join(root, "elsewhere"), link); err == nil {
		if err := writeStateFile(stateDir, link, []byte("x\n")); err == nil {
			t.Fatal("the writer followed a symlinked settings file")
		}
	} else if !os.IsNotExist(err) && !strings.Contains(err.Error(), "privilege") && !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("unexpected symlink setup failure: %v", err)
	}

	missingDirectory := filepath.Join(root, "absent", "config.json")
	if err := writeStateFile(stateDir, missingDirectory, []byte("x\n")); err == nil {
		t.Fatal("a settings pointer into a missing directory was accepted")
	}
}
