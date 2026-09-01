//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRA6WindowsStateRejectsJunctionParent(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, victim).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v output=%s", err, output)
	}
	stateDir := filepath.Join(junction, "nested", "state")
	if _, err := NormalizeStateDir(stateDir); err == nil {
		t.Fatal("state path beneath Windows junction parent was accepted")
	}
	if err := ensurePrivateDir(stateDir); err == nil {
		t.Fatal("state creation traversed Windows junction parent")
	}
	if _, err := os.Stat(filepath.Join(victim, "nested")); !os.IsNotExist(err) {
		t.Fatalf("junction traversal created victim content: %v", err)
	}
}
