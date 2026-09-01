//go:build windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRA6WindowsMetadataRejectsJunctionRoot(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, victim).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v output=%s", err, output)
	}
	if _, err := LoadSnapshotDirectory(junction); err == nil {
		t.Fatal("static metadata junction root was accepted")
	}
}

func TestRA6WindowsMetadataRejectsJunctionCategory(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "routes")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, victim).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v output=%s", err, output)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil {
		t.Fatal("static metadata junction category was accepted")
	}
}
