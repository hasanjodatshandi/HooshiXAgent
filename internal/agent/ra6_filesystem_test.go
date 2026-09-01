package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRA6StateRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows parent reparse behavior is covered by native junction smoke")
	}
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(base, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	stateDir := filepath.Join(linkParent, "nested", "state")
	if _, err := NormalizeStateDir(stateDir); err == nil || !strings.Contains(err.Error(), "component") {
		t.Fatalf("state path beneath symlink parent accepted: %v", err)
	}
	if err := ensurePrivateDir(stateDir); err == nil {
		t.Fatal("private state creation traversed symlink parent")
	}
	if _, err := os.Lstat(filepath.Join(realParent, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe parent traversal created victim content: %v", err)
	}
}

func TestRA6StateReaderRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path); err == nil {
		t.Fatal("state directory accepted as regular file")
	}
}

func TestRA6UnixPrivatePermissionsAreExact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission boundary is DPAPI CurrentUser plus inherited ACLs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory permissions=%04o want=0700", info.Mode().Perm())
	}
	path := filepath.Join(dir, "private.json")
	if err := writePrivateFile(dir, path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private file permissions=%04o want=0600", info.Mode().Perm())
	}
}

func TestRA6SecretStoreRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	secretPath := platformSecretPath(dir)
	if err := os.Mkdir(secretPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlatformSecretStore(dir).Load(); err == nil {
		t.Fatal("non-regular secret store object was accepted")
	}
}
