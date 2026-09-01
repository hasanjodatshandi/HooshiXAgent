package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRA6StaticMetadataRejectsSymlinkAndNonRegularJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reparse behavior is covered by native Agent/platform and cross-platform regular-file helper tests")
	}
	root := t.TempDir()
	for _, category := range []string{"authorizations", "routes", "revocations"} {
		if err := os.Mkdir(filepath.Join(root, category), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "routes", "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil {
		t.Fatal("static metadata symlink was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	directoryJSON := filepath.Join(root, "routes", "directory.json")
	if err := os.Mkdir(directoryJSON, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("non-regular static metadata must fail closed, got %v", err)
	}
}

func TestRA6LiveMetadataReadRejectsSymlinkAtOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not guaranteed on Windows CI")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readRegularFileBounded(link, 1024); err == nil {
		t.Fatal("live metadata symlink was accepted")
	}
}

func TestRA6MetadataRegularReaderRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := readRegularFileBounded(dir, 1024); err == nil {
		t.Fatal("metadata directory was accepted as regular file")
	}
}

func TestRA6StaticMetadataRejectsSymlinkDirectoryComponents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows junction coverage is in ra6_filesystem_windows_test.go")
	}
	base := t.TempDir()
	victimRoot := filepath.Join(base, "victim-root")
	if err := os.Mkdir(victimRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(base, "root-link")
	if err := os.Symlink(victimRoot, rootLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadSnapshotDirectory(rootLink); err == nil {
		t.Fatal("static metadata symlink root was accepted")
	}

	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	victimCategory := filepath.Join(base, "victim-category")
	if err := os.Mkdir(victimCategory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimCategory, filepath.Join(root, "routes")); err != nil {
		t.Skipf("category symlink unavailable: %v", err)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil {
		t.Fatal("static metadata symlink category was accepted")
	}
}
