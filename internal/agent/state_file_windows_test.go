//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// daclString returns the SDDL form of a path's DACL.
func daclString(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL of %s: %v", path, err)
	}
	sddl := descriptor.String()
	if sddl == "" {
		t.Fatalf("security descriptor of %s has no SDDL form", path)
	}
	return sddl
}

// setTestDirectoryDACL installs a PROTECTED DACL with inheritable ACEs on a
// directory, so that files created inside it inherit a known set of ACEs.
func setTestDirectoryDACL(t *testing.T, dir string) {
	t.Helper()
	// Include the actual test identity: an unelevated administrator's BA
	// membership is deny-only and cannot create the baseline otherwise.
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + tokenUser.User.Sid.String() + ")(A;OICI;GRGX;;;BU)"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("build directory DACL: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("extract directory DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("apply directory DACL: %v", err)
	}
}

// TestStateFileWritesDoNotWidenTheDACL proves the agent's state-file write path
// leaves access rights exactly as the platform (installer ACL / inheritance)
// set them. Before the fix grantAdministratorsRead() ran on every write AND
// every read and ADDED two explicit Full-Access ACEs (SYSTEM, Administrators)
// while keeping all inherited ACEs, silently widening access and discarding
// the SetNamedSecurityInfo return value so failures were invisible.
func TestStateFileWritesDoNotWidenTheDACL(t *testing.T) {
	dir := t.TempDir()
	setTestDirectoryDACL(t, dir)

	// Baseline: a plain write in the same directory inherits the directory's
	// ACEs and nothing else.
	baseline := filepath.Join(dir, "baseline.bin")
	if err := os.WriteFile(baseline, []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantDACL := daclString(t, baseline)

	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setTestDirectoryDACL(t, stateDir)
	secret := filepath.Join(stateDir, "secrets.dpapi")
	if err := writePrivateFile(stateDir, secret, []byte("dpapi-blob")); err != nil {
		t.Fatal(err)
	}
	gotDACL := daclString(t, secret)
	if gotDACL != wantDACL {
		t.Fatalf("the state write path changed the file DACL:\n got=%s\nwant=%s", gotDACL, wantDACL)
	}
	if strings.Contains(gotDACL, "(A;;FA;;;BA)") || strings.Contains(gotDACL, "(A;;FA;;;SY)") {
		t.Fatalf("state write added explicit Full-Access ACEs: %s", gotDACL)
	}

	// Reading must not mutate the DACL either: the read path used to call the
	// same widening helper.
	before := daclString(t, secret)
	if _, err := readStateFile(secret); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivateStateFile(secret); err != nil {
		t.Fatal(err)
	}
	if after := daclString(t, secret); after != before {
		t.Fatalf("the state read path changed the file DACL:\nbefore=%s\n after=%s", before, after)
	}
}

// TestProtectPrivateStateFileRejectsNonRegularFiles proves the remaining check
// in protectPrivateStateFile reports an error instead of silently succeeding:
// a directory or a reparse point must never be treated as protected state.
func TestProtectPrivateStateFileRejectsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := protectPrivateStateFile(dir); err == nil {
		t.Fatal("protectPrivateStateFile accepted a directory")
	}
	if err := protectPrivateStateFile(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("protectPrivateStateFile accepted a missing file")
	}
	// A write over a directory path must be surfaced as an error too, rather
	// than reported as a successful private write.
	if err := writePrivateFile(dir, dir, []byte("x")); err == nil {
		t.Fatal("writePrivateFile reported success over a directory")
	}
}
