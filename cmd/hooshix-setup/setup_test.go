//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestUserStateDirsTargetTheInteractiveUser proves uninstall resolves the
// per-user state from the INTERACTIVE desktop user's profile, not from the
// elevated installer account's %LOCALAPPDATA%. Before the fix the cleanup
// targeted the elevated account (or failing that, nothing the desktop user
// owned), so the tray's logs and per-user state survived on the real user's
// machine.
func TestUserStateDirsTargetTheInteractiveUser(t *testing.T) {
	user, err := interactiveUser()
	if err != nil {
		t.Skipf("no interactive desktop user in this session: %v", err)
	}
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		t.Skipf("resolve interactive user SID: %v", err)
	}
	wantProfile := profileLocalAppData(sid)
	if wantProfile == "" {
		t.Skipf("no ProfileList entry for %s", sid)
	}
	want := filepath.Join(wantProfile, "HooshiXAgent")
	dirs := userStateDirs()
	found := false
	for _, dir := range dirs {
		if dir == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("userStateDirs()=%v does not include the interactive user's state directory %s", dirs, want)
	}
}

// TestProfileLocalAppDataReadsTheRegistry proves the profile lookup uses the
// Windows mapping for the SID rather than an environment variable of the
// (elevated) caller.
func TestProfileLocalAppDataReadsTheRegistry(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	profile := profileLocalAppData(sid)
	if profile == "" {
		t.Skip("no ProfileList entry for LocalSystem in this image")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(), registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	imagePath, _, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(imagePath, "AppData", "Local"); !strings.EqualFold(profile, want) {
		t.Fatalf("profileLocalAppData=%q want %q", profile, want)
	}
}

// TestServiceStateDirIgnoresTheEnvironment proves the elevated installer and
// uninstaller resolve the machine-wide state directory through the OS
// known-folder API instead of %ProgramData%. An environment variable is
// process input, and this path is a recursive-delete target, so a poisoned
// ProgramData must not be able to redirect it.
func TestServiceStateDirIgnoresTheEnvironment(t *testing.T) {
	t.Setenv("ProgramData", `C:\attacker-chosen`)
	t.Setenv("LOCALAPPDATA", `C:\attacker-chosen-local`)

	for name, resolve := range map[string]func() (string, error){
		"installer":   serviceStateDir,
		"uninstaller": stateDataDir,
	} {
		resolved, err := resolve()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(strings.ToLower(resolved), "attacker-chosen") {
			t.Fatalf("%s resolved the state directory from the environment: %s", name, resolved)
		}
		if filepath.Base(resolved) != stateDirName {
			t.Fatalf("%s state directory %q does not end in %q", name, resolved, stateDirName)
		}
		want, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(resolved, filepath.Join(want, stateDirName)) {
			t.Fatalf("%s state directory=%q want %q", name, resolved, filepath.Join(want, stateDirName))
		}
	}

	// The per-user cleanup list must likewise ignore the elevated account's
	// environment for its own LocalAppData entry.
	dirs := userStateDirs()
	for _, dir := range dirs {
		if strings.Contains(strings.ToLower(dir), "attacker-chosen-local") {
			t.Fatalf("userStateDirs() derived a delete target from the environment: %v", dirs)
		}
	}
}

// TestGuardOwnedStateDirFailsClosed proves the elevated uninstaller applies the
// same ownership-marker rule as the packaged uninstallers before any recursive
// delete: only a directory the Agent itself marked may be removed.
func TestGuardOwnedStateDirFailsClosed(t *testing.T) {
	base := t.TempDir()

	empty := filepath.Join(base, "empty", "HooshiXAgent")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guardOwnedStateDir(empty); err != nil {
		t.Fatalf("empty state directory rejected: %v", err)
	}

	owned := filepath.Join(base, "owned", "HooshiXAgent")
	if err := os.MkdirAll(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, stateMarkerName), []byte(stateMarkerVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "pairing.capability"), []byte("capability"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardOwnedStateDir(owned); err != nil {
		t.Fatalf("owned state directory rejected: %v", err)
	}

	unowned := filepath.Join(base, "unowned", "HooshiXAgent")
	if err := os.MkdirAll(unowned, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unowned, "somebody-elses-data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardOwnedStateDir(unowned); err == nil {
		t.Fatal("unowned non-empty state directory was accepted for removal")
	}

	invalid := filepath.Join(base, "invalid", "HooshiXAgent")
	if err := os.MkdirAll(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, stateMarkerName), []byte("hooshix-agent-state-v0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardOwnedStateDir(invalid); err == nil {
		t.Fatal("state directory with an invalid marker was accepted for removal")
	}

	regularFile := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardOwnedStateDir(regularFile); err == nil {
		t.Fatal("regular file was accepted as a state directory")
	}

	missing := filepath.Join(base, "missing", "HooshiXAgent")
	if err := guardOwnedStateDir(missing); err != nil {
		t.Fatalf("absent state directory rejected: %v", err)
	}
}

// TestRemoveAllStateRefusesUnownedTrees proves the destructive entry point the
// uninstaller uses cannot delete a directory that does not carry the Agent's
// marker, even when it is handed one by mistake.
func TestRemoveAllStateRefusesUnownedTrees(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim", "HooshiXAgent")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(victim, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeAllState(victim); err == nil {
		t.Fatal("removeAllState accepted an unowned non-empty directory")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("unowned directory was modified: %v", err)
	}

	if err := os.WriteFile(filepath.Join(victim, stateMarkerName), []byte(stateMarkerVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeAllState(victim); err != nil {
		t.Fatalf("owned state directory was not removed: %v", err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("owned state directory still present: %v", err)
	}
}

// TestRecaptureStateOwnershipRejectsMalformedInputs proves the recovery
// descriptor is validated before any privilege is enabled or any object is
// modified: a malformed SID must fail without touching the tree, whether or not
// the caller happens to be elevated.
func TestRecaptureStateOwnershipRejectsMalformedInputs(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(marker, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := recaptureStateOwnership(root, "*not-a-sid")
	if err == nil {
		t.Fatal("recaptureStateOwnership accepted a malformed SID")
	}
	if !strings.Contains(err.Error(), "security descriptor") {
		t.Fatalf("unexpected error for a malformed SID: %v", err)
	}
	data, readErr := os.ReadFile(marker)
	if readErr != nil || string(data) != "untouched" {
		t.Fatalf("the tree was modified before validation: %q %v", data, readErr)
	}
}

// TestRecaptureStateOwnershipNeedsElevationOrAppliesTheRecoveryDACL documents
// the two reachable outcomes at unit level. Without the elevated installer
// token the function must refuse explicitly (a silent no-op is what leaves a
// SYSTEM-only state tree undeletable); with it, the recovery DACL must name
// SYSTEM, Administrators and the target user.
func TestRecaptureStateOwnershipNeedsElevationOrAppliesTheRecoveryDACL(t *testing.T) {
	root := t.TempDir()
	user, err := interactiveUser()
	if err != nil {
		t.Skipf("no interactive user: %v", err)
	}
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		t.Skip(err)
	}
	err = recaptureStateOwnership(root, "*"+sid.String())
	if err != nil {
		if !strings.Contains(err.Error(), "elevated installer token") {
			t.Fatalf("unexpected failure: %v", err)
		}
		// Not elevated: the tree must be intact and still writable.
		if writeErr := os.WriteFile(filepath.Join(root, "writable.txt"), []byte("x"), 0o600); writeErr != nil {
			t.Fatalf("the refusal damaged the tree: %v", writeErr)
		}
		return
	}
	// Elevated: the recovery DACL is applied to every entry.
	descriptor, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	// The SDDL writer emits well-known SIDs as two-letter aliases (SY =
	// LocalSystem, BA = Administrators), so both spellings are accepted.
	expected := []struct {
		name    string
		matches []string
	}{
		{"the target user", []string{sid.String()}},
		{"LocalSystem", []string{";;;SY)", "S-1-5-18"}},
		{"Administrators", []string{";;;BA)", "S-1-5-32-544"}},
	}
	for _, want := range expected {
		found := false
		for _, candidate := range want.matches {
			if strings.Contains(sddl, candidate) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("recovery DACL %s is missing %s", sddl, want.name)
		}
	}
}

// TestVerifyPayloadDigestRefusesAnythingButTheManifestedBytes proves Setup can
// never promote an embedded payload that does not match the manifest its own
// distribution build recorded: a tampered, truncated or unlisted binary is
// rejected before anything is written to the install directory.
func TestVerifyPayloadDigestRefusesAnythingButTheManifestedBytes(t *testing.T) {
	agent := []byte("embedded-agent-binary")
	tray := []byte("embedded-tray-binary")
	digest := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	manifest := digest(agent) + "  hooshix-agent.exe\n" + digest(tray) + " *hooshix-agent-tray.exe\n"

	if err := verifyPayloadDigest(manifest, "hooshix-agent.exe", agent); err != nil {
		t.Fatalf("valid agent payload rejected: %v", err)
	}
	// Binary-mode entries ("*name") must be recognised too.
	if err := verifyPayloadDigest(manifest, "hooshix-agent-tray.exe", tray); err != nil {
		t.Fatalf("valid tray payload rejected: %v", err)
	}
	if err := verifyPayloadDigest(manifest, "hooshix-agent.exe", []byte("tampered-agent-binary")); err == nil {
		t.Fatal("tampered payload was accepted")
	}
	// A payload with no manifest entry must fail closed rather than install.
	if err := verifyPayloadDigest(manifest, "hooshix-agent-extra.exe", agent); err == nil {
		t.Fatal("payload without a manifest entry was accepted")
	}
	if err := verifyPayloadDigest("", "hooshix-agent.exe", agent); err == nil {
		t.Fatal("missing manifest was accepted")
	}
	// The digest is case-insensitive and the entry lookup tolerates the "./"
	// prefix some checksum tools emit.
	upper := strings.ToUpper(digest(agent)) + "  ./hooshix-agent.exe\n"
	if err := verifyPayloadDigest(upper, "hooshix-agent.exe", agent); err != nil {
		t.Fatalf("upper-case/./-prefixed manifest entry rejected: %v", err)
	}
}

// TestWriteUTF16LEToWritesBOMAndPayload proves the task XML handed to
// schtasks.exe is a BOM-prefixed UTF-16LE document, which schtasks requires.
func TestWriteUTF16LEToWritesBOMAndPayload(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "task-*.xml")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := writeUTF16LETo(file, "<Task>é</Task>"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0xff || data[1] != 0xfe {
		t.Fatalf("missing UTF-16LE BOM: % x", data[:min(4, len(data))])
	}
	units := make([]uint16, 0, (len(data)-2)/2)
	for index := 2; index+1 < len(data); index += 2 {
		units = append(units, binary.LittleEndian.Uint16(data[index:index+2]))
	}
	if got, want := string(utf16.Decode(units)), "<Task>é</Task>"; got != want {
		t.Fatalf("decoded %q want %q", got, want)
	}
}

// TestStageTaskXMLUsesAUniquePath proves the staged task XML is written to a
// fresh random path on every run. The previous implementation wrote a fixed
// "%TEMP%\\hooshix-tray-task.xml" from an ELEVATED process with os.WriteFile
// (no O_EXCL), so a process running as the same account could pre-create or
// replace the file the installer then handed to schtasks.exe.
func TestStageTaskXMLUsesAUniquePath(t *testing.T) {
	first, err := stageTaskXML("<Task/>")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(first)
	second, err := stageTaskXML("<Task/>")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(second)
	if first == second {
		t.Fatalf("stageTaskXML reused the path %q", first)
	}
	if filepath.Base(first) == "hooshix-tray-task.xml" {
		t.Fatalf("stageTaskXML used the predictable legacy path %q", first)
	}
	if !strings.EqualFold(filepath.Dir(first), filepath.Clean(os.TempDir())) {
		t.Fatalf("stageTaskXML wrote outside the temp directory: %q", first)
	}
	for _, path := range []string{first, second} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("staged file %s: %v", path, err)
		}
		if len(data) < 2 || data[0] != 0xff || data[1] != 0xfe {
			t.Fatalf("staged file %s is not UTF-16LE with a BOM", path)
		}
	}
}

// TestRollbackFilesRestoresPreviousBinaryAndRemovesNewOnes proves the staging
// rollback puts a replaced binary back and deletes a newly installed one, so a
// failed install cannot leave a half-updated directory.
func TestRollbackFilesRestoresPreviousBinaryAndRemovesNewOnes(t *testing.T) {
	dir := t.TempDir()
	replaced := filepath.Join(dir, "replaced.exe")
	backup := replaced + ".previous"
	if err := os.WriteFile(backup, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replaced, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(dir, "added.exe")
	if err := os.WriteFile(added, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	rollbackFiles(map[string]string{replaced: backup, added: ""})

	data, err := os.ReadFile(replaced)
	if err != nil {
		t.Fatalf("the replaced binary was not restored: %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("restored contents %q want %q", data, "old")
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Fatalf("a newly installed binary survived the rollback: %v", err)
	}
}

// TestXMLEscapeProtectsTheTaskDefinition proves interpolated user and path
// values cannot break out of the task XML.
func TestXMLEscapeProtectsTheTaskDefinition(t *testing.T) {
	escaped := xmlEscape(`DOMAIN\user<script>&"`)
	if strings.ContainsAny(escaped, `<>"`) {
		t.Fatalf("xmlEscape left markup characters: %q", escaped)
	}
	if !strings.Contains(escaped, "&lt;") || !strings.Contains(escaped, "&amp;") {
		t.Fatalf("xmlEscape did not escape markup: %q", escaped)
	}
}

// TestRecoverySDDLOmitsTheUserACEWhenNoDesktopUserExists proves a headless or
// unattended install does not fail and does not widen access: with no
// interactive desktop user to resolve, the recovery DACL names only SYSTEM and
// Administrators instead of granting a principal that does not exist.
func TestRecoverySDDLOmitsTheUserACEWhenNoDesktopUserExists(t *testing.T) {
	withoutUser := recoverySDDL("")
	if strings.Contains(withoutUser, "GRGX") {
		t.Fatalf("headless recovery DACL still grants interactive-user read+execute: %s", withoutUser)
	}
	if !strings.Contains(withoutUser, ";;;SY)") || !strings.Contains(withoutUser, ";;;BA)") {
		t.Fatalf("headless recovery DACL lost SYSTEM/Administrators: %s", withoutUser)
	}
	if _, err := windows.SecurityDescriptorFromString(withoutUser); err != nil {
		t.Fatalf("headless recovery DACL is not a valid security descriptor: %v", err)
	}

	withUser := recoverySDDL("*S-1-5-21-1-2-3-1001")
	if !strings.Contains(withUser, "(A;OICI;GRGX;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("resolved user is missing from the recovery DACL: %s", withUser)
	}
	// The "*" the callers pass is a SID-string prefix, not part of the SID.
	if strings.Contains(withUser, ";;;*") {
		t.Fatalf("recovery DACL kept the SID prefix as a principal: %s", withUser)
	}
}

// TestRegisterTrayTaskRefusesAnUnresolvedUser proves the tray registration
// cannot silently fall back to the elevated installer account when no
// interactive desktop user exists: it must report that it did not register,
// which setup reports as a warning because the service is the product.
func TestRegisterTrayTaskRefusesAnUnresolvedUser(t *testing.T) {
	if err := registerTrayTask(""); err == nil {
		t.Fatal("registerTrayTask accepted an empty interactive user")
	}
	if err := registerTrayTask("   "); err == nil {
		t.Fatal("registerTrayTask accepted a blank interactive user")
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
