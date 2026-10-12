//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connectgui"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// dpapiTestBundle is shaped like a real bundle: connectgui.Load refuses plaintext
// that does not carry the prefix, so the store tests must use one.
func dpapiTestBundle() string {
	return connector.BundlePrefix + strings.Repeat("q", 96)
}

func TestDPAPISealedBundleIsNotItsOwnPlaintext(t *testing.T) {
	protector := newProtector()
	bundle := dpapiTestBundle()
	sealed, err := protector.Seal([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealing produced nothing")
	}
	if strings.Contains(string(sealed), bundle) {
		t.Error("DPAPI returned the credential unchanged")
	}
	opened, err := protector.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != bundle {
		t.Errorf("opened = %q, want the sealed bundle", opened)
	}
}

// TestSavedBundleFileHoldsNoCredential is the end-to-end proof for the promise in
// docs/runtime/remote-desktop.md: the cfg beside the exe exists, and it is not a
// copy of a token somebody else can use.
func TestSavedBundleFileHoldsNoCredential(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "hooshix-connect.exe")
	bundle := dpapiTestBundle()

	state := openSavedBundleStore(executable)
	if state.problem != nil {
		t.Fatal(state.problem)
	}
	if state.store == nil {
		t.Fatal("no store was built")
	}
	if state.compact() {
		t.Error("a directory with no cfg opened without a paste area")
	}
	saved, err := state.store.Save(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if saved.SavedAt == "" {
		t.Error("Save reported no timestamp, so the button would have no date to show")
	}

	data, err := os.ReadFile(state.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, bundle) || strings.Contains(text, connector.BundlePrefix) {
		t.Error("the saved file holds the connect bundle in readable form")
	}
	if filepath.Base(state.store.Path()) != connectgui.BundleFileName {
		t.Errorf("the cfg is at %q, not beside the executable", state.store.Path())
	}

	// The whole point of the file: the next run reads it back.
	reopened := openSavedBundleStore(executable)
	if reopened.problem != nil {
		t.Fatalf("the next run could not read what this one saved: %v", reopened.problem)
	}
	if reopened.bundle != bundle {
		t.Error("the reopened store holds a different bundle")
	}
	if !reopened.compact() {
		t.Error("a run that woke up with a saved bundle still showed the paste area")
	}
	if reopened.savedAt != saved.SavedAt {
		t.Errorf("save date reported twice as %q and %q", saved.SavedAt, reopened.savedAt)
	}
}

// TestOpenSavedBundleStoreKeepsAFileItCannotOpen covers a cfg written by another
// Windows account: the run must say so, keep the paste area, and still be able to
// overwrite the stale file rather than disable saving for good.
func TestOpenSavedBundleStoreKeepsAFileItCannotOpen(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "hooshix-connect.exe")
	stale := "version=1\nsaved_at=2026-10-12T18:30:00Z\nbundle=AQID\n"
	if err := os.WriteFile(filepath.Join(directory, connectgui.BundleFileName), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	state := openSavedBundleStore(executable)
	if state.problem == nil {
		t.Fatal("a blob this account cannot open was accepted")
	}
	if !strings.Contains(state.problem.Error(), "different Windows account or machine") {
		t.Errorf("the operator is not told what is wrong: %v", state.problem)
	}
	if state.compact() {
		t.Error("an unreadable cfg must leave the paste area on screen")
	}
	if state.store == nil {
		t.Fatal("the store was dropped, so this run could never replace the stale file")
	}
	if _, err := state.store.Save(dpapiTestBundle()); err != nil {
		t.Fatal(err)
	}
	if fixed := openSavedBundleStore(executable); fixed.problem != nil {
		t.Errorf("re-saving left the store unusable: %v", fixed.problem)
	}
}

func TestOpenSavedBundleStoreRefusesAnUnlocatableExecutable(t *testing.T) {
	for _, executable := range []string{"", filepath.Join("relative", "hooshix-connect.exe")} {
		state := openSavedBundleStore(executable)
		if state.problem == nil {
			t.Errorf("openSavedBundleStore(%q) claimed success", executable)
		}
		if state.store != nil {
			t.Errorf("openSavedBundleStore(%q) built a store it cannot place", executable)
		}
	}
}

// The Win32 blob struct carries a uint32 length. On a 64-bit build a Go byte
// count can exceed it, and wrapping that value would protect only the head of the
// credential and later open as corrupt data. The bound lives in dpapiBlobLength
// precisely so it is testable without a 4 GiB allocation.
func TestConnectDPAPIBlobLengthRefusesWhatCbDataCannotDescribe(t *testing.T) {
	var ceiling uint64 = maxDPAPIBlobBytes
	largest := int(ceiling)
	if largest < 0 {
		t.Skip("a 32-bit int cannot express the Win32 blob ceiling, so the overflow branch is unreachable on this build")
	}
	for _, testCase := range []struct {
		name  string
		input int
		want  uint32
		err   bool
	}{
		{name: "zero", input: 0},
		{name: "one byte", input: 1, want: 1},
		{name: "largest describable", input: largest, want: ^uint32(0)},
		{name: "one past the limit", input: largest + 1, err: true},
	} {
		got, err := dpapiBlobLength(testCase.input)
		if testCase.err {
			if err == nil || !strings.Contains(err.Error(), "Win32 blob limit") {
				t.Fatalf("%s: overflow returned %d, %v", testCase.name, got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if got != testCase.want {
			t.Fatalf("%s: cbData=%d want %d", testCase.name, got, testCase.want)
		}
	}
}

// TestConnectBlobFromBytesDescribesTheCallersBuffer pins both the empty case and
// the length/pointer pairing: a wrong cbData or a pbData that points at a copy
// corrupts the protected blob without any API error.
func TestConnectBlobFromBytesDescribesTheCallersBuffer(t *testing.T) {
	empty, err := blobFromBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.cbData != 0 || empty.pbData != nil {
		t.Fatalf("empty input built cbData=%d pbData=%v, want a zero blob", empty.cbData, empty.pbData)
	}
	data := []byte("connect-bundle-material")
	blob, err := blobFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if blob.cbData != uint32(len(data)) {
		t.Fatalf("cbData=%d want %d", blob.cbData, len(data))
	}
	if unsafe.Pointer(blob.pbData) != unsafe.Pointer(&data[0]) {
		t.Fatal("pbData must point at the caller's first byte, not a copy")
	}
}
