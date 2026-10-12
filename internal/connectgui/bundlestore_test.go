package connectgui

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

const savedBundleAt = "2026-10-12T18:30:00Z"

// testProtector is a Protector that stores its input backwards and tagged, so a
// test can prove two things at once: the round trip works, and what lands in the
// file is not the credential in any directly readable form.
type testProtector struct {
	openErr error
}

const protectedTag = "sealed:"

func (protector testProtector) Seal(plaintext []byte) ([]byte, error) {
	return append([]byte(protectedTag), reverseBytes(plaintext)...), nil
}

func (protector testProtector) Open(sealed []byte) ([]byte, error) {
	if protector.openErr != nil {
		return nil, protector.openErr
	}
	if !strings.HasPrefix(string(sealed), protectedTag) {
		return nil, errors.New("blob was not sealed by this protector")
	}
	return reverseBytes(sealed[len(protectedTag):]), nil
}

func reverseBytes(data []byte) []byte {
	reversed := make([]byte, len(data))
	for index := range data {
		reversed[index] = data[len(data)-1-index]
	}
	return reversed
}

func newTestStore(t *testing.T, protector Protector) *BundleStore {
	t.Helper()
	store, err := NewBundleStore(filepath.Join(t.TempDir(), BundleFileName), protector)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Date(2026, 10, 12, 18, 30, 0, 0, time.UTC) }
	return store
}

func savedTestBundle() string {
	return connector.BundlePrefix + strings.Repeat("k", 96)
}

func TestSavedBundleRoundTripsThroughTheStore(t *testing.T) {
	store := newTestStore(t, testProtector{})
	bundle := savedTestBundle()
	saved, err := store.Save(bundle)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	// The window titles its button from what Save reported, so the two views of
	// the file have to agree.
	if saved != loaded {
		t.Errorf("Save reported %+v but the file reads %+v", saved, loaded)
	}
	if loaded.Bundle != bundle {
		t.Errorf("loaded bundle = %q, want the saved one", loaded.Bundle)
	}
	if loaded.SavedAt != savedBundleAt {
		t.Errorf("SavedAt = %q, want %q", loaded.SavedAt, savedBundleAt)
	}
}

// TestSavedFileCarriesNoReadableCredential pins the reason the store is not just
// a config writer: the connect bundle is a bearer token, and the operator's
// Downloads folder must not hold it in a form a passer-by can read.
func TestSavedFileCarriesNoReadableCredential(t *testing.T) {
	store := newTestStore(t, testProtector{})
	bundle := savedTestBundle()
	if _, err := store.Save(bundle); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, bundle) {
		t.Error("the saved file holds the connect bundle verbatim")
	}
	if strings.Contains(text, protectedTag) {
		t.Error("the saved file holds the protected blob verbatim, it must be encoded")
	}
	if !strings.Contains(text, "version="+bundleFileVersion) {
		t.Errorf("the saved file does not declare its version: %q", text)
	}
	if !strings.Contains(text, "saved_at="+savedBundleAt) {
		t.Errorf("the saved file does not record when it was written: %q", text)
	}
}

func TestSaveReplacesThePreviousBundle(t *testing.T) {
	store := newTestStore(t, testProtector{})
	if _, err := store.Save(savedTestBundle()); err != nil {
		t.Fatal(err)
	}
	replacement := connector.BundlePrefix + strings.Repeat("m", 96)
	if _, err := store.Save(replacement); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("re-saving a bundle left an unreadable file: %v", err)
	}
	if loaded.Bundle != replacement {
		t.Errorf("loaded bundle = %q, want the replacement", loaded.Bundle)
	}
	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("the store left %v behind, want only %s", names, BundleFileName)
	}
}

func TestLoadTreatsAMissingFileAsNoSavedBundle(t *testing.T) {
	store := newTestStore(t, testProtector{})
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("a first run with nothing saved must not fail: %v", err)
	}
	if loaded.Bundle != "" || loaded.SavedAt != "" {
		t.Errorf("Load = %+v, want the zero value", loaded)
	}
}

func TestSaveRefusesAnEmptyBundle(t *testing.T) {
	store := newTestStore(t, testProtector{})
	if _, err := store.Save("   "); err == nil {
		t.Fatal("saving a blank bundle succeeded")
	}
	if _, err := os.Stat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused Save still produced a file: %v", err)
	}
}

func TestNewBundleStoreNeedsAPathAndAProtector(t *testing.T) {
	if _, err := NewBundleStore("", testProtector{}); err == nil {
		t.Error("a store with no path was accepted")
	}
	if _, err := NewBundleStore(filepath.Join(t.TempDir(), BundleFileName), nil); err == nil {
		t.Error("a store that would write plaintext was accepted")
	}
}

func TestLoadRefusesFilesThisAppDidNotWrite(t *testing.T) {
	cases := []struct {
		name    string
		content string
		why     string
	}{
		{"unknown key", "version=1\nsaved_at=" + savedBundleAt + "\nbundle=Zm9v\nextra=1\n", "unknown key"},
		{"repeated key", "version=1\nsaved_at=" + savedBundleAt + "\nbundle=Zm9v\nbundle=Zm9v\n", "appears twice"},
		{"not a pair", "version=1\nnonsense\nsaved_at=" + savedBundleAt + "\nbundle=Zm9v\n", "not a key=value pair"},
		{"future version", "version=2\nsaved_at=" + savedBundleAt + "\nbundle=Zm9v\n", "not supported"},
		{"missing bundle", "version=1\nsaved_at=" + savedBundleAt + "\n", "no bundle"},
		{"unreadable date", "version=1\nsaved_at=yesterday\nbundle=Zm9v\n", "unreadable saved_at"},
		{"blob is not base64", "version=1\nsaved_at=" + savedBundleAt + "\nbundle=not base64!\n", "protected bundle"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := newTestStore(t, testProtector{})
			if err := os.WriteFile(store.Path(), []byte(testCase.content), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load()
			if err == nil {
				t.Fatalf("Load accepted %s: %+v", testCase.name, loaded)
			}
			if !strings.Contains(err.Error(), testCase.why) {
				t.Errorf("error %q does not name the reason %q", err, testCase.why)
			}
		})
	}
}

func TestLoadRefusesAnOversizedFile(t *testing.T) {
	store := newTestStore(t, testProtector{})
	pad := strings.Repeat("0", maxBundleFileBytes+1)
	if err := os.WriteFile(store.Path(), []byte("version=1\nsaved_at="+savedBundleAt+"\nbundle="+pad+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Load read an oversized file: %v", err)
	}
}

// TestUnknownKeyStaysQuotable covers the hand-edited cfg. An editor that wraps
// long lines turns the sealed blob into a line that reads like a key with an "="
// inside it, and the refusal is shown in a dialog box: it has to name the line,
// not reprint the payload it just refused.
func TestUnknownKeyStaysQuotable(t *testing.T) {
	store := newTestStore(t, testProtector{})
	wrapped := strings.Repeat("A", 200) + "=" + strings.Repeat("B", 200)
	content := "version=1\nsaved_at=" + savedBundleAt + "\nbundle=Zm9v\n" + wrapped + "\n"
	if err := os.WriteFile(store.Path(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	if err == nil {
		t.Fatal("a wrapped saved bundle file was accepted")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("error %q does not name the reason", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("A", 25)) {
		t.Errorf("error repeated the payload it refused: %q", err)
	}
	if len(err.Error()) > 120 {
		t.Errorf("error is too long for the dialog that shows it: %q", err)
	}
}

// TestLoadRefusesAPlaintextThatIsNotABundle covers the case where the protector
// opens a blob happily but what comes back is not a connect bundle: a hand-edited
// or truncated file must never reach App.Connect.
func TestLoadRefusesAPlaintextThatIsNotABundle(t *testing.T) {
	store := newTestStore(t, testProtector{})
	sealed, err := store.protector.Seal([]byte("just some text"))
	if err != nil {
		t.Fatal(err)
	}
	content := "version=1\nsaved_at=" + savedBundleAt + "\nbundle=" + base64.StdEncoding.EncodeToString(sealed) + "\n"
	if err := os.WriteFile(store.Path(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "not a connect bundle") {
		t.Fatalf("Load returned a non-bundle: %v", err)
	}
}

func TestLoadReportsAFileAnotherAccountCannotOpen(t *testing.T) {
	store := newTestStore(t, testProtector{openErr: errors.New("CryptUnprotectData failed")})
	if _, err := store.Save(savedTestBundle()); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err == nil {
		t.Fatalf("an unopenable blob loaded anyway: %+v", loaded)
	}
	if !strings.Contains(err.Error(), "different Windows account or machine") {
		t.Errorf("error %q does not tell the operator what to do", err)
	}
	if strings.Contains(err.Error(), savedTestBundle()) {
		t.Error("the failure message echoes the credential")
	}
}

func TestBundlePathForSitsBesideTheExecutable(t *testing.T) {
	directory := t.TempDir()
	path, err := BundlePathFor(filepath.Join(directory, "hooshix-connect.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(directory, BundleFileName); path != want {
		t.Errorf("BundlePathFor = %q, want %q", path, want)
	}
	if _, err := BundlePathFor(""); err == nil {
		t.Error("an empty executable path was accepted")
	}
	if _, err := BundlePathFor(filepath.Join("relative", "hooshix-connect.exe")); err == nil {
		t.Error("a relative executable path was accepted")
	}
}
