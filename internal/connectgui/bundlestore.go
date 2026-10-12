package connectgui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// BundleFileName is the file the Connect app keeps beside its own executable so
// a bundle that is still live does not have to be pasted again on every run.
const BundleFileName = "hooshix-connect.cfg"

// maxBundleFileBytes bounds what Load reads. A protected bundle is a few hundred
// bytes, so anything larger is corruption or somebody else's file, and reading
// it whole would let the directory decide how much memory the app holds.
const maxBundleFileBytes = 8 << 10

// bundleFileVersion is the only file shape this build understands.
const bundleFileVersion = "1"

// Protector keeps a saved bundle unreadable while the app is not running it.
// A connect bundle carries the grant's bearer token, so it is a credential and
// must not sit in a configuration file as plaintext. The shipped implementation
// is the current Windows user's DPAPI key, which also makes the file useless to
// anybody who copies it to another account or machine.
type Protector interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// SavedBundle is a bundle the app stored on an earlier run.
type SavedBundle struct {
	// Bundle is the connect bundle, in memory only.
	Bundle string
	// SavedAt is when it was stored, in the RFC 3339 form the file records. It is
	// shown to the operator because a saved bundle outlives nobody's guess about
	// whether the grant behind it is still current.
	SavedAt string
}

// BundleStore reads and writes one saved bundle at a fixed path.
type BundleStore struct {
	path      string
	protector Protector
	now       func() time.Time
}

func NewBundleStore(path string, protector Protector) (*BundleStore, error) {
	if path == "" {
		return nil, errors.New("a bundle store needs a path")
	}
	if protector == nil {
		return nil, errors.New("a bundle store needs a protector: the connect bundle is a credential")
	}
	return &BundleStore{path: path, protector: protector, now: time.Now}, nil
}

// Path is where the store keeps its file, for the messages that tell the
// operator where the saved bundle lives.
func (store *BundleStore) Path() string { return store.path }

// BundlePathFor returns the cfg path beside the running executable. It refuses
// an empty or relative path because the file's location is the whole contract
// with the operator, who is told to look for it next to hooshix-connect.exe.
func BundlePathFor(executable string) (string, error) {
	if executable == "" {
		return "", errors.New("cannot find the directory of the running program")
	}
	if !filepath.IsAbs(executable) {
		return "", fmt.Errorf("program path %q is not absolute", executable)
	}
	return filepath.Join(filepath.Dir(executable), BundleFileName), nil
}

// Load returns the saved bundle. No file is not a failure: the first run of the
// app has never saved anything, and it must open as the full window instead of
// announcing an error nobody caused.
func (store *BundleStore) Load() (SavedBundle, error) {
	file, err := os.Open(store.path)
	if errors.Is(err, fs.ErrNotExist) {
		return SavedBundle{}, nil
	}
	if err != nil {
		return SavedBundle{}, fmt.Errorf("open the saved bundle file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBundleFileBytes+1))
	if err != nil {
		return SavedBundle{}, fmt.Errorf("read the saved bundle file: %w", err)
	}
	if len(data) > maxBundleFileBytes {
		return SavedBundle{}, fmt.Errorf("saved bundle file is larger than %d bytes", maxBundleFileBytes)
	}
	record, err := parseBundleFile(data)
	if err != nil {
		return SavedBundle{}, err
	}
	sealed, err := base64.StdEncoding.DecodeString(record.bundle)
	if err != nil || len(sealed) == 0 {
		return SavedBundle{}, errors.New("saved bundle file does not hold a protected bundle")
	}
	plaintext, err := store.protector.Open(sealed)
	if err != nil {
		// Named without the wrapped call error: DPAPI failures are always "this
		// file was not written for this user", and the reason is for the operator,
		// not for the log.
		return SavedBundle{}, errors.New("the saved bundle was written for a different Windows account or machine and cannot be opened here")
	}
	defer zeroBytes(plaintext)
	bundle := strings.TrimSpace(string(plaintext))
	if !strings.HasPrefix(bundle, connector.BundlePrefix) {
		return SavedBundle{}, errors.New("the saved bundle is not a connect bundle")
	}
	return SavedBundle{Bundle: bundle, SavedAt: record.savedAt}, nil
}

// Save stores a bundle so a later run can offer it without a re-paste, and
// returns the record the file now holds. The caller keeps that instead of
// guessing a timestamp of its own, because the window shows this date as the age
// of the credential it is running from. The credential never reaches the file as
// readable text: Seal runs first, and the file is published by rename so an
// interrupted write cannot leave the operator with a half-written bundle that the
// next run tries to open.
func (store *BundleStore) Save(bundle string) (SavedBundle, error) {
	trimmed := strings.TrimSpace(bundle)
	if trimmed == "" {
		return SavedBundle{}, errors.New("cannot save an empty connect bundle")
	}
	sealed, err := store.protector.Seal([]byte(trimmed))
	if err != nil {
		return SavedBundle{}, fmt.Errorf("protect the connect bundle: %w", err)
	}
	savedAt := store.now().UTC().Format(time.RFC3339)
	record := bundleRecord{
		version: bundleFileVersion,
		savedAt: savedAt,
		bundle:  base64.StdEncoding.EncodeToString(sealed),
	}
	if err := writeBundleFile(store.path, record.render()); err != nil {
		return SavedBundle{}, err
	}
	return SavedBundle{Bundle: trimmed, SavedAt: savedAt}, nil
}

// bundleRecord is one parsed cfg file.
type bundleRecord struct {
	version string
	savedAt string
	bundle  string
}

func (record bundleRecord) render() []byte {
	return []byte(strings.Join([]string{
		"# HooshiX Connect saved bundle.",
		"# bundle holds the connect bundle protected for this Windows account.",
		"# It is not a readable credential, and it does not open on another",
		"# account or machine. Delete this file to forget the saved bundle.",
		"version=" + record.version,
		"saved_at=" + record.savedAt,
		"bundle=" + record.bundle,
		"",
	}, "\n"))
}

// parseBundleFile reads the cfg strictly. Unknown keys and repeats are refused
// rather than skipped: a file this app did not write is not something the app
// should guess about, and silently ignoring a second bundle line would let the
// wrong credential be the one that connects.
func parseBundleFile(data []byte) (bundleRecord, error) {
	var record bundleRecord
	seen := map[string]bool{}
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return bundleRecord{}, fmt.Errorf("saved bundle line %d is not a key=value pair", index+1)
		}
		if seen[key] {
			return bundleRecord{}, fmt.Errorf("saved bundle key %q appears twice", key)
		}
		seen[key] = true
		switch key {
		case "version":
			record.version = value
		case "saved_at":
			record.savedAt = value
		case "bundle":
			record.bundle = value
		default:
			// Quoted through shortKeyName: an operator who opens this file in an
			// editor that wraps long lines puts the sealed payload where a key
			// should be, and the whole blob would otherwise be repeated in a
			// dialog box the size of the file.
			return bundleRecord{}, fmt.Errorf("saved bundle file has an unknown key %q", shortKeyName(key))
		}
	}
	if record.version != bundleFileVersion {
		return bundleRecord{}, fmt.Errorf("saved bundle version %q is not supported", record.version)
	}
	if record.bundle == "" {
		return bundleRecord{}, errors.New("saved bundle file has no bundle")
	}
	if _, err := time.Parse(time.RFC3339, record.savedAt); err != nil {
		return bundleRecord{}, errors.New("saved bundle file has an unreadable saved_at timestamp")
	}
	return record, nil
}

// shortKeyName keeps a message that names a bad key inside the width of the
// dialog that shows it. A real key is a word, so anything this long is not a key
// but whatever else the file held, and repeating it would dump that payload at
// the operator.
func shortKeyName(key string) string {
	if len(key) <= 24 {
		return key
	}
	return key[:24] + "..."
}

// writeBundleFile publishes content at path through a temporary file in the same
// directory, so the only state the operator can observe is "no saved bundle" or
// "a complete saved bundle".
func writeBundleFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+BundleFileName+".*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("write the saved bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("write the saved bundle: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish the saved bundle file: %w", err)
	}
	return nil
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
