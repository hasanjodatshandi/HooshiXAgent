package agent

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countingReader records how many bytes were actually copied out of it, which
// is how these tests tell a bounded read from a full read of an oversized file.
type countingReader struct {
	source   io.Reader
	consumed int64
}

func (reader *countingReader) Read(p []byte) (int, error) {
	n, err := reader.source.Read(p)
	reader.consumed += int64(n)
	return n, err
}

func TestReadBoundedStateFileStopsAtTheLimit(t *testing.T) {
	t.Parallel()
	reader := &countingReader{source: bytes.NewReader(make([]byte, 3*maxSettingsFileBytes))}
	data, err := readBoundedStateFile(reader)
	if err == nil {
		t.Fatal("an oversized state file was accepted")
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v, want the size-limit refusal", err)
	}
	if len(data) != 0 {
		t.Fatalf("oversized data was returned: %d bytes", len(data))
	}
	if reader.consumed > maxSettingsFileBytes+1 {
		t.Fatalf("the read was unbounded: %d bytes consumed, limit %d", reader.consumed, maxSettingsFileBytes)
	}
}

func TestReadStateFileRefusesAnOversizedFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxSettingsFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readStateFile(path)
	if err == nil {
		t.Fatal("readStateFile accepted a file past the bound")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an oversized file must not read as absent: %v", err)
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v, want the size-limit refusal", err)
	}

	// Right at the bound stays readable: the limit is a ceiling, not a target.
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxSettingsFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readStateFile(path)
	if err != nil {
		t.Fatalf("a file exactly at the bound was refused: %v", err)
	}
	if len(data) != maxSettingsFileBytes {
		t.Fatalf("read %d bytes of a %d byte file", len(data), maxSettingsFileBytes)
	}
}

func TestOversizedConfigFailsTheLoadInsteadOfDefaulting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, settingsFileName), bytes.Repeat([]byte("x"), maxSettingsFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfigUnlocked(dir)
	if err == nil {
		t.Fatal("an oversized config.json was accepted")
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v, want the size-limit refusal rather than a decode error", err)
	}
}

func TestOversizedSettingsPointerIsIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, settingsLocationName), bytes.Repeat([]byte("A"), maxSettingsFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := redirectedSettingsPath(dir); ok {
		t.Fatalf("an oversized settings pointer was obeyed: %q", got)
	}
	if got := ConfigPath(dir); got != filepath.Join(dir, settingsFileName) {
		t.Fatalf("ConfigPath = %q, want the state-directory default after refusing the pointer", got)
	}
}
