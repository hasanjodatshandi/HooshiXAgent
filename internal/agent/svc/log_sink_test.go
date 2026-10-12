package svc

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestForegroundLoggerWritesEveryRecordToTheGivenWriter(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := newForegroundLogger(buffer)
	logger.Info("tunnel ready", "state_dir", "/var/lib/hooshix")
	logger.Debug("below the service floor")
	if !strings.Contains(buffer.String(), "tunnel ready") || !strings.Contains(buffer.String(), "state_dir=/var/lib/hooshix") {
		t.Fatalf("foreground logger dropped the record: %q", buffer.String())
	}
	if strings.Contains(buffer.String(), "below the service floor") {
		t.Fatalf("foreground logger emits debug noise the service never asked for: %q", buffer.String())
	}
}

// TestServicePackageHasNoDiscardDiagnosticSink pins the fix for the silent
// non-Windows service log: the foreground entry points must route diagnostics
// through the shared writer, and no writer in this package may swallow bytes.
// A discard sink there erases the only record of why a tunnel stopped, on
// every platform whose supervisor runs in the foreground.
func TestServicePackageHasNoDiscardDiagnosticSink(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read service package: %v", err)
	}
	var foregroundFiles []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(source)
		if strings.Contains(text, "io.Discard") {
			t.Errorf("%s sends service diagnostics to io.Discard", name)
		}
		if strings.Contains(text, "func RunService(") {
			foregroundFiles = append(foregroundFiles, name)
			if !strings.Contains(text, "newForegroundLogger(os.Stderr)") {
				t.Errorf("%s runs the supervisor without the shared stderr sink", name)
			}
			if strings.Contains(text, "slog.NewTextHandler") {
				t.Errorf("%s builds its own handler instead of calling newForegroundLogger", name)
			}
		}
	}
	if len(foregroundFiles) == 0 {
		t.Fatal("no RunService entry point found in the service package")
	}
}
