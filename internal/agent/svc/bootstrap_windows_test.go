//go:build windows

package svc

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/webapp"
)

func TestFreshArchiveServiceStateBootstrapsBeforeLogging(t *testing.T) {
	dir := t.TempDir()
	if err := initializeServiceIdentity(dir); err != nil {
		t.Fatal(err)
	}
	identity, _, err := agent.LoadIdentity(agent.NewPlatformSecretStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	capability, err := agent.LoadPairingCapability(dir)
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := newRotatingFile(filepath.Join(dir, "agent.log"), agentLogMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	if _, err := webapp.NewApp(dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("pairing UI bootstrap: %v", err)
	}
	if err := initializeServiceIdentity(dir); err != nil {
		t.Fatalf("restart: %v", err)
	}
	again, _, err := agent.LoadIdentity(agent.NewPlatformSecretStore(dir))
	if err != nil || !bytes.Equal(again, identity) {
		t.Fatalf("restart replaced identity: %v", err)
	}
	if got, err := agent.LoadPairingCapability(dir); err != nil || got != capability {
		t.Fatalf("restart replaced pairing capability: %v", err)
	}
}
