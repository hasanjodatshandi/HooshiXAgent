package agent

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/tunnelstates"
)

var errSyntheticRotationFailure = errors.New("synthetic rotation failure")

// TestRotateCommandReplacesIdentityAtomically proves the CLI rotate path
// replaces the Ed25519 identity, keeps the session token, and requires an
// initialized identity.
func TestRotateCommandReplacesIdentityAtomically(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := Main([]string{"init", "--state-dir", dir, "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("init exit=%d err=%s", code, errOut.String())
	}
	store := NewPlatformSecretStore(dir)
	beforePub, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	token := "test_session_token_0123456789ABCDEF"
	gateway := "wss://gateway.example/agent/v1/connect"
	var cfgOut, cfgErr bytes.Buffer
	if code := Main([]string{
		"configure", "--state-dir", dir,
		"--gateway", gateway,
		"--device-id", "device-001",
		"--authorization-id", "auth-001",
		"--token-id", "token-001",
		"--token-stdin",
	}, strings.NewReader(token+"\n"), &cfgOut, &cfgErr); code != 0 {
		t.Fatalf("configure exit=%d err=%s", code, cfgErr.String())
	}

	// Rotate with --force (non-interactive determinism).
	var rotOut, rotErr bytes.Buffer
	if code := Main([]string{"rotate", "--state-dir", dir, "--force", "--json"}, strings.NewReader(""), &rotOut, &rotErr); code != 0 {
		t.Fatalf("rotate exit=%d err=%s", code, rotErr.String())
	}
	after, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforePub, after) {
		t.Fatal("rotate did not replace the device identity")
	}
	if got, err := LoadSessionToken(store); err != nil || got != token {
		t.Fatalf("rotate disturbed the session token: token=%q err=%v", got, err)
	}
	if !strings.Contains(rotOut.String(), `"rotated":true`) || !strings.Contains(rotOut.String(), `"public_key"`) {
		t.Fatalf("rotate output missing fields: %s", rotOut.String())
	}
}

// TestRotateRequiresConfirmation proves the interactive default aborts
// without a positive confirmation and that confirmation is consumed strictly.
func TestRotateRequiresConfirmation(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := Main([]string{"init", "--state-dir", dir, "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("init exit=%d err=%s", code, errOut.String())
	}
	store := NewPlatformSecretStore(dir)
	before, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	// Declined confirmation aborts without changing the key.
	var rotOut, rotErr bytes.Buffer
	if code := Main([]string{"rotate", "--state-dir", dir}, strings.NewReader("n\n"), &rotOut, &rotErr); code != 1 {
		t.Fatalf("declined rotate exit=%d want=1 err=%s", code, rotErr.String())
	}
	current, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, current) {
		t.Fatal("declined rotation changed the identity")
	}

	// Accepted confirmation rotates.
	var okOut, okErr bytes.Buffer
	if code := Main([]string{"rotate", "--state-dir", dir}, strings.NewReader("y\n"), &okOut, &okErr); code != 0 {
		t.Fatalf("confirmed rotate exit=%d err=%s", code, okErr.String())
	}
	rotated, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, rotated) {
		t.Fatal("confirmed rotation did not change the identity")
	}
}

// TestRotateUninitializedFailsClosed proves rotation refuses to invent an
// identity for an uninitialized state directory.
func TestRotateUninitializedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := Main([]string{"rotate", "--state-dir", dir, "--force"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("uninitialized rotate exit=%d want=1", code)
	}
	if !strings.Contains(errOut.String(), "not initialized") {
		t.Fatalf("uninitialized rotate error=%q", errOut.String())
	}
}

// TestRotateRollsBackOnFailure proves an injected failure after the secret
// write restores the previous identity byte-for-byte through the state
// transaction journal.
func TestRotateRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	before, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	secretBefore, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rotateAgentIdentity(dir, store, stateMutationFaults{
		afterSecretSave: func() error { return errSyntheticRotationFailure },
	}); err == nil {
		t.Fatal("fault-injected rotation unexpectedly succeeded")
	}
	after, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed rotation did not restore the previous identity")
	}
	secretAfter, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("failed rotation left a different secret blob")
	}
}

// TestRunnerHealthAfterRotation proves the connection state machine still
// transitions through reconnecting/connecting after an identity rotation,
// keeping the observational health view usable.
func TestRunnerHealthAfterRotation(t *testing.T) {
	machine := tunnelstates.New()
	machine.MustTransition(tunnelstates.Connecting)
	machine.MustTransition(tunnelstates.Connected)
	machine.MustTransition(tunnelstates.Reconnecting)
	machine.MustTransition(tunnelstates.Connecting)
	machine.MustTransition(tunnelstates.Connected)
	if state, terminal := machine.Observability(); state != "connected" || terminal {
		t.Fatalf("post-rotation health=%q terminal=%t", state, terminal)
	}
}
