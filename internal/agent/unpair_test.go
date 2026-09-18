package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pairedStateDir builds the state a successful pairing leaves behind: an
// initialized identity, a complete pairing record, and a local exposure.
func pairedStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	if err := MutateConfig(dir, func(config *Config) error {
		config.SetEndpoint(Endpoint{ID: "local-http-001", Target: "127.0.0.1:4000"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := configureAgentState(dir, store, Config{
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		GatewayAliases:  []string{"wss://backup.example/agent/v1/connect"},
		CAFile:          writeTestTrustAnchor(t),
		DeviceID:        "device-unpair-000001",
		AuthorizationID: "auth-unpair-000001",
		TokenID:         "token-unpair-000001",
		UpdateChannel:   "stable",
	}, testSessionToken, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	return dir
}

const testSessionToken = "test_session_token_0123456789ABCDEF"

// writeTestTrustAnchor writes a real PEM certificate, which is what a
// configured ca_file points at (ValidateCAFile rejects anything that does not
// parse into an x509 trust pool).
func writeTestTrustAnchor(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HooshiX unpair test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUnpairClearsPairingAndPreservesIdentity proves the default behaviour:
// every field a pairing installs is cleared, the session token is gone, the
// device identity and the local exposure survive, and no transaction journal
// is left behind.
func TestUnpairClearsPairingAndPreservesIdentity(t *testing.T) {
	dir := pairedStateDir(t)
	store := NewPlatformSecretStore(dir)
	beforeKey, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Main([]string{"unpair", "--state-dir", dir, "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("unpair exit=%d err=%s", code, errOut.String())
	}
	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || len(config.GatewayAliases) != 0 || config.CAFile != "" ||
		config.DeviceID != "" || config.AuthorizationID != "" || config.TokenID != "" {
		t.Fatalf("unpair left pairing material behind: %+v", config)
	}
	// The cleared state is exactly the pending_config state the supervisor
	// waits in.
	if err := config.ValidateRuntime(); err == nil {
		t.Fatal("unpaired config still validates as runnable")
	}
	if _, err := LoadSessionToken(store); err == nil {
		t.Fatal("unpair left the session token in the secret store")
	}
	afterKey, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatalf("unpair destroyed the device identity: %v", err)
	}
	if !bytes.Equal(beforeKey, afterKey) {
		t.Fatal("default unpair replaced the device identity")
	}
	if !strings.Contains(out.String(), `"identity_preserved":true`) {
		t.Fatalf("unpair output does not report identity preservation: %s", out.String())
	}
	if !strings.Contains(out.String(), `"device_id":"device-unpair-000001"`) {
		t.Fatalf("unpair output does not report the cleared device id: %s", out.String())
	}
	// Local exposure configuration is not pairing material.
	if len(config.Endpoints) != 1 || config.Endpoints[0].ID != "local-http-001" {
		t.Fatalf("unpair dropped local endpoint mappings: %+v", config.Endpoints)
	}
	assertNoStateTransaction(t, dir)
}

// TestUnpairResetIdentityReplacesIdentity proves --reset-identity is the only
// way the key changes, that the replacement is usable, and that the operator is
// told to register the new key.
func TestUnpairResetIdentityReplacesIdentity(t *testing.T) {
	dir := pairedStateDir(t)
	store := NewPlatformSecretStore(dir)
	beforeKey, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Main([]string{"unpair", "--state-dir", dir, "--reset-identity", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("unpair --reset-identity exit=%d err=%s", code, errOut.String())
	}
	afterKey, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatalf("unpair --reset-identity left no usable identity: %v", err)
	}
	if bytes.Equal(beforeKey, afterKey) {
		t.Fatal("--reset-identity did not replace the device identity")
	}
	if !strings.Contains(out.String(), PublicKeyBase64(afterKey)) {
		t.Fatalf("output does not report the new public key: %s", out.String())
	}
	if !strings.Contains(out.String(), `"identity_preserved":false`) {
		t.Fatalf("output does not distinguish the replaced identity: %s", out.String())
	}
	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || config.DeviceID != "" {
		t.Fatalf("--reset-identity left pairing material behind: %+v", config)
	}
	if _, err := LoadSessionToken(store); err == nil {
		t.Fatal("--reset-identity left the session token in the secret store")
	}
}

// TestUnpairIsIdempotentWhenAlreadyUnpaired proves a second unpair succeeds
// with an explicit message and changes nothing at all.
func TestUnpairIsIdempotentWhenAlreadyUnpaired(t *testing.T) {
	dir := pairedStateDir(t)
	if _, err := unpairState(dir, false); err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretBefore, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Main([]string{"unpair", "--state-dir", dir, "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("second unpair exit=%d err=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"already_unpaired":true`) {
		t.Fatalf("second unpair did not report an already-unpaired agent: %s", out.String())
	}
	configAfter, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretAfter, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) || !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("unpair on an already-unpaired agent rewrote state")
	}
	assertNoStateTransaction(t, dir)

	// A fresh state directory with no identity at all is also a successful
	// no-op rather than an error.
	empty := t.TempDir()
	var emptyOut, emptyErr bytes.Buffer
	if code := Main([]string{"unpair", "--state-dir", empty}, strings.NewReader(""), &emptyOut, &emptyErr); code != 0 {
		t.Fatalf("unpair on a fresh state directory exit=%d err=%s", code, emptyErr.String())
	}
	if !strings.Contains(emptyOut.String(), "already unpaired") {
		t.Fatalf("fresh-directory unpair message: %q", emptyOut.String())
	}
}

// TestUnpairRollsBackAtomicallyOnFailure proves the operation is
// all-or-nothing: an injected failure after the config write restores both the
// config and the secret byte-for-byte and leaves no journal behind.
func TestUnpairRollsBackAtomicallyOnFailure(t *testing.T) {
	dir := pairedStateDir(t)
	store := NewPlatformSecretStore(dir)
	configBefore, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretBefore, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := unpairAgentState(dir, store, true, stateMutationFaults{
		afterConfigSave: func() error { return errors.New("synthetic unpair failure") },
	}); err == nil {
		t.Fatal("fault-injected unpair unexpectedly succeeded")
	}
	configAfter, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretAfter, err := readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) {
		t.Fatalf("failed unpair left a different config:\n%s", configAfter)
	}
	if !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("failed unpair left a different secret blob")
	}
	keyAfter, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("failed unpair changed the device identity")
	}
	assertNoStateTransaction(t, dir)

	// The same holds when the failure lands after the secret write.
	if _, err := unpairAgentState(dir, store, false, stateMutationFaults{
		afterSecretSave: func() error { return errors.New("synthetic unpair failure") },
	}); err == nil {
		t.Fatal("fault-injected unpair unexpectedly succeeded")
	}
	configAfter, err = os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretAfter, err = readStateFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) || !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("failed unpair after the secret write did not restore both sides")
	}
	assertNoStateTransaction(t, dir)
}

// TestUnpairRemovesLegacyTokenCopy proves a leftover plaintext token record is
// not among the "orphaned secrets" an unpair leaves behind.
func TestUnpairRemovesLegacyTokenCopy(t *testing.T) {
	dir := pairedStateDir(t)
	if err := os.WriteFile(filepath.Join(dir, "token.txt"), []byte(testSessionToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := unpairState(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "token.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy token.txt survived unpair: %v", err)
	}
}

func assertNoStateTransaction(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(stateTransactionPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpair left a state transaction journal behind: %v", err)
	}
}
