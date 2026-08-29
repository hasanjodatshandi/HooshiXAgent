package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalTargetPolicy(t *testing.T) {
	t.Parallel()
	allowed := []string{
		"localhost:80",
		"127.0.0.1:8080",
		"127.42.5.9:65535",
		"[::1]:443",
	}
	for _, target := range allowed {
		if err := ValidateLocalTarget(target); err != nil {
			t.Errorf("allowed target %q rejected: %v", target, err)
		}
	}
	denied := []string{
		"0.0.0.0:80",
		"192.168.1.10:80",
		"10.0.0.1:80",
		"172.16.0.1:80",
		"169.254.169.254:80",
		"224.0.0.1:80",
		"example.com:443",
		"metadata.google.internal:80",
		"http://localhost:80",
		"file:///etc/passwd",
		"/var/run/docker.sock",
		"localhost",
		"localhost:0",
		"localhost:65536",
	}
	for _, target := range denied {
		if err := ValidateLocalTarget(target); err == nil {
			t.Errorf("denied target %q was accepted", target)
		}
	}
}

func TestIdentityPersistsAndSecretStateIsProtected(t *testing.T) {
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	publicOne, _, err := LoadOrCreateIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSessionToken(store, "synthetic_session_token_0123456789ABCDEF"); err != nil {
		t.Fatal(err)
	}
	publicTwo, _, err := LoadOrCreateIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicOne, publicTwo) {
		t.Fatal("identity changed for the same state directory")
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, "secrets.json")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("secret file permissions too broad: %04o", info.Mode().Perm())
		}
		dirInfo, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("state directory permissions too broad: %04o", dirInfo.Mode().Perm())
		}
	}
}

func TestSecretStoreRejectsUnsafePermissionsAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission/symlink test")
	}
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if err := store.Save(SecretState{Seed: strings.Repeat("A", 43)}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secrets.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("expected broad secret-file permissions to be rejected")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("expected secret-file symlink to be rejected")
	}
}

func TestCLIStatusDoesNotLeakSecrets(t *testing.T) {
	dir := t.TempDir()
	var initOut bytes.Buffer
	if code := Main([]string{"init", "--state-dir", dir, "--json"}, strings.NewReader(""), &initOut, &bytes.Buffer{}); code != 0 {
		t.Fatalf("init exit=%d output=%s", code, initOut.String())
	}
	token := "test_session_token_0123456789ABCDEF"
	gateway := "wss://gateway.example/agent/v1/connect"
	var configureOut, configureErr bytes.Buffer
	code := Main([]string{
		"configure", "--state-dir", dir,
		"--gateway", gateway,
		"--device-id", "device-001",
		"--authorization-id", "auth-001",
		"--token-id", "token-001",
		"--token-stdin",
	}, strings.NewReader(token+"\n"), &configureOut, &configureErr)
	if code != 0 {
		t.Fatalf("configure exit=%d err=%s", code, configureErr.String())
	}
	if code := Main([]string{"expose", "add", "--state-dir", dir, "--id", "local-http-001", "--target", "127.0.0.1:8080"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("expose exit=%d", code)
	}
	var statusOut, statusErr bytes.Buffer
	if code := Main([]string{"status", "--state-dir", dir, "--json"}, strings.NewReader(""), &statusOut, &statusErr); code != 0 {
		t.Fatalf("status exit=%d err=%s", code, statusErr.String())
	}
	if strings.Contains(statusOut.String(), token) {
		t.Fatal("status leaked session token")
	}
	configData, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(configData, []byte(token)) || bytes.Contains(configData, []byte("seed")) {
		t.Fatal("normal config contains secret material")
	}
	var status map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["credentials_present"] != true {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestRunnerUsesBoundedReconnectBackoff(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = 2 * time.Millisecond
	limits.ReconnectMax = 4 * time.Millisecond
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner, err := NewRunner(t.TempDir(), limits, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	runner.attempt = func(context.Context) error {
		if attempts.Add(1) >= 4 {
			cancel()
		}
		return errors.New("synthetic reconnect failure")
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() < 4 {
		t.Fatalf("expected multiple reconnect attempts, got %d", attempts.Load())
	}
	for i := 0; i < 100; i++ {
		delay := jittered(limits.ReconnectMax)
		if delay < 3*time.Millisecond || delay > 5*time.Millisecond {
			t.Fatalf("jittered delay escaped bounded range: %s", delay)
		}
	}
}

func TestGatewayURLValidation(t *testing.T) {
	t.Parallel()
	if err := ValidateGatewayURL("wss://gateway.example/agent/v1/connect"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"ws://gateway.example/agent/v1/connect",
		"https://gateway.example/agent/v1/connect",
		"wss://gateway.example/other",
		"wss://user@gateway.example/agent/v1/connect",
		"wss://gateway.example/agent/v1/connect?x=1",
	} {
		if err := ValidateGatewayURL(raw); err == nil {
			t.Fatalf("expected Gateway URL rejection: %s", raw)
		}
	}
}

func TestServiceSpecFoundations(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		spec, err := NativeServiceSpec(goos, filepath.Join(t.TempDir(), "hooshix-agent"), filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if spec.Native == "" || spec.Name != "hooshix-agent" {
			t.Fatalf("invalid %s service spec: %#v", goos, spec)
		}
	}
}

func TestUpdateFoundationValidation(t *testing.T) {
	t.Parallel()
	current := CurrentUpdateInfo("stable")
	digest := sha256.Sum256([]byte("artifact"))
	candidate := UpdateCandidate{
		Version: "v1.2.3",
		OS:      current.OS,
		Arch:    current.Arch,
		URL:     "https://downloads.example/hooshix-agent",
		SHA256:  hex.EncodeToString(digest[:]),
	}
	if err := ValidateUpdateCandidate(candidate, current); err != nil {
		t.Fatal(err)
	}
	candidate.URL = "http://downloads.example/hooshix-agent"
	if err := ValidateUpdateCandidate(candidate, current); err == nil {
		t.Fatal("expected insecure update URL rejection")
	}
}
