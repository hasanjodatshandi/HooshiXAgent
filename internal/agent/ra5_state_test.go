package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRA5InitTransactionRollsBackPartialState(t *testing.T) {
	phases := []struct {
		name   string
		faults stateMutationFaults
	}{
		{name: "after-config", faults: stateMutationFaults{afterConfigSave: func() error { return errors.New("synthetic after-config failure") }}},
		{name: "after-secret", faults: stateMutationFaults{afterSecretSave: func() error { return errors.New("synthetic after-secret failure") }}},
	}
	for _, test := range phases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			store := NewPlatformSecretStore(dir)
			if _, err := initializeAgentState(dir, store, test.faults); err == nil {
				t.Fatal("fault-injected init unexpectedly succeeded")
			}
			for _, path := range []string{ConfigPath(dir), platformSecretPath(dir), stateTransactionPath(dir), filepath.Join(dir, configLockName)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("partial init artifact remained at %s: %v", filepath.Base(path), err)
				}
			}
			if _, _, err := LoadIdentity(store); err == nil {
				t.Fatal("failed init left an identity behind")
			}
			if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
				t.Fatalf("clean retry after rolled-back init failed: %v", err)
			}
		})
	}
}

func TestRA5ConfigureTransactionRestoresConfigAndSecret(t *testing.T) {
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	oldToken := "old_session_token_0123456789ABCDEFGH"
	oldRequested := ra5RequestedConfig("device-old", "auth-old", "token-old")
	if _, err := configureAgentState(dir, store, oldRequested, oldToken, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretBefore, err := os.ReadFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	publicBefore, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}

	newToken := "new_session_token_0123456789ABCDEFGH"
	newRequested := ra5RequestedConfig("device-new", "auth-new", "token-new")
	_, err = configureAgentState(dir, store, newRequested, newToken, stateMutationFaults{
		afterSecretSave: func() error { return errors.New("synthetic commit failure") },
	})
	if err == nil {
		t.Fatal("fault-injected configure unexpectedly succeeded")
	}
	configAfter, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	secretAfter, err := os.ReadFile(platformSecretPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) {
		t.Fatal("config changed after configure transaction rollback")
	}
	if !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("secret state changed after configure transaction rollback")
	}
	if token, err := LoadSessionToken(store); err != nil || token != oldToken {
		t.Fatalf("session token after rollback=%q err=%v", token, err)
	}
	publicAfter, _, err := LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicBefore, publicAfter) {
		t.Fatal("identity changed after configure rollback")
	}
	if _, err := os.Lstat(stateTransactionPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction journal remained after successful rollback: %v", err)
	}
}

func TestRA5InterruptedTransactionFailsReadsClosedAndMutationRecovers(t *testing.T) {
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	oldToken := "stable_session_token_0123456789ABCDEF"
	if _, err := configureAgentState(dir, store, ra5RequestedConfig("device-stable", "auth-stable", "token-stable"), oldToken, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}

	if err := withConfigLock(dir, func() error {
		if _, err := beginStateTransaction(dir); err != nil {
			return err
		}
		config, err := loadConfigUnlocked(dir)
		if err != nil {
			return err
		}
		config.DeviceID = "device-crash-partial"
		if err := saveConfigUnlocked(dir, config); err != nil {
			return err
		}
		return SetSessionToken(store, "partial_session_token_0123456789ABCDE")
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(dir); !errors.Is(err, ErrStateTransactionPending) {
		t.Fatalf("config read did not fail closed on interrupted transaction: %v", err)
	}
	if _, err := LoadSessionToken(store); !errors.Is(err, ErrStateTransactionPending) {
		t.Fatalf("secret read did not fail closed on interrupted transaction: %v", err)
	}
	var statusOut, statusErr bytes.Buffer
	if code := Main([]string{"status", "--state-dir", dir, "--json"}, strings.NewReader(""), &statusOut, &statusErr); code == 0 {
		t.Fatal("status recovered/masked an interrupted transaction")
	}
	if _, err := os.Lstat(stateTransactionPath(dir)); err != nil {
		t.Fatalf("read-only status mutated pending transaction: %v", err)
	}

	if err := MutateConfig(dir, func(config *Config) error {
		config.SetEndpoint(Endpoint{ID: "recovered-endpoint", Target: "127.0.0.1:8080"})
		return nil
	}); err != nil {
		t.Fatalf("mutation did not recover interrupted transaction: %v", err)
	}
	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.DeviceID != "device-stable" {
		t.Fatalf("partial config survived recovery: %q", config.DeviceID)
	}
	if _, ok := config.EndpointByID("recovered-endpoint"); !ok {
		t.Fatal("post-recovery mutation was not applied")
	}
	if token, err := LoadSessionToken(store); err != nil || token != oldToken {
		t.Fatalf("partial secret survived recovery: token=%q err=%v", token, err)
	}
	if _, err := os.Lstat(stateTransactionPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered transaction journal remained: %v", err)
	}
}

func TestRA5StatusDoctorAndRunDoNotCreateState(t *testing.T) {
	parent := t.TempDir()
	for _, command := range []string{"status", "doctor"} {
		t.Run(command, func(t *testing.T) {
			dir := filepath.Join(parent, "missing-"+command)
			var stdout, stderr bytes.Buffer
			if code := Main([]string{command, "--state-dir", dir}, strings.NewReader(""), &stdout, &stderr); code == 0 {
				t.Fatalf("%s unexpectedly succeeded on uninitialized state", command)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s created state directory: %v", command, err)
			}
		})
	}

	runDir := filepath.Join(parent, "missing-run")
	runner, err := NewRunner(runDir, DefaultLimits(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.runOnce(context.Background()); !errors.Is(err, ErrPermanentAgentFailure) {
		t.Fatalf("runOnce uninitialized error=%v want permanent", err)
	}
	if _, err := os.Lstat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run created state directory: %v", err)
	}
}

func TestRA5StatusAndDoctorAreByteForByteReadOnly(t *testing.T) {
	dir := t.TempDir()
	store := NewPlatformSecretStore(dir)
	if _, err := initializeAgentState(dir, store, stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	if _, err := configureAgentState(dir, store, ra5RequestedConfig("device-readonly", "auth-readonly", "token-readonly"), "readonly_session_token_0123456789ABCDE", stateMutationFaults{}); err != nil {
		t.Fatal(err)
	}
	before := snapshotRA5StateTree(t, dir)
	for _, command := range []string{"status", "doctor"} {
		var stdout, stderr bytes.Buffer
		args := []string{command, "--state-dir", dir}
		if command == "status" {
			args = append(args, "--json")
		}
		if code := Main(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("%s exit=%d stderr=%s", command, code, stderr.String())
		}
	}
	after := snapshotRA5StateTree(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("status/doctor mutated state tree\nbefore=%v\nafter=%v", before, after)
	}
}

func TestRA5ConfigLockReclaimsOnlyProvablyStaleOwner(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, configLockName)
	now := time.Now().UTC()
	record := configLockRecord{Version: configLockFileVersion, PID: 424242, CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(lockPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if reclaimed, err := reclaimStaleConfigLockWithProcessCheck(lockPath, now, func(int) bool { return true }); err != nil || reclaimed {
		t.Fatalf("live lock reclaimed=%t err=%v", reclaimed, err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("live lock disappeared: %v", err)
	}
	if reclaimed, err := reclaimStaleConfigLockWithProcessCheck(lockPath, now, func(int) bool { return false }); err != nil || !reclaimed {
		t.Fatalf("dead lock reclaimed=%t err=%v", reclaimed, err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead lock remained: %v", err)
	}

	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * legacyLockStaleAfter)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	if reclaimed, err := reclaimStaleConfigLockWithProcessCheck(lockPath, now, func(int) bool { return true }); err != nil || !reclaimed {
		t.Fatalf("legacy stale lock reclaimed=%t err=%v", reclaimed, err)
	}

	if err := os.WriteFile(lockPath, []byte("{malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reclaimed, err := reclaimStaleConfigLockWithProcessCheck(lockPath, now, func(int) bool { return false }); err == nil || reclaimed {
		t.Fatalf("malformed lock must fail closed: reclaimed=%t err=%v", reclaimed, err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("malformed lock was removed: %v", err)
	}
}

func TestRA5PermanentFailureStopsReconnectLoop(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	runner, err := NewRunner(t.TempDir(), limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	runner.attempt = func(context.Context) error {
		attempts.Add(1)
		return permanentAgentFailure(errors.New("configuration is permanently invalid"))
	}
	err = runner.Run(context.Background())
	if !errors.Is(err, ErrPermanentAgentFailure) {
		t.Fatalf("Run error=%v want permanent", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("permanent failure retried %d times", attempts.Load())
	}
	if !permanentRemoteSessionError(websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "authentication failed"}) {
		t.Fatal("policy violation was not classified permanent")
	}
	if permanentRemoteSessionError(websocket.CloseError{Code: websocket.StatusTryAgainLater, Reason: "overloaded"}) {
		t.Fatal("try-again-later was incorrectly classified permanent")
	}
	if !permanentRemoteSessionError(errors.New("invalid server_challenge frame")) {
		t.Fatal("non-transport protocol validation error was not classified permanent")
	}
	if permanentRemoteSessionError(io.EOF) || permanentRemoteSessionError(context.DeadlineExceeded) {
		t.Fatal("transport/end-of-stream condition was incorrectly classified permanent")
	}
	if !permanentDialError(errGatewayRedirect, nil) {
		t.Fatal("Gateway redirect was not classified permanent")
	}
	if !permanentDialError(errors.New("HTTP 401"), &http.Response{StatusCode: http.StatusUnauthorized}) {
		t.Fatal("HTTP 401 WebSocket handshake was not classified permanent")
	}
	if permanentDialError(errors.New("HTTP 429"), &http.Response{StatusCode: http.StatusTooManyRequests}) {
		t.Fatal("HTTP 429 WebSocket handshake was incorrectly classified permanent")
	}
}

func TestRA5RuntimeErrorSanitizationRedactsCredentials(t *testing.T) {
	known := "known_" + strings.Repeat("k", 32)
	wrapped := protectError(errors.New("gateway echoed bare credential "+known), known)
	if strings.Contains(wrapped.Error(), known) || !strings.Contains(wrapped.Error(), "<redacted>") {
		t.Fatalf("known secret was not redacted: %q", wrapped.Error())
	}
	jsonSecret := "json_" + strings.Repeat("j", 24)
	assignSecret := "assign_" + strings.Repeat("a", 24)
	spaceSecret := "space_" + strings.Repeat("s", 24)
	bearerSecret := "bearer_" + strings.Repeat("b", 24)
	cases := []struct {
		secret string
		input  string
	}{
		{secret: jsonSecret, input: `remote error {"session_token":"` + jsonSecret + `"}`},
		{secret: assignSecret, input: "session_token=" + assignSecret},
		{secret: spaceSecret, input: "credential " + spaceSecret},
		{secret: bearerSecret, input: "Bearer " + bearerSecret},
	}
	for _, test := range cases {
		got := sanitizedError(errors.New(test.input))
		if strings.Contains(got, test.secret) || !strings.Contains(got, "<redacted>") {
			t.Fatalf("sanitizer input=%q output=%q", test.input, got)
		}
	}
}

func ra5RequestedConfig(deviceID, authorizationID, tokenID string) Config {
	return Config{
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        deviceID,
		AuthorizationID: authorizationID,
		TokenID:         tokenID,
		UpdateChannel:   "stable",
	}
}

func snapshotRA5StateTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[relative] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
