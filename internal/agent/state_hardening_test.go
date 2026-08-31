package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic entropy failure")
}

type memorySecretStore struct {
	mu    sync.Mutex
	state SecretState
}

func (store *memorySecretStore) Load() (SecretState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state, nil
}

func (store *memorySecretStore) Save(state SecretState) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state = state
	return nil
}

func (*memorySecretStore) Kind() string { return "memory-test" }

func TestLoadConfigRejectsTrailingJSONData(t *testing.T) {
	dir := t.TempDir()
	if err := SaveConfig(dir, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(ConfigPath(dir), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"version":1}`); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing JSON must fail closed, got %v", err)
	}
}


func TestConfigFileSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not guaranteed on Windows CI")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target-config.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"update_channel":"stable"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ConfigPath(dir)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadConfig(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("config symlink must fail closed, got %v", err)
	}
}

func TestSecretStateRejectsTrailingAndUnknownJSON(t *testing.T) {
	if _, err := decodeSecretState([]byte(`{"seed":"abc"}{"seed":"def"}`)); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("secret trailing JSON must fail closed, got %v", err)
	}
	if _, err := decodeSecretState([]byte(`{"seed":"abc","unexpected":true}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown secret field must fail closed, got %v", err)
	}
}

func TestStateMarkerAdoptsLegacyKnownStateFiles(t *testing.T) {
	dir := t.TempDir()
	config := []byte("{\n  \"version\": 1,\n  \"update_channel\": \"stable\"\n}\n")
	if err := os.WriteFile(ConfigPath(dir), config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MutateConfig(dir, func(config *Config) error {
		config.SetEndpoint(Endpoint{ID: "legacy-001", Target: "127.0.0.1:8080"})
		return nil
	}); err != nil {
		t.Fatalf("known legacy state must be adopted safely: %v", err)
	}
	marker, err := os.ReadFile(filepath.Join(dir, stateMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != string(stateMarkerContents) {
		t.Fatalf("state marker=%q want=%q", marker, stateMarkerContents)
	}
}

func TestConcurrentConfigMutationPreservesEveryEndpoint(t *testing.T) {
	dir := t.TempDir()
	if err := SaveConfig(dir, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	const mutations = 64
	var wg sync.WaitGroup
	errs := make(chan error, mutations)
	for i := 0; i < mutations; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := "concurrent-" + leftPadDecimal(i, 3)
			err := MutateConfig(dir, func(config *Config) error {
				config.SetEndpoint(Endpoint{ID: id, Target: "127.0.0.1:8080"})
				return nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	config, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Endpoints) != mutations {
		t.Fatalf("endpoint count=%d want=%d", len(config.Endpoints), mutations)
	}
	seen := make(map[string]struct{}, mutations)
	for _, endpoint := range config.Endpoints {
		seen[endpoint.ID] = struct{}{}
	}
	for i := 0; i < mutations; i++ {
		id := "concurrent-" + leftPadDecimal(i, 3)
		if _, ok := seen[id]; !ok {
			t.Fatalf("concurrent mutation lost endpoint %s", id)
		}
	}
}

func TestStateDirectorySafetyRejectsRootHomeAndSymlinks(t *testing.T) {
	root := filepath.Clean(filepath.VolumeName(t.TempDir()) + string(os.PathSeparator))
	if _, err := NormalizeStateDir(root); err == nil {
		t.Fatalf("filesystem root %q accepted as state directory", root)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := NormalizeStateDir(home); err == nil {
			t.Fatalf("user home %q accepted as state directory", home)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := NormalizeStateDir(link); err == nil {
		t.Fatal("state directory symlink was accepted")
	}
}

func TestStateDirectoryOwnershipRejectsUnrelatedNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "user-data.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(dir, DefaultConfig()); err == nil || !strings.Contains(err.Error(), "unowned") {
		t.Fatalf("unowned non-empty state directory must fail closed, got %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "keep" {
		t.Fatalf("unowned sentinel changed: data=%q err=%v", data, err)
	}
}

func TestConfigLockRejectsUnsafeLockObject(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, configLockName)
	if err := os.WriteFile(lockPath, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MutateConfig(dir, func(*Config) error { return nil }); err == nil || !strings.Contains(err.Error(), "config lock path") {
		t.Fatalf("unsafe config lock object must fail closed, got %v", err)
	}
}

func TestEntropyFailuresReturnErrorsWithoutPersistingWeakState(t *testing.T) {
	store := &memorySecretStore{}
	if _, _, err := loadOrCreateIdentity(store, failingEntropyReader{}); err == nil || !strings.Contains(err.Error(), "generate Ed25519 seed") {
		t.Fatalf("identity entropy failure not returned: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Seed != "" {
		t.Fatal("identity seed was persisted after entropy failure")
	}
	if _, err := randomNonceFrom(failingEntropyReader{}); err == nil || !strings.Contains(err.Error(), "generate client nonce") {
		t.Fatalf("nonce entropy failure not returned: %v", err)
	}
}

func leftPadDecimal(value, width int) string {
	text := ""
	if value == 0 {
		text = "0"
	} else {
		for value > 0 {
			text = string(rune('0'+value%10)) + text
			value /= 10
		}
	}
	for len(text) < width {
		text = "0" + text
	}
	return text
}
