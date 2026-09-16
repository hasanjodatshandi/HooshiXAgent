//go:build windows

package tray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// notificationsFile is the per-user tray settings file. It lives next to
// tray.log under LOCALAPPDATA\HooshiXAgent so an uninstall removes it with
// the rest of the user state.
const notificationsFile = "settings.json"

// traySettings is the persisted user preference subset.
type traySettings struct {
	BalloonsEnabled bool `json:"balloons_enabled"`
}

// settingsStore is a tiny thread-safe accessor over the settings file. The
// default is balloons enabled: the notification feature ships on.
type settingsStore struct {
	mu         sync.Mutex
	path       string
	loaded     bool
	balloonsOn bool
}

func newSettingsStore(dir string) *settingsStore {
	if dir == "" {
		dir = "."
	}
	return &settingsStore{path: filepath.Join(dir, notificationsFile), balloonsOn: true}
}

// enabled loads (once) and returns the balloon preference.
func (store *settingsStore) enabled() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.loaded {
		store.loaded = true
		store.balloonsOn = loadSettings(store.path)
	}
	return store.balloonsOn
}

// setEnabled persists the balloon preference and updates the cached value.
func (store *settingsStore) setEnabled(value bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.balloonsOn = value
	store.loaded = true
	if err := saveSettings(store.path, value); err != nil {
		if logger := currentTrayLogger(); logger != nil {
			logger.Warn("persist notification setting failed", "error", err)
		}
	}
}

// loadSettings reads the settings file; any error means "use the default".
func loadSettings(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var parsed traySettings
	if json.Unmarshal(data, &parsed) != nil {
		return true
	}
	return parsed.BalloonsEnabled
}

// saveSettings writes the settings file atomically (tmp + rename).
func saveSettings(path string, value bool) error {
	data, err := json.Marshal(traySettings{BalloonsEnabled: value})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
