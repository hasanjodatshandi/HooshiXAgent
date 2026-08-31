package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	configLockName = ".config.lock"
	configLockWait = 5 * time.Second
	configLockPoll = 10 * time.Millisecond
)

func withConfigLock(stateDir string, operation func() error) error {
	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	lockPath := filepath.Join(stateDir, configLockName)
	deadline := time.Now().Add(configLockWait)
	for {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			if closeErr := lockFile.Close(); closeErr != nil {
				_ = os.Remove(lockPath)
				return fmt.Errorf("close config lock: %w", closeErr)
			}
			defer os.Remove(lockPath)
			return operation()
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire config lock: %w", err)
		}
		info, statErr := os.Lstat(lockPath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("inspect config lock: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("config lock path is not a private regular file")
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for config lock")
		}
		time.Sleep(configLockPoll)
	}
}
