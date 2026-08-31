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
		info, statErr := os.Lstat(lockPath)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("config lock path is not a private regular file")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) && !errors.Is(statErr, os.ErrPermission) {
			return fmt.Errorf("inspect config lock: %w", statErr)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for config lock after create error: %w", err)
		}
		time.Sleep(configLockPoll)
	}
}
