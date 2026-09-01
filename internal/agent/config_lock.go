package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	configLockName        = ".config.lock"
	configLockWait        = 5 * time.Second
	configLockPoll        = 10 * time.Millisecond
	legacyLockStaleAfter  = 30 * time.Second
	configLockFileVersion = 1
)

type configLockRecord struct {
	Version   int    `json:"version"`
	PID       int    `json:"pid"`
	CreatedAt string `json:"created_at"`
}

func withConfigLock(stateDir string, operation func() error) error {
	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	lockPath := filepath.Join(stateDir, configLockName)
	deadline := time.Now().Add(configLockWait)
	for {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			record := configLockRecord{Version: configLockFileVersion, PID: os.Getpid(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			data, encodeErr := json.Marshal(record)
			if encodeErr == nil {
				data = append(data, '\n')
				_, encodeErr = lockFile.Write(data)
			}
			if encodeErr == nil {
				encodeErr = lockFile.Sync()
			}
			if closeErr := lockFile.Close(); encodeErr == nil && closeErr != nil {
				encodeErr = closeErr
			}
			if encodeErr != nil {
				_ = os.Remove(lockPath)
				return fmt.Errorf("initialize config lock: %w", encodeErr)
			}
			defer os.Remove(lockPath)
			if err := recoverStateTransaction(stateDir); err != nil {
				return err
			}
			return operation()
		}
		if !errors.Is(err, os.ErrExist) {
			// Windows can report an existing directory or another incompatible lock object
			// as a generic OpenFile error instead of os.ErrExist. If the path now exists,
			// route it through the same fail-closed inspection used for normal contention.
			if _, inspectErr := os.Lstat(lockPath); inspectErr != nil {
				if errors.Is(inspectErr, os.ErrNotExist) {
					return fmt.Errorf("create config lock: %w", err)
				}
				return fmt.Errorf("inspect config lock after create failure: %w", inspectErr)
			}
		}
		reclaimed, inspectErr := reclaimStaleConfigLock(lockPath, time.Now().UTC())
		if inspectErr != nil {
			return inspectErr
		}
		if reclaimed {
			continue
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for live config lock")
		}
		time.Sleep(configLockPoll)
	}
}

func reclaimStaleConfigLock(lockPath string, now time.Time) (bool, error) {
	return reclaimStaleConfigLockWithProcessCheck(lockPath, now, processAlive)
}

func reclaimStaleConfigLockWithProcessCheck(lockPath string, now time.Time, alive func(int) bool) (bool, error) {
	info, err := os.Lstat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect config lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, errors.New("config lock path is not a private regular file")
	}
	data, err := os.ReadFile(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read config lock: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if now.Sub(info.ModTime()) < legacyLockStaleAfter {
			return false, nil
		}
		return removeUnchangedLock(lockPath, data, info.ModTime())
	}
	record, err := decodeConfigLockRecord(data)
	if err != nil {
		return false, fmt.Errorf("invalid config lock metadata: %w", err)
	}
	// Contention between goroutines in this process is unquestionably live and should
	// not perform an expensive platform process query on every poll. This also avoids
	// Windows handle churn under high local mutation concurrency.
	if record.PID == os.Getpid() || alive(record.PID) {
		return false, nil
	}
	return removeUnchangedLock(lockPath, data, info.ModTime())
}

func decodeConfigLockRecord(data []byte) (configLockRecord, error) {
	var record configLockRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return record, errors.New("trailing JSON value")
		}
		return record, err
	}
	if record.Version != configLockFileVersion || record.PID <= 0 {
		return record, errors.New("unsupported config lock metadata")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return record, errors.New("invalid config lock created_at")
	}
	return record, nil
}

func removeUnchangedLock(lockPath string, expected []byte, expectedModTime time.Time) (bool, error) {
	info, err := os.Lstat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reinspect config lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !info.ModTime().Equal(expectedModTime) {
		return false, nil
	}
	current, err := os.ReadFile(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reread config lock: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return false, nil
	}
	if err := os.Remove(lockPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("remove stale config lock: %w", err)
	}
	return true, nil
}
