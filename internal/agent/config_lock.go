package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
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

type processConfigLockEntry struct {
	mu   sync.Mutex
	refs int
}

var processConfigLocks = struct {
	sync.Mutex
	byStateDir map[string]*processConfigLockEntry
}{byStateDir: make(map[string]*processConfigLockEntry)}

func acquireProcessConfigLock(stateDir string) func() {
	processConfigLocks.Lock()
	entry := processConfigLocks.byStateDir[stateDir]
	if entry == nil {
		entry = &processConfigLockEntry{}
		processConfigLocks.byStateDir[stateDir] = entry
	}
	entry.refs++
	processConfigLocks.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		processConfigLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(processConfigLocks.byStateDir, stateDir)
		}
		processConfigLocks.Unlock()
	}
}

func withConfigLock(stateDir string, operation func() error) error {
	releaseProcessLock := acquireProcessConfigLock(stateDir)
	defer releaseProcessLock()

	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	lockPath := filepath.Join(stateDir, configLockName)
	deadline := time.Now().Add(configLockWait)
	lastObservation := ""
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
			if err := recoverStateTransaction(stateDir); err != nil {
				releaseErr := releaseOwnedConfigLock(lockPath, data)
				if releaseErr != nil {
					return errors.Join(err, releaseErr)
				}
				return err
			}
			operationErr := operation()
			releaseErr := releaseOwnedConfigLock(lockPath, data)
			if operationErr != nil && releaseErr != nil {
				return errors.Join(operationErr, releaseErr)
			}
			if operationErr != nil {
				return operationErr
			}
			return releaseErr
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
		now := time.Now().UTC()
		reclaimed, observation, inspectErr := inspectConfigLockWithProcessCheck(lockPath, now, processAlive)
		if inspectErr != nil {
			return inspectErr
		}
		if reclaimed {
			continue
		}
		// The bounded wait measures a stuck owner, not total queue depth. A new
		// owner record proves forward progress and safely renews the wait window.
		if observation != lastObservation {
			lastObservation = observation
			deadline = time.Now().Add(configLockWait)
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for live config lock")
		}
		time.Sleep(configLockPoll)
	}
}

func releaseOwnedConfigLock(lockPath string, expected []byte) error {
	deadline := time.Now().Add(configLockWait)
	for {
		current, err := os.ReadFile(lockPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read owned config lock before release: %w", err)
		}
		if !bytes.Equal(current, expected) {
			return errors.New("config lock ownership changed before release")
		}
		if err := os.Remove(lockPath); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("release config lock: %w", err)
		}
		time.Sleep(configLockPoll)
	}
}

func reclaimStaleConfigLock(lockPath string, now time.Time) (bool, error) {
	reclaimed, _, err := inspectConfigLockWithProcessCheck(lockPath, now, processAlive)
	return reclaimed, err
}

func reclaimStaleConfigLockWithProcessCheck(lockPath string, now time.Time, alive func(int) bool) (bool, error) {
	reclaimed, _, err := inspectConfigLockWithProcessCheck(lockPath, now, alive)
	return reclaimed, err
}

func inspectConfigLockWithProcessCheck(lockPath string, now time.Time, alive func(int) bool) (bool, string, error) {
	info, err := os.Lstat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("inspect config lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, "", errors.New("config lock path is not a private regular file")
	}
	data, err := os.ReadFile(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("read config lock: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if now.Sub(info.ModTime()) < legacyLockStaleAfter {
			return false, fmt.Sprintf("legacy:%d:%d", info.ModTime().UnixNano(), info.Size()), nil
		}
		reclaimed, err := removeUnchangedLock(lockPath, data, info.ModTime())
		return reclaimed, "", err
	}
	record, err := decodeConfigLockRecord(data)
	if err != nil {
		return false, "", fmt.Errorf("invalid config lock metadata: %w", err)
	}
	// Contention between goroutines in this process is unquestionably live and should
	// not perform an expensive platform process query on every poll. This also avoids
	// Windows handle churn under high local mutation concurrency.
	observation := string(data)
	if record.PID == os.Getpid() || alive(record.PID) {
		return false, observation, nil
	}
	reclaimed, err := removeUnchangedLock(lockPath, data, info.ModTime())
	return reclaimed, "", err
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
