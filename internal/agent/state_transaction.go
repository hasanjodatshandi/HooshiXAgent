package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	stateTransactionName         = ".state-transaction"
	stateTransactionManifestName = "manifest.json"
	stateTransactionVersion      = 1
)

var ErrStateTransactionPending = errors.New("Agent state transaction recovery required")

type stateTransactionManifest struct {
	Version      int  `json:"version"`
	ConfigExists bool `json:"config_exists"`
	SecretExists bool `json:"secret_exists"`
}

type stateMutationFaults struct {
	afterConfigSave func() error
	afterSecretSave func() error
}

func initializeAgentState(stateDir string, store SecretStore, faults stateMutationFaults) (publicKey []byte, err error) {
	err = withConfigLock(stateDir, func() error {
		return runStateTransaction(stateDir, func() error {
			config, err := loadConfigUnlocked(stateDir)
			if err != nil {
				return err
			}
			if err := saveConfigUnlocked(stateDir, config); err != nil {
				return err
			}
			if faults.afterConfigSave != nil {
				if err := faults.afterConfigSave(); err != nil {
					return err
				}
			}
			key, _, err := LoadOrCreateIdentity(store)
			if err != nil {
				return err
			}
			publicKey = append(publicKey[:0], key...)
			if faults.afterSecretSave != nil {
				if err := faults.afterSecretSave(); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return publicKey, err
}

func configureAgentState(stateDir string, store SecretStore, requested Config, token string, faults stateMutationFaults) (configured Config, err error) {
	err = withConfigLock(stateDir, func() error {
		return runStateTransaction(stateDir, func() error {
			current, err := loadConfigUnlocked(stateDir)
			if err != nil {
				return err
			}
			current.GatewayURL = requested.GatewayURL
			current.CAFile = requested.CAFile
			current.DeviceID = requested.DeviceID
			current.AuthorizationID = requested.AuthorizationID
			current.TokenID = requested.TokenID
			current.UpdateChannel = requested.UpdateChannel
			if err := current.ValidateRuntime(); err != nil {
				return err
			}
			if _, _, err := LoadOrCreateIdentity(store); err != nil {
				return err
			}
			if err := saveConfigUnlocked(stateDir, current); err != nil {
				return err
			}
			if faults.afterConfigSave != nil {
				if err := faults.afterConfigSave(); err != nil {
					return err
				}
			}
			if err := SetSessionToken(store, token); err != nil {
				return err
			}
			if faults.afterSecretSave != nil {
				if err := faults.afterSecretSave(); err != nil {
					return err
				}
			}
			configured = current
			return nil
		})
	})
	return configured, err
}

type stateTransaction struct {
	stateDir string
	path     string
}

func stateTransactionPath(stateDir string) string {
	return filepath.Join(stateDir, stateTransactionName)
}

func ensureStateReadable(stateDir string) error {
	path := stateTransactionPath(stateDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Agent state transaction: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Agent state transaction path must be a real directory")
	}
	return fmt.Errorf("%w: run init/configure/expose to recover the interrupted mutation", ErrStateTransactionPending)
}

func beginStateTransaction(stateDir string) (*stateTransaction, error) {
	path := stateTransactionPath(stateDir)
	if _, err := os.Lstat(path); err == nil {
		return nil, ErrStateTransactionPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Agent state transaction: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("create Agent state transaction: %w", err)
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = os.RemoveAll(path)
		}
	}()

	configExists, err := snapshotStateFile(ConfigPath(stateDir), filepath.Join(path, "config.before"))
	if err != nil {
		return nil, err
	}
	secretExists, err := snapshotStateFile(platformSecretPath(stateDir), filepath.Join(path, "secret.before"))
	if err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(stateTransactionManifest{Version: stateTransactionVersion, ConfigExists: configExists, SecretExists: secretExists})
	if err != nil {
		return nil, fmt.Errorf("encode Agent state transaction manifest: %w", err)
	}
	if err := writeTransactionFileAtomic(path, stateTransactionManifestName, append(manifest, '\n')); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, fmt.Errorf("sync Agent state transaction: %w", err)
	}
	if err := syncDirectory(stateDir); err != nil {
		return nil, fmt.Errorf("publish Agent state transaction: %w", err)
	}
	prepared = true
	return &stateTransaction{stateDir: stateDir, path: path}, nil
}

func runStateTransaction(stateDir string, operation func() error) error {
	txn, err := beginStateTransaction(stateDir)
	if err != nil {
		return err
	}
	if err := operation(); err != nil {
		if rollbackErr := txn.rollback(); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback Agent state transaction: %w", rollbackErr))
		}
		return err
	}
	return txn.commit()
}

func (txn *stateTransaction) commit() error {
	if err := syncDirectory(txn.stateDir); err != nil {
		return fmt.Errorf("sync Agent state before transaction commit: %w", err)
	}
	if err := os.RemoveAll(txn.path); err != nil {
		return fmt.Errorf("commit Agent state transaction: %w", err)
	}
	if err := syncDirectory(txn.stateDir); err != nil {
		return fmt.Errorf("sync Agent state transaction commit: %w", err)
	}
	return nil
}

func (txn *stateTransaction) rollback() error {
	return recoverStateTransaction(txn.stateDir)
}

func recoverStateTransaction(stateDir string) error {
	path := stateTransactionPath(stateDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Agent state transaction: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Agent state transaction path must be a real directory")
	}
	manifestPath := filepath.Join(path, stateTransactionManifestName)
	data, err := readStateFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		// State mutation starts only after the manifest is durably published. A transaction
		// directory without a manifest is therefore a preparation remnant and is safe to remove.
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove incomplete Agent state transaction: %w", err)
		}
		return syncDirectory(stateDir)
	}
	if err != nil {
		return fmt.Errorf("read Agent state transaction manifest: %w", err)
	}
	var manifest stateTransactionManifest
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Version != stateTransactionVersion {
		return errors.New("Agent state transaction manifest is invalid")
	}
	if err := restoreStateFile(stateDir, ConfigPath(stateDir), filepath.Join(path, "config.before"), manifest.ConfigExists); err != nil {
		return fmt.Errorf("restore config from Agent state transaction: %w", err)
	}
	if err := restoreStateFile(stateDir, platformSecretPath(stateDir), filepath.Join(path, "secret.before"), manifest.SecretExists); err != nil {
		return fmt.Errorf("restore secrets from Agent state transaction: %w", err)
	}
	if err := syncDirectory(stateDir); err != nil {
		return fmt.Errorf("sync recovered Agent state: %w", err)
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove recovered Agent state transaction: %w", err)
	}
	return syncDirectory(stateDir)
}

func snapshotStateFile(source, backup string) (bool, error) {
	data, err := readStateFile(source)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("snapshot state file %s: %w", filepath.Base(source), err)
	}
	if err := writeExclusivePrivateFile(backup, data); err != nil {
		return false, fmt.Errorf("write state transaction backup %s: %w", filepath.Base(source), err)
	}
	return true, nil
}

func restoreStateFile(stateDir, destination, backup string, existed bool) error {
	if !existed {
		info, err := os.Lstat(destination)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing to remove unsafe state file during rollback")
		}
		return os.Remove(destination)
	}
	data, err := readStateFile(backup)
	if err != nil {
		return err
	}
	return writePrivateFile(stateDir, destination, data)
}

func writeTransactionFileAtomic(dir, name string, data []byte) error {
	temp, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return fmt.Errorf("create Agent state transaction temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, filepath.Join(dir, name))
}

func writeExclusivePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
