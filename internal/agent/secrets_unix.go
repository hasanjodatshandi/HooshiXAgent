//go:build !windows

package agent

import (
	"errors"
	"fmt"
	"os"
)

type fileSecretStore struct {
	stateDir string
	path     string
}

func platformSecretPath(stateDir string) string { return stateRelativePath(stateDir, "secrets.json") }

func NewPlatformSecretStore(stateDir string) SecretStore {
	return &fileSecretStore{stateDir: stateDir, path: platformSecretPath(stateDir)}
}

func (store *fileSecretStore) Kind() string { return "private-file" }

func (store *fileSecretStore) PrepareMutation() error { return ensurePrivateDir(store.stateDir) }

func (store *fileSecretStore) Load() (SecretState, error) {
	if err := ensureStateReadable(store.stateDir); err != nil {
		return SecretState{}, err
	}
	return store.LoadForMutation()
}

func (store *fileSecretStore) LoadForMutation() (SecretState, error) {
	if err := inspectPrivateDir(store.stateDir); err != nil {
		return SecretState{}, err
	}
	data, mode, err := readTrustedStateFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SecretState{}, nil
		}
		return SecretState{}, fmt.Errorf("read secret file: %w", err)
	}
	if mode.Perm()&0o077 != 0 {
		return SecretState{}, fmt.Errorf("secret file permissions are too broad: %04o", mode.Perm())
	}
	return decodeSecretState(data)
}

func (store *fileSecretStore) Save(state SecretState) error {
	data, err := encodeSecretState(state)
	if err != nil {
		return err
	}
	return writePrivateFile(store.stateDir, store.path, data)
}
