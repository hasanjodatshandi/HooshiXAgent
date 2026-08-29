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

func NewPlatformSecretStore(stateDir string) SecretStore {
	return &fileSecretStore{stateDir: stateDir, path: stateRelativePath(stateDir, "secrets.json")}
}

func (store *fileSecretStore) Kind() string { return "private-file" }

func (store *fileSecretStore) Load() (SecretState, error) {
	if err := ensurePrivateDir(store.stateDir); err != nil {
		return SecretState{}, err
	}
	info, err := os.Lstat(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SecretState{}, nil
		}
		return SecretState{}, fmt.Errorf("inspect secret file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return SecretState{}, errors.New("secret file must not be a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return SecretState{}, fmt.Errorf("secret file permissions are too broad: %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		return SecretState{}, fmt.Errorf("read secret file: %w", err)
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
