package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private state directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("protect private state directory: %w", err)
	}
	return nil
}

func writePrivateFile(stateDir, path string, data []byte) error {
	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect private file: %w", err)
	}
	temp, err := os.CreateTemp(stateDir, ".tmp-hooshix-*")
	if err != nil {
		return fmt.Errorf("create private temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("chmod private temp file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write private temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync private temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close private temp file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("protect private file: %w", err)
	}
	return nil
}

func stateRelativePath(stateDir, name string) string {
	return filepath.Join(stateDir, name)
}
