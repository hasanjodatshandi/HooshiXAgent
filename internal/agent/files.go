package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const stateMarkerName = ".hooshix-agent-state"

var stateMarkerContents = []byte("hooshix-agent-state-v1\n")

func inspectPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state directory must be a real directory")
	}
	markerPath := filepath.Join(path, stateMarkerName)
	marker, err := readStateFile(markerPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("Agent state marker is missing; run init or configure to initialize/adopt state")
		}
		return fmt.Errorf("read Agent state marker: %w", err)
	}
	if !bytes.Equal(marker, stateMarkerContents) {
		return errors.New("Agent state marker contents are invalid")
	}
	return nil
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state directory must not be a symlink")
		}
		if !info.IsDir() {
			return errors.New("state directory path is not a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect private state directory: %w", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state directory must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("protect private state directory: %w", err)
	}
	if err := ensureStateMarker(path); err != nil {
		return err
	}
	return nil
}

func ensureStateMarker(stateDir string) error {
	path := filepath.Join(stateDir, stateMarkerName)
	data, err := readStateFile(path)
	if err == nil {
		if !bytes.Equal(data, stateMarkerContents) {
			return errors.New("Agent state marker contents are invalid")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read Agent state marker: %w", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return fmt.Errorf("inspect Agent state directory ownership: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == configLockName || name == "config.json" || name == "secrets.json" || name == "secrets.dpapi" || strings.HasPrefix(name, ".tmp-hooshix-") {
			continue
		}
		return fmt.Errorf("refusing unowned non-empty Agent state directory: unexpected entry %q", name)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ensureStateMarker(stateDir)
		}
		return fmt.Errorf("create Agent state marker: %w", err)
	}
	if _, err := file.Write(stateMarkerContents); err != nil {
		file.Close()
		return fmt.Errorf("write Agent state marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync Agent state marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close Agent state marker: %w", err)
	}
	return nil
}

func readStateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink file: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("state file is not a regular file: %s", path)
	}
	return os.ReadFile(path)
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
