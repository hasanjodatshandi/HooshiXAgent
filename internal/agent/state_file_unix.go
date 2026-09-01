//go:build !windows

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func readTrustedStateFile(path string) ([]byte, os.FileMode, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, 0, fmt.Errorf("refusing symlink state file: %s", path)
		}
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, 0, errors.New("open state file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("state file is not a regular non-symlink file: %s", path)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode(), nil
}

func validateStateDirectoryPath(path string, allowMissing bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absolute = filepath.Clean(absolute)
	root := filepath.Clean(filepath.VolumeName(absolute) + string(os.PathSeparator))
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return err
	}
	current := root
	for _, part := range splitStatePathComponents(relative) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if allowMissing {
				return nil
			}
			return err
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("state directory path component must be a real directory: %s", current)
		}
	}
	return nil
}

func protectPrivateDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private state directory permissions are not owner-only")
	}
	return nil
}

func protectPrivateStateFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	_, mode, err := readTrustedStateFile(path)
	if err != nil {
		return err
	}
	if mode.Perm()&0o077 != 0 {
		return errors.New("private state file permissions are not owner-only")
	}
	return nil
}

func splitStatePathComponents(relative string) []string {
	var parts []string
	for relative != "." && relative != "" {
		dir, base := filepath.Split(relative)
		if base != "" {
			parts = append([]string{base}, parts...)
		}
		relative = filepath.Clean(dir)
		if relative == string(os.PathSeparator) {
			break
		}
	}
	return parts
}
