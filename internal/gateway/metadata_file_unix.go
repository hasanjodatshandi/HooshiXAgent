//go:build !windows

package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func readTrustedMetadataFile(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("metadata path must be a regular non-symlink file")
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open metadata file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("metadata path must be a regular non-symlink file")
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("metadata file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("metadata file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func validateTrustedMetadataDirectory(path string, allowMissing bool) error {
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
	for _, part := range splitPathComponents(relative) {
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
			return fmt.Errorf("metadata directory path component must be a real directory: %s", current)
		}
	}
	return nil
}

func splitPathComponents(relative string) []string {
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
