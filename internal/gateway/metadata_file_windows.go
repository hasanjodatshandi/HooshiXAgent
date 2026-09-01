//go:build windows

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
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("open metadata file handle")
	}
	defer file.Close()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, errors.New("metadata path must be a regular non-reparse file")
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	if size > maxBytes {
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
	root := filepath.VolumeName(absolute) + string(os.PathSeparator)
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return err
	}
	current := root
	for _, part := range splitPathComponents(relative) {
		current = filepath.Join(current, part)
		ptr, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attrs, err := syscall.GetFileAttributes(ptr)
		if err != nil {
			if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
				if allowMissing {
					return nil
				}
				return err
			}
			return err
		}
		if attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("metadata directory path component must be a real non-reparse directory: %s", current)
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
