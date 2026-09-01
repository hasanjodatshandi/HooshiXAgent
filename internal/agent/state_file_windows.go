//go:build windows

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
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, 0, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, 0, errors.New("open state file handle")
	}
	defer file.Close()
	var handleInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		return nil, 0, err
	}
	if handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, 0, fmt.Errorf("state file is not a regular non-reparse file: %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
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
	root := filepath.VolumeName(absolute) + string(os.PathSeparator)
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return err
	}
	current := root
	for _, part := range splitStatePathComponents(relative) {
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
			return fmt.Errorf("state directory path component must be a real non-reparse directory: %s", current)
		}
	}
	return nil
}

// DPAPI CurrentUser remains the confidentiality boundary on Windows. POSIX mode bits
// are not treated as a Windows ACL substitute; path/reparse validation is enforced here.
func protectPrivateDirectory(path string) error {
	return validateStateDirectoryPath(path, false)
}

func protectPrivateStateFile(path string) error {
	_, _, err := readTrustedStateFile(path)
	return err
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
