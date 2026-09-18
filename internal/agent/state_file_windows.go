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

// Windows state-file confidentiality policy
//
// The confidentiality boundary for agent state on Windows is:
//
//  1. DPAPI with CRYPTPROTECT_UI_FORBIDDEN under the CurrentUser scope, owned
//     by the account that wrote the blob (LocalSystem for the service), so the
//     secret store is readable only by that account; and
//  2. the explicit ACLs the installer applies to the state directory and to
//     pairing.capability (SYSTEM, Administrators, and the interactive desktop
//     user — nobody else), in cmd/hooshix-setup.
//
// The agent runtime therefore does NOT touch DACLs. The previous
// grantAdministratorsRead helper rewrote the DACL of every state file on every
// read with only DACL_SECURITY_INFORMATION: that ADDED two explicit Full-Access
// ACEs and KEPT every inherited ACE (it never protected or replaced the DACL,
// despite the SDDL looking like a replacement), and it discarded the
// SetNamedSecurityInfo return value, so it silently widened access and could
// never report failure. Its caller protectPrivateStateFile ran from the read
// path and was named as if it restricted access.
//
// What remains here is the part the agent itself can enforce and report:
// validating that a state path is a real, non-reparse file or directory.

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

// protectPrivateDirectory validates the state directory path. Windows mode bits
// are not an ACL substitute, so nothing is chmod-ed (the install-time ACL is
// authoritative).
func protectPrivateDirectory(path string) error {
	return validateStateDirectoryPath(path, false)
}

// protectPrivateStateFile verifies that the state file exists and is a regular,
// non-reparse file, and reports any failure to the caller. It deliberately does
// not modify the file's DACL: see the policy note at the top of this file.
func protectPrivateStateFile(path string) error {
	if _, _, err := readTrustedStateFile(path); err != nil {
		return err
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
