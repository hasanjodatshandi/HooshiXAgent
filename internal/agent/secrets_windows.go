//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const cryptprotectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

type dpapiSecretStore struct {
	stateDir string
	path     string
}

var (
	crypt32DLL         = syscall.NewLazyDLL("crypt32.dll")
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	cryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	localFree          = kernel32DLL.NewProc("LocalFree")
)

func platformSecretPath(stateDir string) string { return stateRelativePath(stateDir, "secrets.dpapi") }

func NewPlatformSecretStore(stateDir string) SecretStore {
	return &dpapiSecretStore{stateDir: stateDir, path: platformSecretPath(stateDir)}
}

func (store *dpapiSecretStore) Kind() string { return "windows-dpapi-current-user" }

func (store *dpapiSecretStore) PrepareMutation() error { return ensurePrivateDir(store.stateDir) }

func (store *dpapiSecretStore) Load() (SecretState, error) {
	if err := ensureStateReadable(store.stateDir); err != nil {
		return SecretState{}, err
	}
	return store.LoadForMutation()
}

func (store *dpapiSecretStore) LoadForMutation() (SecretState, error) {
	if err := inspectPrivateDir(store.stateDir); err != nil {
		return SecretState{}, err
	}
	protected, _, err := readTrustedStateFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SecretState{}, nil
		}
		return SecretState{}, fmt.Errorf("read DPAPI secret file: %w", err)
	}
	plain, err := dpapiUnprotect(protected)
	if err != nil {
		return SecretState{}, err
	}
	defer zeroBytes(plain)
	return decodeSecretState(plain)
}

func (store *dpapiSecretStore) Save(state SecretState) error {
	plain, err := encodeSecretState(state)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)
	protected, err := dpapiProtect(plain)
	if err != nil {
		return err
	}
	return writePrivateFile(store.stateDir, store.path, protected)
}

func dpapiProtect(plain []byte) ([]byte, error) {
	input, err := blobFromBytes(plain)
	if err != nil {
		return nil, err
	}
	var output dataBlob
	result, _, callErr := cryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", callErr)
	}
	return copyAndFreeBlob(output), nil
}

func dpapiUnprotect(protected []byte) ([]byte, error) {
	input, err := blobFromBytes(protected)
	if err != nil {
		return nil, err
	}
	var output dataBlob
	result, _, callErr := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", callErr)
	}
	return copyAndFreeBlob(output), nil
}

func blobFromBytes(data []byte) (dataBlob, error) {
	if len(data) == 0 {
		return dataBlob{}, nil
	}
	length, err := dpapiBlobLength(len(data))
	if err != nil {
		return dataBlob{}, err
	}
	return dataBlob{cbData: length, pbData: &data[0]}, nil
}

// maxDPAPIBlobBytes is the largest buffer the Win32 CRYPT_DATA_BLOB cbData
// field can describe.
const maxDPAPIBlobBytes = uint64(^uint32(0))

// dpapiBlobLength converts a Go byte count into the 32-bit cbData field. A
// longer buffer must be refused instead of wrapped: silently truncating the
// length would hand CryptProtectData only the first part of a secret and write
// a blob that later decrypts into corrupt state. The conversion lives apart
// from blobFromBytes so the bound is testable without a 4 GiB allocation.
func dpapiBlobLength(length int) (uint32, error) {
	if uint64(length) > maxDPAPIBlobBytes {
		return 0, fmt.Errorf("DPAPI input of %d bytes exceeds the %d byte Win32 blob limit", length, maxDPAPIBlobBytes)
	}
	return uint32(length), nil
}

func copyAndFreeBlob(blob dataBlob) []byte {
	if blob.pbData == nil || blob.cbData == 0 {
		return nil
	}
	defer localFree.Call(uintptr(unsafe.Pointer(blob.pbData)))
	view := unsafe.Slice(blob.pbData, int(blob.cbData))
	return append([]byte(nil), view...)
}
