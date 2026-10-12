//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connectgui"
)

// dpapiProtector implements connectgui.Protector with the current user's DPAPI
// master key, which is what the rest of this product uses for secrets at rest.
//
// It deliberately carries its own copy of the Win32 blob plumbing instead of
// importing the Agent's secret store: that store is bound to a state directory
// and a schema belonging to a service this machine may not even run, and pulling
// internal/agent into the GUI would drag the whole Agent runtime into a binary
// the operator downloads onto a laptop that has never paired a device.
type dpapiProtector struct{}

func newProtector() connectgui.Protector { return dpapiProtector{} }

// savedBundleEntropy pins a sealed blob to this use. DPAPI entropy is not a
// password and stays in this binary, so it adds no secrecy, but it means a blob
// sealed here cannot be unsealed by whatever else in the same user profile calls
// DPAPI, and vice versa.
var savedBundleEntropy = []byte("hooshix-connect-bundle")

const cryptprotectUIForbidden = 0x1

// dataBlob mirrors the Win32 CRYPT_DATA_BLOB structure exactly.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	cryptProtectData   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	localFree          = windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalFree")
)

func (dpapiProtector) Seal(plaintext []byte) ([]byte, error) {
	return dpapiCall(cryptProtectData, "CryptProtectData", plaintext)
}

func (dpapiProtector) Open(sealed []byte) ([]byte, error) {
	return dpapiCall(cryptUnprotectData, "CryptUnprotectData", sealed)
}

func dpapiCall(proc *windows.LazyProc, name string, input []byte) ([]byte, error) {
	blob, err := blobFromBytes(input)
	if err != nil {
		return nil, fmt.Errorf("%s input: %w", name, err)
	}
	entropy, err := blobFromBytes(savedBundleEntropy)
	if err != nil {
		return nil, fmt.Errorf("%s entropy: %w", name, err)
	}
	var output dataBlob
	result, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(&blob)),
		0,
		uintptr(unsafe.Pointer(&entropy)),
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, fmt.Errorf("%s failed: %w", name, callErr)
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

// maxDPAPIBlobBytes is the largest buffer the Win32 CRYPT_DATA_BLOB cbData field
// can describe.
const maxDPAPIBlobBytes = uint64(^uint32(0))

// dpapiBlobLength converts a Go byte count into the 32-bit cbData field.
// Refusing a longer buffer is the only honest option: wrapping the length would
// protect a prefix of the input and write a blob that later opens as truncated,
// corrupt data. The bound lives apart from blobFromBytes so it is testable
// without a 4 GiB allocation.
func dpapiBlobLength(length int) (uint32, error) {
	if uint64(length) > maxDPAPIBlobBytes {
		return 0, fmt.Errorf("%d bytes exceeds the %d byte Win32 blob limit", length, maxDPAPIBlobBytes)
	}
	return uint32(length), nil
}

func copyAndFreeBlob(blob dataBlob) []byte {
	if blob.pbData == nil || blob.cbData == 0 {
		return nil
	}
	// The buffer belongs to Win32 and is released before this returns, so the
	// copy is what the caller keeps. Returning the view itself hands back memory
	// the local allocator has already freed, and DPAPI then "fails" on bytes that
	// were never the blob.
	defer localFree.Call(uintptr(unsafe.Pointer(blob.pbData)))
	return append([]byte(nil), unsafe.Slice(blob.pbData, int(blob.cbData))...)
}

// savedBundleState is what the window needs to know about the cfg beside its own
// executable before it can build its first layout.
type savedBundleState struct {
	store   *connectgui.BundleStore
	bundle  string
	savedAt string
	// problem explains why the app could not read or write a saved bundle. It is
	// never fatal: a laptop where the file cannot be written still gets a working
	// tunnel, it just has to paste the bundle again next time.
	problem error
}

// compact reports whether the window can drop its paste area: a run that woke up
// with a usable saved bundle has no use for a text box, and the operator who has
// nothing stored yet has no use for a window without one.
func (saved savedBundleState) compact() bool { return saved.bundle != "" }

// openSavedBundleStore locates the cfg for the running executable and reads it.
// executable comes from os.Executable, and is a parameter so a test can point it
// at a temporary directory instead of the real build output.
func openSavedBundleStore(executable string) savedBundleState {
	path, err := connectgui.BundlePathFor(executable)
	if err != nil {
		return savedBundleState{problem: err}
	}
	store, err := connectgui.NewBundleStore(path, newProtector())
	if err != nil {
		return savedBundleState{problem: err}
	}
	saved, err := store.Load()
	if err != nil {
		// The store stays: the next successful Connect overwrites a file this run
		// cannot open, so one stale cfg does not disable saving for good.
		return savedBundleState{store: store, problem: err}
	}
	return savedBundleState{store: store, bundle: saved.Bundle, savedAt: saved.SavedAt}
}
