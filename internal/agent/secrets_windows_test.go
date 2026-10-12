//go:build windows

package agent

import (
	"strings"
	"testing"
	"unsafe"
)

// Win32 CRYPT_DATA_BLOB carries a uint32 length. On a 64-bit build a Go byte
// count can exceed it, and wrapping that value silently would protect only the
// head of a secret and later decrypt into corrupt state. The bound lives in
// dpapiBlobLength precisely so it is testable without a 4 GiB allocation.
func TestDPAPIBlobLengthRefusesWhatCbDataCannotDescribe(t *testing.T) {
	t.Parallel()

	// A runtime conversion, because int(maxDPAPIBlobBytes) is a constant
	// expression that overflows the 32-bit int type and would not compile.
	var ceiling uint64 = maxDPAPIBlobBytes
	largest := int(ceiling)
	if largest < 0 {
		t.Skip("a 32-bit int cannot express the Win32 blob ceiling, so the overflow branch is unreachable on this build")
	}

	for _, tc := range []struct {
		name  string
		input int
		want  uint32
		err   bool
	}{
		{name: "zero", input: 0, want: 0},
		{name: "one byte", input: 1, want: 1},
		{name: "state file ceiling", input: maxSettingsFileBytes, want: maxSettingsFileBytes},
		{name: "largest describable", input: largest, want: ^uint32(0)},
		{name: "one past the limit", input: largest + 1, err: true},
		{name: "a full gigabyte past the limit", input: largest + (1 << 30), err: true},
	} {
		got, err := dpapiBlobLength(tc.input)
		if tc.err {
			if err == nil {
				t.Fatalf("%s: overflow accepted, got cbData=%d", tc.name, got)
			}
			if !strings.Contains(err.Error(), "Win32 blob limit") {
				t.Fatalf("%s: error must name the Win32 blob limit: %v", tc.name, err)
			}
			if got != 0 {
				t.Fatalf("%s: refused conversion must not return a length: %d", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: cbData=%d want %d", tc.name, got, tc.want)
		}
	}
}

// blobFromBytes is the only bridge from Go bytes to the Win32 struct, so both
// its empty-buffer case and its length/pointer pairing are pinned here: a wrong
// cbData or a pbData that is not the first byte of the caller's buffer
// corrupts the protected blob without any API error.
func TestBlobFromBytesDescribesTheCallersBuffer(t *testing.T) {
	t.Parallel()

	empty, err := blobFromBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.cbData != 0 || empty.pbData != nil {
		t.Fatalf("empty input built blob cbData=%d pbData=%v; want a zero blob", empty.cbData, empty.pbData)
	}

	data := []byte("session-token-material")
	blob, err := blobFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if blob.cbData != uint32(len(data)) {
		t.Fatalf("cbData=%d want %d", blob.cbData, len(data))
	}
	if unsafe.Pointer(blob.pbData) != unsafe.Pointer(&data[0]) {
		t.Fatal("pbData must point at the caller's first byte, not a copy")
	}
}
