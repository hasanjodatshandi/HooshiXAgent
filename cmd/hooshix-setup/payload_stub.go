//go:build windows && !hooshix_release_payload

package main

import (
	"fmt"
	"io/fs"
)

// payloadMissingError is returned for every payload lookup in a non-release
// build: the embedded product binaries are gitignored build inputs that only
// scripts/build-setup.ps1 produces, so a plain `go build ./...` on Windows must
// compile and vet the package without them (the release variant is selected
// with -tags hooshix_release_payload).
type payloadStore struct{}

func (payloadStore) Open(name string) (fs.File, error) {
	return nil, fmt.Errorf("setup was built without the release payload (-tags hooshix_release_payload): %q is unavailable; build the distribution with scripts/build-setup.ps1: %w", name, fs.ErrNotExist)
}

var payload fs.FS = payloadStore{}
