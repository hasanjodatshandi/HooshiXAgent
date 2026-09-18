//go:build windows && hooshix_release_payload

package main

import (
	"embed"
	"io/fs"
)

// The shipped distribution embeds the two product binaries so Setup.exe is
// self-contained. Building this variant requires the payload files to exist,
// which only the release build step guarantees: scripts/build-setup.ps1 stages
// them and builds with -tags hooshix_release_payload. Without the tag the
// non-release stub is used, so a clean checkout (where the gitignored payload
// directory is absent) still builds and vets on Windows.
//
//go:embed payload/hooshix-agent.exe payload/hooshix-agent-tray.exe payload/SHA256SUMS
var embeddedPayload embed.FS

var payload fs.FS = embeddedPayload
