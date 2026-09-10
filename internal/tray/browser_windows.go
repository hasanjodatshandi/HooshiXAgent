//go:build windows

package tray

import (
	"fmt"
	"os/exec"
)

// openBrowser opens the default browser on the URL. The tray runs
// per-session so the user's default handler is the correct choice.
func openBrowser(url string) error {
	command := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := command.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	// rundll32 returns immediately; do not wait.
	return nil
}
