package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteTokenCopy writes the user-facing token.txt record in the state
// directory. The live credential stays in the platform secret store; this
// copy exists so the user has a durable record of the issued token exactly
// like the documented CLI workflow.
func WriteTokenCopy(stateDir string, token string) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	path := filepath.Join(normalized, "token.txt")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write token.txt: %w", err)
	}
	return nil
}
