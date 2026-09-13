package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// RemoveTokenCopy deletes any legacy plaintext token.txt record from the
// state directory. The live credential stays only in the platform secret
// store; the plaintext convenience copy is no longer written and must be
// removed on load so old installations do not keep exposing the session
// token to every local user with inherited read access.
func RemoveTokenCopy(stateDir string) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	path := filepath.Join(normalized, "token.txt")
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect token.txt: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove unsafe token.txt path")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove token.txt: %w", err)
	}
	return nil
}
