//go:build !windows

package agent

// serviceOwnsState is always false off Windows: the state directory belongs to
// the user running the command, so the process can read and rewrite the
// secret store itself.
func serviceOwnsState(string) bool { return false }
