//go:build windows

package agent

// serviceOwnsState reports whether the machine-wide Windows Agent service owns
// this state directory.
//
// On Windows the service state root is LocalSystem-owned and its secret store
// is a DPAPI CurrentUser blob written by the service account. An interactive
// process can neither read nor rewrite it, and a blob it minted itself would
// be undecryptable by the service, so unpair must never write there directly:
// it delegates to the running service instead.
func serviceOwnsState(stateDir string) bool {
	return samePath(stateDir, ServiceStateDir())
}
