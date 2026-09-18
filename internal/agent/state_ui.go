package agent

// ConfigureAgentStateForUI applies a validated pairing configuration and
// session token through the same transactional state mutation used by the
// CLI configure command (config lock + rollback journal).
func ConfigureAgentStateForUI(stateDir string, store SecretStore, requested Config, token string) (Config, error) {
	return configureAgentState(stateDir, store, requested, token, stateMutationFaults{})
}

// UnpairAgentStateForUI clears the pairing through the same transactional
// state mutation the CLI uses (config lock + rollback journal). It runs in the
// process that serves the pairing UI, i.e. the Agent service on Windows, which
// is also the process that owns the secret store.
func UnpairAgentStateForUI(stateDir string, store SecretStore, resetIdentity bool) (UnpairResult, error) {
	return unpairAgentState(stateDir, store, resetIdentity, stateMutationFaults{})
}
