package agent

// ConfigureAgentStateForUI applies a validated pairing configuration and
// session token through the same transactional state mutation used by the
// CLI configure command (config lock + rollback journal).
func ConfigureAgentStateForUI(stateDir string, store SecretStore, requested Config, token string) (Config, error) {
	return configureAgentState(stateDir, store, requested, token, stateMutationFaults{})
}
