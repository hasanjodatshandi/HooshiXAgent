package agent

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

// UnpairResult is the machine-readable outcome of one unpair operation. The
// CLI prints it with --json and the pairing UI returns it to a JSON client.
type UnpairResult struct {
	StateDir string `json:"state_dir"`
	// DeviceID is the external device identity that was cleared. It is empty
	// when there was no pairing record to clear.
	DeviceID string `json:"device_id,omitempty"`
	// PublicKey is the device Ed25519 identity that is in effect AFTER the
	// operation. It is the same key the device was registered with unless the
	// identity was explicitly replaced.
	PublicKey string `json:"public_key,omitempty"`
	// IdentityPreserved reports whether the pre-existing device identity is
	// still the device identity. It is false only when the operator asked for a
	// replacement identity AND one existed.
	IdentityPreserved bool `json:"identity_preserved"`
	// AlreadyUnpaired reports that there was nothing to clear: the operation
	// changed no state and succeeded anyway (idempotent unpair).
	AlreadyUnpaired bool `json:"already_unpaired"`
	// LocalEndpoints counts the loopback endpoint mappings left in place. They
	// are local exposure configuration, not pairing material, so unpair never
	// destroys them.
	LocalEndpoints int `json:"local_endpoints"`
}

// pairingRecordPresent reports whether any state written by a pairing (or by
// the configure command that consumes the same external credentials) is still
// stored. It covers every field unpair clears, so "nothing to clear" can never
// be reported while a pairing field remains.
func pairingRecordPresent(config Config, secret SecretState) bool {
	return config.GatewayURL != "" || len(config.GatewayAliases) > 0 || config.CAFile != "" ||
		config.DeviceID != "" || config.AuthorizationID != "" || config.TokenID != "" ||
		secret.SessionToken != ""
}

// unpairAgentState clears the pairing record and returns the Agent to the
// unpaired (pending_config) state.
//
// Scope of the clear is exactly the material a pairing installs: the gateway
// binding (gateway_url, gateway_aliases), the configured trust anchor
// (ca_file), the external identifiers (device_id, authorization_id, token_id)
// and the session token. The device Ed25519 identity is preserved unless
// resetIdentity is set, because re-pairing the same device must not silently
// mint a second identity: the panel would keep authorizing a public key the
// device no longer holds. Local endpoint mappings are local exposure
// configuration, not pairing material, and are likewise preserved.
//
// The identity is NEVER read, re-wrapped, or re-created by a process that does
// not own the secret store: the whole operation runs through the same config
// lock and rollback journal as init/configure/rotate, so a crash mid-operation
// cannot leave a partially cleared pairing (config cleared, token still
// present, or the reverse). When resetIdentity is set the replacement seed is
// minted by THIS process through store.Save, i.e. in the context that owns the
// DPAPI current-user key. A caller that cannot read the store (an interactive
// administrator against the LocalSystem service state) must not call this
// directly; it delegates to the service instead (requestServiceUnpair).
func unpairAgentState(stateDir string, store SecretStore, resetIdentity bool, faults stateMutationFaults) (result UnpairResult, err error) {
	result = UnpairResult{StateDir: stateDir}
	err = withConfigLock(stateDir, func() error {
		return runStateTransaction(stateDir, func() error {
			if err := prepareSecretMutation(store); err != nil {
				return err
			}
			secret, err := loadSecretForMutation(store)
			if err != nil {
				return err
			}
			config, err := loadConfigUnlocked(stateDir)
			if err != nil {
				return err
			}
			result.LocalEndpoints = len(config.Endpoints)
			// Idempotent: with nothing to clear (and no identity replacement
			// requested) the operation succeeds without touching state at all.
			if !pairingRecordPresent(config, secret) && !(resetIdentity && secret.Seed != "") {
				result.AlreadyUnpaired = true
				result.IdentityPreserved = true
				result.PublicKey = publicKeyFromSeed(secret.Seed)
				return nil
			}
			result.DeviceID = config.DeviceID
			replacedIdentity := resetIdentity && secret.Seed != ""

			config.GatewayURL = ""
			config.GatewayAliases = nil
			config.CAFile = ""
			config.DeviceID = ""
			config.AuthorizationID = ""
			config.TokenID = ""
			secret.SessionToken = ""
			if replacedIdentity {
				secret.Seed = ""
			}
			if err := saveConfigUnlocked(stateDir, config); err != nil {
				return err
			}
			if faults.afterConfigSave != nil {
				if err := faults.afterConfigSave(); err != nil {
					return err
				}
			}
			if err := store.Save(secret); err != nil {
				return err
			}
			if faults.afterSecretSave != nil {
				if err := faults.afterSecretSave(); err != nil {
					return err
				}
			}
			if replacedIdentity {
				if _, _, err := LoadOrCreateIdentity(store); err != nil {
					return err
				}
			}
			// A legacy plaintext token record is exactly the orphaned secret
			// this operation must not leave behind. It is removed inside the
			// transaction so the operation is still all-or-nothing for the
			// caller even though the journal does not cover that legacy file.
			if err := RemoveTokenCopy(stateDir); err != nil {
				return err
			}
			// Read back through the mutation-safe path: the transaction
			// directory exists for the remainder of this operation.
			saved, err := loadSecretForMutation(store)
			if err != nil {
				return err
			}
			result.PublicKey = publicKeyFromSeed(saved.Seed)
			result.IdentityPreserved = !replacedIdentity
			return nil
		})
	})
	return result, err
}

func publicKeyFromSeed(seed string) string {
	if seed == "" {
		return ""
	}
	publicKey, _, err := identityFromSeed(seed)
	if err != nil {
		return ""
	}
	return PublicKeyBase64(publicKey)
}

// unpairState performs an unpair in the context that owns the secret store.
//
// A process that is serving this state directory's pairing endpoint owns the
// secret store (on Windows that is the LocalSystem Agent service), and only
// that process can clear a DPAPI current-user blob. When such a service is
// serving, the operation is delegated to it; when the machine-wide service
// owns the directory but is not serving, the operation cannot be completed
// from here at all and the operator is told exactly what to do.
func unpairState(stateDir string, resetIdentity bool) (UnpairResult, error) {
	if serviceServingStateDir(stateDir) {
		return requestServiceUnpair(stateDir, resetIdentity)
	}
	if serviceOwnsState(stateDir) {
		return UnpairResult{}, describeServiceUnavailable(errors.New("the state directory has no live pairing endpoint record"))
	}
	store := NewPlatformSecretStore(stateDir)
	return unpairAgentState(stateDir, store, resetIdentity, stateMutationFaults{})
}

// serviceServingStateDir reports whether a live process is serving the pairing
// endpoint published in this state directory.
//
// Detection is a probe, not a path guess: the published port is challenged for
// the per-bind listener token exactly as the tray challenges it before handing
// over the pairing capability, so a stale record, a dead listener, or a port
// squatter is never mistaken for the service that owns the state.
func serviceServingStateDir(stateDir string) bool {
	endpoint, err := LoadPairingEndpoint(stateDir)
	if err != nil {
		return false
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(endpoint.Port))
	client := &http.Client{Timeout: serviceProbeTimeout}
	return verifyServiceListener(client, address, endpoint.Token) == nil
}

// errServiceNotServing is the operator-facing refusal used when the machine
// state is owned by the Windows service but the service is not reachable. The
// LocalSystem DPAPI key cannot be used by an interactive process, so the
// operation genuinely cannot be completed from here and the message has to say
// exactly what to do instead of guessing.
var errServiceNotServing = errors.New("the HooshiXAgent service owns this state but is not serving its loopback endpoint")

func describeServiceUnavailable(cause error) error {
	return fmt.Errorf("%w: start it with `hooshix-agent service start` and run `hooshix-agent unpair` again (%v)", errServiceNotServing, cause)
}
