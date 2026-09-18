package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pairingEndpointFile = "pairing.endpoint.json"

// PairingEndpoint is the published record of the running pairing-UI listener.
//
// The pairing UI binds a FIXED loopback port, so any local process can bind
// that port first (or while the service is stopped) and receive the capability
// when the tray opens the page. Publishing the real port together with a
// per-bind random token lets the tray prove — before it hands the capability
// to a URL — that the listener it is about to talk to is the one the service
// started. The token lives under the state directory, whose ACL the installer
// restricts to SYSTEM, Administrators and the interactive desktop user, so a
// process running as any other local user cannot answer the challenge.
type PairingEndpoint struct {
	Port      int    `json:"port"`
	Token     string `json:"token"`
	PID       int    `json:"pid"`
	CreatedAt string `json:"created_at"`
}

// PairingEndpointPath is the published listener record location.
func PairingEndpointPath(stateDir string) string {
	return filepath.Join(stateDir, pairingEndpointFile)
}

// WritePairingEndpoint publishes the listener record for the tray.
func WritePairingEndpoint(stateDir string, endpoint PairingEndpoint) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	data, err := json.Marshal(endpoint)
	if err != nil {
		return fmt.Errorf("encode pairing endpoint: %w", err)
	}
	return writePrivateFile(normalized, PairingEndpointPath(normalized), append(data, '\n'))
}

// LoadPairingEndpoint reads and validates the published listener record. A
// missing or malformed record is an error: the tray must fail closed rather
// than guess an address.
func LoadPairingEndpoint(stateDir string) (PairingEndpoint, error) {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return PairingEndpoint{}, err
	}
	data, err := readStateFile(PairingEndpointPath(normalized))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PairingEndpoint{}, errors.New("pairing UI listener record is missing; the agent service is not serving the pairing page")
		}
		return PairingEndpoint{}, fmt.Errorf("read pairing endpoint: %w", err)
	}
	var endpoint PairingEndpoint
	if err := json.Unmarshal(data, &endpoint); err != nil {
		return PairingEndpoint{}, fmt.Errorf("decode pairing endpoint: %w", err)
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return PairingEndpoint{}, errors.New("pairing endpoint port is invalid")
	}
	if len(endpoint.Token) != 43 {
		return PairingEndpoint{}, errors.New("pairing endpoint token is invalid")
	}
	return endpoint, nil
}

// RemovePairingEndpoint drops the listener record (service shutdown) so the
// tray never verifies against a listener that no longer exists.
func RemovePairingEndpoint(stateDir string) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	if err := os.Remove(PairingEndpointPath(normalized)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pairing endpoint: %w", err)
	}
	return nil
}
