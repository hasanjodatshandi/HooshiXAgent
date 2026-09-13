package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
)

const pairingCapabilityFile = "pairing.capability"

func PairingCapabilityPath(stateDir string) string {
	return filepath.Join(stateDir, pairingCapabilityFile)
}

func GeneratePairingCapability() (string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(entropy), nil
}

func EnsurePairingCapability(stateDir string) (string, error) {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return "", err
	}
	stateDir = normalized
	capability, err := LoadPairingCapability(stateDir)
	if err == nil {
		return capability, nil
	}
	capability, err = GeneratePairingCapability()
	if err != nil {
		return "", err
	}
	if err := WritePairingCapability(stateDir, capability); err != nil {
		return "", err
	}
	return capability, nil
}

func WritePairingCapability(stateDir, capability string) error {
	capability = strings.TrimSpace(capability)
	if len(capability) != 43 {
		return errors.New("invalid pairing capability")
	}
	return writePrivateFile(stateDir, PairingCapabilityPath(stateDir), []byte(capability))
}

func LoadPairingCapability(stateDir string) (string, error) {
	data, err := readStateFile(PairingCapabilityPath(stateDir))
	if err != nil {
		return "", err
	}
	capability := strings.TrimSpace(string(data))
	if len(capability) != 43 {
		return "", errors.New("invalid pairing capability file")
	}
	return capability, nil
}

func PairingCapabilityMatches(expected, provided string) bool {
	if len(expected) != 43 || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}
