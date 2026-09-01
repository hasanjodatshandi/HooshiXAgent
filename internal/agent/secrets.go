package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type SecretState struct {
	Seed         string `json:"seed,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

type SecretStore interface {
	Load() (SecretState, error)
	Save(SecretState) error
	Kind() string
}

type secretMutationStore interface {
	PrepareMutation() error
	LoadForMutation() (SecretState, error)
}

func prepareSecretMutation(store SecretStore) error {
	if preparer, ok := store.(secretMutationStore); ok {
		return preparer.PrepareMutation()
	}
	return nil
}

func loadSecretForMutation(store SecretStore) (SecretState, error) {
	if mutationStore, ok := store.(secretMutationStore); ok {
		return mutationStore.LoadForMutation()
	}
	return store.Load()
}

func LoadOrCreateIdentity(store SecretStore) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return loadOrCreateIdentity(store, rand.Reader)
}

func LoadIdentity(store SecretStore) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	state, err := store.Load()
	if err != nil {
		return nil, nil, err
	}
	if state.Seed == "" {
		return nil, nil, errors.New("Agent identity is not initialized")
	}
	return identityFromSeed(state.Seed)
}

func loadOrCreateIdentity(store SecretStore, entropy io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := prepareSecretMutation(store); err != nil {
		return nil, nil, err
	}
	state, err := loadSecretForMutation(store)
	if err != nil {
		return nil, nil, err
	}
	if state.Seed == "" {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(entropy, seed); err != nil {
			return nil, nil, fmt.Errorf("generate Ed25519 seed: %w", err)
		}
		state.Seed = base64.RawURLEncoding.EncodeToString(seed)
		if err := store.Save(state); err != nil {
			return nil, nil, err
		}
	}
	return identityFromSeed(state.Seed)
}

func identityFromSeed(encoded string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("stored Ed25519 seed is invalid")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return publicKey, privateKey, nil
}

func PublicKeyBase64(publicKey ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

func SetSessionToken(store SecretStore, token string) error {
	if err := prepareSecretMutation(store); err != nil {
		return err
	}
	state, err := loadSecretForMutation(store)
	if err != nil {
		return err
	}
	state.SessionToken = token
	return store.Save(state)
}

func LoadSessionToken(store SecretStore) (string, error) {
	state, err := store.Load()
	if err != nil {
		return "", err
	}
	if state.SessionToken == "" {
		return "", errors.New("session token is not configured")
	}
	return state.SessionToken, nil
}

func encodeSecretState(state SecretState) ([]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode secret state: %w", err)
	}
	return data, nil
}

func decodeSecretState(data []byte) (SecretState, error) {
	if len(data) == 0 {
		return SecretState{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state SecretState
	if err := decoder.Decode(&state); err != nil {
		return SecretState{}, fmt.Errorf("decode secret state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return SecretState{}, errors.New("decode secret state: trailing JSON value")
		}
		return SecretState{}, fmt.Errorf("decode secret state trailing data: %w", err)
	}
	return state, nil
}
