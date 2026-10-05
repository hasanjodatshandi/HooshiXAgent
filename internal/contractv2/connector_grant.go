package contractv2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const MaxConnectorGrantConnections = 16

type ConnectorGrant struct {
	Kind            string `json:"kind"`
	ContractVersion int    `json:"contract_version"`
	GrantID         string `json:"grant_id"`
	EndpointID      string `json:"endpoint_id"`
	TokenID         string `json:"token_id"`
	TokenSHA256     string `json:"token_sha256"`
	NotBefore       string `json:"not_before"`
	ExpiresAt       string `json:"expires_at"`
	Disabled        bool   `json:"disabled"`
	MaxConnections  int    `json:"max_connections"`
}

func ParseConnectorGrant(data []byte) (ConnectorGrant, error) {
	var record ConnectorGrant
	if err := validateStrictJSONObject(data); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode connector grant: %w", err)
	}
	if err := requireMembers(data, "kind", "contract_version", "grant_id", "endpoint_id", "token_id", "token_sha256", "not_before", "expires_at", "disabled", "max_connections"); err != nil {
		return record, err
	}
	if err := ValidateConnectorGrant(record); err != nil {
		return record, err
	}
	return record, nil
}

func ValidateConnectorGrant(record ConnectorGrant) error {
	if record.Kind != "connector_grant" {
		return errors.New("kind must be connector_grant")
	}
	if record.ContractVersion != ProtocolVersion {
		return fmt.Errorf("contract_version must be %d", ProtocolVersion)
	}
	for name, value := range map[string]string{
		"grant_id": record.GrantID, "endpoint_id": record.EndpointID, "token_id": record.TokenID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	digest, err := hex.DecodeString(record.TokenSHA256)
	if err != nil || len(digest) != 32 || record.TokenSHA256 != fmt.Sprintf("%x", digest) {
		return errors.New("token_sha256 must be 64 lowercase hexadecimal characters")
	}
	notBefore, err := canonicalTimestamp(record.NotBefore)
	if err != nil {
		return fmt.Errorf("not_before: %w", err)
	}
	expiresAt, err := canonicalTimestamp(record.ExpiresAt)
	if err != nil {
		return fmt.Errorf("expires_at: %w", err)
	}
	if !notBefore.Before(expiresAt) {
		return errors.New("not_before must be earlier than expires_at")
	}
	if record.MaxConnections < 1 || record.MaxConnections > MaxConnectorGrantConnections {
		return fmt.Errorf("max_connections must be between 1 and %d", MaxConnectorGrantConnections)
	}
	return nil
}

func canonicalTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Format(time.RFC3339Nano) != value || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("must be a canonical UTC RFC3339 timestamp")
	}
	return parsed, nil
}
