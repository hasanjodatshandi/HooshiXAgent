package contractv2

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseConnectorGrant(t *testing.T) {
	record := validConnectorGrant()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConnectorGrant(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != record {
		t.Fatalf("parsed grant mismatch: got %+v want %+v", parsed, record)
	}
}

func TestParseConnectorGrantRejectsMalformedAuthority(t *testing.T) {
	valid := validConnectorGrant()
	tests := map[string]func(*ConnectorGrant){
		"raw target endpoint":   func(record *ConnectorGrant) { record.EndpointID = "127.0.0.1:3389/path" },
		"uppercase digest":      func(record *ConnectorGrant) { record.TokenSHA256 = strings.ToUpper(record.TokenSHA256) },
		"unordered lifetime":    func(record *ConnectorGrant) { record.ExpiresAt = record.NotBefore },
		"unbounded connections": func(record *ConnectorGrant) { record.MaxConnections = MaxConnectorGrantConnections + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseConnectorGrant(data); err == nil {
				t.Fatal("malformed connector grant was accepted")
			}
		})
	}
}

func TestServiceEndpointEnforcesPrivateRDP(t *testing.T) {
	record := validServiceEndpoint()
	record.Protocol = ProtocolTCP
	record.ApplicationProtocol = ApplicationRDP
	record.Exposure = ExposurePrivate
	if err := ValidateServiceEndpoint(record); err != nil {
		t.Fatal(err)
	}
	record.Exposure = ExposurePublic
	if err := ValidateServiceEndpoint(record); err == nil {
		t.Fatal("public RDP endpoint was accepted")
	}
}

func validConnectorGrant() ConnectorGrant {
	return ConnectorGrant{
		Kind: "connector_grant", ContractVersion: ProtocolVersion,
		GrantID: "grant-1", EndpointID: "endpoint-1", TokenID: "token-1",
		TokenSHA256: strings.Repeat("ab", 32),
		NotBefore:   "2026-09-27T08:00:00Z", ExpiresAt: "2026-09-27T08:15:00Z",
		MaxConnections: 2,
	}
}
