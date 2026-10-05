package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

func TestAuthorizeConnectorBindsTokenGrantAndPrivateTCPEndpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	token := "connector-token-with-at-least-32-bytes"
	digest := sha256.Sum256([]byte(token))
	source := NewSnapshotMetadata()
	addV2Record(t, source.addServiceEndpointJSON, contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-1",
		OwnerDeviceID: "device-1", Protocol: contractv2.ProtocolTCP,
		ApplicationProtocol: contractv2.ApplicationRDP, LocalEndpointID: "rdp-1",
		Exposure: contractv2.ExposurePrivate, Enabled: true,
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
	})
	addV2Record(t, source.addConnectorGrantJSON, contractv2.ConnectorGrant{
		Kind: "connector_grant", ContractVersion: 2, GrantID: "grant-1",
		EndpointID: "endpoint-1", TokenID: "token-1", TokenSHA256: hex.EncodeToString(digest[:]),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
		MaxConnections: 1,
	})

	grant, endpoint, err := authorizeConnector(context.Background(), source, "grant-1", "token-1", token, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.EndpointID != endpoint.EndpointID || endpoint.ApplicationProtocol != contractv2.ApplicationRDP {
		t.Fatalf("authority mismatch: grant=%+v endpoint=%+v", grant, endpoint)
	}
	for name, values := range map[string][3]string{
		"wrong grant":    {"grant-x", "token-1", token},
		"wrong token id": {"grant-1", "token-x", token},
		"wrong token":    {"grant-1", "token-1", "another-connector-token-at-least-32"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := authorizeConnector(context.Background(), source, values[0], values[1], values[2], now)
			if !errors.Is(err, errConnectorUnauthorized) {
				t.Fatalf("error=%v want connector authorization failure", err)
			}
		})
	}
}

func TestUDPConnectorRequiresProtocolHeader(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	token := "connector-token-with-at-least-32-bytes"
	digest := sha256.Sum256([]byte(token))
	source := NewSnapshotMetadata()
	addV2Record(t, source.addServiceEndpointJSON, contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-udp-1", OwnerDeviceID: "device-1",
		Protocol: contractv2.ProtocolUDP, LocalEndpointID: "udp-1", Exposure: contractv2.ExposurePrivate,
		Enabled: true, CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
	})
	addV2Record(t, source.addConnectorGrantJSON, contractv2.ConnectorGrant{
		Kind: "connector_grant", ContractVersion: 2, GrantID: "grant-udp-1", EndpointID: "endpoint-udp-1",
		TokenID: "token-udp-1", TokenSHA256: hex.EncodeToString(digest[:]),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), MaxConnections: 1,
	})
	serverGateway, err := New(source, nil, DefaultLimits(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverGateway.Close(context.Background()) }()
	request := httptest.NewRequest(http.MethodGet, "/connector/v1/connect", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Hooshix-Grant-ID", "grant-udp-1")
	request.Header.Set("X-Hooshix-Token-ID", "token-udp-1")
	response := httptest.NewRecorder()
	serverGateway.handleConnector(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("UDP grant without UDP intent returned HTTP %d", response.Code)
	}
}

func TestActiveConnectorFlowIsCancelledAfterGrantRevocation(t *testing.T) {
	for _, protocol := range []contractv2.Protocol{contractv2.ProtocolTCP, contractv2.ProtocolUDP} {
		t.Run(string(protocol), func(t *testing.T) { testActiveConnectorRevocation(t, protocol) })
	}
}

func testActiveConnectorRevocation(t *testing.T, protocol contractv2.Protocol) {
	now := time.Now().UTC().Truncate(time.Second)
	token := "connector-token-with-at-least-32-bytes"
	digest := sha256.Sum256([]byte(token))
	source := &revocableConnectorMetadata{
		grant: contractv2.ConnectorGrant{
			Kind: "connector_grant", ContractVersion: 2, GrantID: "grant-live-1", EndpointID: "endpoint-live-1",
			TokenID: "token-live-1", TokenSHA256: hex.EncodeToString(digest[:]),
			NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), MaxConnections: 1,
		},
		endpoint: contractv2.ServiceEndpoint{
			Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-live-1", OwnerDeviceID: "device-live-1",
			Protocol: protocol, LocalEndpointID: "local-live-1", Exposure: contractv2.ExposurePrivate,
			Enabled: true, CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
		},
	}
	gateway := &Gateway{limits: DefaultLimits(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gateway.monitorConnectorAuthorization(ctx, cancel, source, source.grant, source.endpoint, token)
	source.revoked.Store(true)
	select {
	case <-ctx.Done():
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("active connector authorization remained live after revocation")
	}
}

type revocableConnectorMetadata struct {
	grant    contractv2.ConnectorGrant
	endpoint contractv2.ServiceEndpoint
	revoked  atomic.Bool
}

func (source *revocableConnectorMetadata) ConnectorGrant(context.Context, string, time.Time) (contractv2.ConnectorGrant, error) {
	if source.revoked.Load() {
		return contractv2.ConnectorGrant{}, ErrMetadataNotFound
	}
	return source.grant, nil
}

func (source *revocableConnectorMetadata) ServiceEndpoint(context.Context, string, time.Time) (contractv2.ServiceEndpoint, error) {
	return source.endpoint, nil
}

func addV2Record(t *testing.T, add func([]byte) error, record any) {
	t.Helper()
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := add(payload); err != nil {
		t.Fatal(err)
	}
}
