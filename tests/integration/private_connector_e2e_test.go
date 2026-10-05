package runtimegate_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
)

func TestPrivateTCPConnectorEndToEndThroughRealAgent(t *testing.T) {
	localService := startHalfCloseService(t)
	publicPort := reserveTCPPort(t)
	stateDir := t.TempDir()
	store := agent.NewPlatformSecretStore(stateDir)
	publicKey, _, err := agent.LoadOrCreateIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := strings.Repeat("s", 43)
	if err := agent.SetSessionToken(store, sessionToken); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	connectorToken := strings.Repeat("c", 43)
	sessionDigest := sha256.Sum256([]byte(sessionToken))
	connectorDigest := sha256.Sum256([]byte(connectorToken))
	metadataDir := t.TempDir()
	if err := gateway.WriteSnapshotRecord(metadataDir, "authorizations", "authorization.json", contractv1.DeviceSessionAuthorization{
		ContractVersion: contractv1.ProtocolVersion, AuthorizationID: "auth-e2e-1", DeviceID: "device-e2e-1",
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(publicKey), TokenID: "session-token-e2e-1",
		TokenSHA256: hex.EncodeToString(sessionDigest[:]), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-e2e-1", OwnerDeviceID: "device-e2e-1",
		Protocol: contractv2.ProtocolTCP, ApplicationProtocol: contractv2.ApplicationRDP, LocalEndpointID: "local-tcp-e2e-1",
		Exposure: contractv2.ExposurePrivate, Enabled: true, CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
	}
	publicEndpoint := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-public-e2e-1", OwnerDeviceID: "device-e2e-1",
		Protocol: contractv2.ProtocolTCP, ApplicationProtocol: contractv2.ApplicationGeneric, LocalEndpointID: "local-public-e2e-1",
		PublicPort: publicPort, AllowedSourceCIDRs: []string{"127.0.0.0/8"},
		Exposure: contractv2.ExposurePublic, Enabled: true, CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
	}
	grant := contractv2.ConnectorGrant{
		Kind: "connector_grant", ContractVersion: 2, GrantID: "grant-e2e-1", EndpointID: endpoint.EndpointID,
		TokenID: "connector-token-e2e-1", TokenSHA256: hex.EncodeToString(connectorDigest[:]),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MaxConnections: 1,
	}
	if err := gateway.WriteSnapshotRecord(metadataDir, "service_endpoints", "endpoint.json", endpoint); err != nil {
		t.Fatal(err)
	}
	if err := gateway.WriteSnapshotRecord(metadataDir, "service_endpoints", "public-endpoint.json", publicEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := gateway.WriteSnapshotRecord(metadataDir, "connector_grants", "grant.json", grant); err != nil {
		t.Fatal(err)
	}
	metadata, err := gateway.LoadSnapshotDirectory(metadataDir)
	if err != nil {
		t.Fatal(err)
	}

	limits := gateway.DefaultLimits()
	serverGateway, err := gateway.New(metadata, nil, limits, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = serverGateway.Close(ctx)
	})
	server := httptest.NewTLSServer(serverGateway.Handler())
	defer server.Close()
	caPath := filepath.Join(stateDir, "gateway-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	wssBase := "wss" + strings.TrimPrefix(server.URL, "https")
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version: agent.ConfigVersion, GatewayURL: wssBase + "/agent/v1/connect", CAFile: caPath,
		DeviceID: "device-e2e-1", AuthorizationID: "auth-e2e-1", TokenID: "session-token-e2e-1", UpdateChannel: "stable",
		Endpoints: []agent.Endpoint{{ID: endpoint.LocalEndpointID, Target: localService}, {ID: publicEndpoint.LocalEndpointID, Target: localService}},
	}); err != nil {
		t.Fatal(err)
	}
	agentLimits := agent.DefaultLimits()
	agentLimits.ReconnectMin, agentLimits.ReconnectMax = 20*time.Millisecond, 100*time.Millisecond
	runner, err := agent.NewRunner(stateDir, agentLimits, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentDone := make(chan error, 1)
	go func() { agentDone <- runner.Run(ctx) }()
	waitFor(t, 3*time.Second, runner.HealthyTunnel)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connectorConfig := connector.DefaultConfig()
	connectorConfig.GatewayURL = wssBase + "/connector/v1/connect"
	connectorConfig.GrantID, connectorConfig.TokenID, connectorConfig.Token = grant.GrantID, grant.TokenID, connectorToken
	connectorConfig.ListenAddress = listener.Addr().String()
	connectorConfig.HTTPClient = server.Client()
	connectorDone := make(chan error, 1)
	go func() {
		connectorDone <- connector.Serve(ctx, listener, connectorConfig, privateConnectorDiscardLogger())
	}()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcpClient := client.(*net.TCPConn)
	if _, err := tcpClient.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tcpClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(tcpClient)
	_ = tcpClient.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo:hello" {
		t.Fatalf("response=%q want echo:hello", response)
	}

	publicManager, err := gateway.NewPublicTCPManager(serverGateway, metadata, gateway.PublicTCPConfig{
		BindHost: "127.0.0.1", PortMin: publicPort, PortMax: publicPort, ReconcileInterval: 20 * time.Millisecond,
	}, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publicDone := make(chan error, 1)
	go func() { publicDone <- publicManager.Run(ctx) }()
	publicClient := dialTCPEventually(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort)))
	publicTCPClient := publicClient.(*net.TCPConn)
	if _, err := publicTCPClient.Write([]byte("public")); err != nil {
		t.Fatal(err)
	}
	if err := publicTCPClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	publicResponse, err := io.ReadAll(publicTCPClient)
	_ = publicTCPClient.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(publicResponse) != "echo:public" {
		t.Fatalf("public response=%q want echo:public", publicResponse)
	}

	cancel()
	if err := <-publicDone; err != nil {
		t.Fatal(err)
	}
	if err := <-connectorDone; err != nil {
		t.Fatal(err)
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
}

func startHalfCloseService(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				request, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				_, _ = conn.Write(append([]byte("echo:"), request...))
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func dialTCPEventually(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func privateConnectorDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
