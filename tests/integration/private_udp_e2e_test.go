package runtimegate_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
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
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestPrivateUDPConnectorEndToEndThroughRealAgent(t *testing.T) {
	localService := startUDPEchoService(t)
	quicService, quicCertificate := startHTTP3Service(t)
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := reservation.LocalAddr().(*net.UDPAddr).Port
	_ = reservation.Close()
	quicReservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quicPort := quicReservation.LocalAddr().(*net.UDPAddr).Port
	_ = quicReservation.Close()
	deniedReservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deniedPort := deniedReservation.LocalAddr().(*net.UDPAddr).Port
	_ = deniedReservation.Close()
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
	connectorToken := strings.Repeat("c", 43)
	quicConnectorToken := strings.Repeat("q", 43)
	sessionDigest := sha256.Sum256([]byte(sessionToken))
	connectorDigest := sha256.Sum256([]byte(connectorToken))
	quicConnectorDigest := sha256.Sum256([]byte(quicConnectorToken))
	now := time.Now().UTC().Truncate(time.Second)
	metadataDir := t.TempDir()
	if err := gateway.WriteSnapshotRecord(metadataDir, "authorizations", "authorization.json", contractv1.DeviceSessionAuthorization{
		ContractVersion: 1, AuthorizationID: "auth-udp-1", DeviceID: "device-udp-1",
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(publicKey), TokenID: "session-token-udp-1",
		TokenSHA256: hex.EncodeToString(sessionDigest[:]), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-udp-1", OwnerDeviceID: "device-udp-1",
		Protocol: contractv2.ProtocolUDP, ApplicationProtocol: contractv2.ApplicationGeneric,
		LocalEndpointID: "local-udp-1", Exposure: contractv2.ExposureBoth, Enabled: true,
		PublicPort: publicPort, AllowedSourceCIDRs: []string{"127.0.0.0/8"},
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), Revision: 1,
	}
	grant := contractv2.ConnectorGrant{
		Kind: "connector_grant", ContractVersion: 2, GrantID: "grant-udp-1", EndpointID: endpoint.EndpointID,
		TokenID: "connector-token-udp-1", TokenSHA256: hex.EncodeToString(connectorDigest[:]),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MaxConnections: 1,
	}
	if err := gateway.WriteSnapshotRecord(metadataDir, "service_endpoints", "endpoint.json", endpoint); err != nil {
		t.Fatal(err)
	}
	quicEndpoint := endpoint
	quicEndpoint.EndpointID = "endpoint-quic-1"
	quicEndpoint.LocalEndpointID = "local-quic-1"
	quicEndpoint.PublicPort = quicPort
	quicEndpoint.Exposure = contractv2.ExposureBoth
	if err := gateway.WriteSnapshotRecord(metadataDir, "service_endpoints", "quic.json", quicEndpoint); err != nil {
		t.Fatal(err)
	}
	deniedEndpoint := endpoint
	deniedEndpoint.EndpointID = "endpoint-denied-1"
	deniedEndpoint.PublicPort = deniedPort
	deniedEndpoint.Exposure = contractv2.ExposurePublic
	deniedEndpoint.AllowedSourceCIDRs = []string{"192.0.2.0/24"}
	if err := gateway.WriteSnapshotRecord(metadataDir, "service_endpoints", "denied.json", deniedEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := gateway.WriteSnapshotRecord(metadataDir, "connector_grants", "grant.json", grant); err != nil {
		t.Fatal(err)
	}
	quicGrant := grant
	quicGrant.GrantID = "grant-quic-1"
	quicGrant.EndpointID = quicEndpoint.EndpointID
	quicGrant.TokenID = "connector-token-quic-1"
	quicGrant.TokenSHA256 = hex.EncodeToString(quicConnectorDigest[:])
	if err := gateway.WriteSnapshotRecord(metadataDir, "connector_grants", "quic.json", quicGrant); err != nil {
		t.Fatal(err)
	}
	metadata, err := gateway.LoadSnapshotDirectory(metadataDir)
	if err != nil {
		t.Fatal(err)
	}
	serverGateway, err := gateway.New(metadata, nil, gateway.DefaultLimits(), privateConnectorDiscardLogger())
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
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	wssBase := "wss" + strings.TrimPrefix(server.URL, "https")
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version: agent.ConfigVersion, GatewayURL: wssBase + "/agent/v1/connect", CAFile: caPath,
		DeviceID: "device-udp-1", AuthorizationID: "auth-udp-1", TokenID: "session-token-udp-1", UpdateChannel: "stable",
		Endpoints: []agent.Endpoint{
			{ID: endpoint.LocalEndpointID, Target: localService, Protocol: "udp"},
			{ID: quicEndpoint.LocalEndpointID, Target: quicService, Protocol: "udp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	limits := agent.DefaultLimits()
	limits.ReconnectMin, limits.ReconnectMax = 20*time.Millisecond, 100*time.Millisecond
	runner, err := agent.NewRunner(stateDir, limits, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentDone := make(chan error, 1)
	go func() { agentDone <- runner.Run(ctx) }()
	waitFor(t, 3*time.Second, runner.HealthyTunnel)

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := connector.DefaultConfig()
	config.Protocol = "udp"
	config.MaxConnections = 1
	config.GatewayURL = wssBase + "/connector/v1/connect"
	config.GrantID, config.TokenID, config.Token = grant.GrantID, grant.TokenID, connectorToken
	config.ListenAddress = listener.LocalAddr().String()
	config.HTTPClient = server.Client()
	connectorDone := make(chan error, 1)
	go func() { connectorDone <- connector.ServeUDP(ctx, listener, config, privateConnectorDiscardLogger()) }()
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	buffer := make([]byte, 64)
	for _, packet := range []string{"a", "bc"} {
		if _, err := client.Write([]byte(packet)); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(buffer[:n]), "echo:"+packet; got != want {
			t.Fatalf("UDP response %q; want %q", got, want)
		}
	}
	// A second local peer cannot consume another WSS flow while the first is
	// active. Its packet is dropped without disturbing the admitted peer.
	second, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := second.Read(buffer); err == nil {
		t.Fatal("second UDP peer bypassed Connector flow limit")
	}
	if _, err := client.Write(make([]byte, contractv1.MaxUDPDatagram+1)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("oversize UDP datagram reached the Agent")
	}
	if _, err := client.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client.Read(buffer)
	if err != nil || string(buffer[:n]) != "echo:still-alive" {
		t.Fatalf("admitted UDP flow did not recover after drops: %q, %v", buffer[:n], err)
	}
	publicManager, err := gateway.NewPublicUDPManager(serverGateway, metadata, gateway.PublicUDPConfig{
		BindHost: "127.0.0.1", PortMin: min(publicPort, quicPort, deniedPort), PortMax: max(publicPort, quicPort, deniedPort), ReconcileInterval: time.Second,
	}, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publicDone := make(chan error, 1)
	go func() { publicDone <- publicManager.Run(ctx) }()
	publicClient, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer publicClient.Close()
	var got string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := publicClient.Write([]byte("public")); err != nil {
			t.Fatal(err)
		}
		_ = publicClient.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if n, err := publicClient.Read(buffer); err == nil {
			got = string(buffer[:n])
			break
		}
	}
	if got != "echo:public" {
		t.Fatalf("public UDP response %q; want echo:public", got)
	}
	if _, err := publicClient.Write(make([]byte, contractv1.MaxUDPDatagram+1)); err != nil {
		t.Fatal(err)
	}
	_ = publicClient.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := publicClient.Read(buffer); err == nil {
		t.Fatal("oversize public UDP datagram reached the Agent")
	}
	if _, err := publicClient.Write([]byte("still-public")); err != nil {
		t.Fatal(err)
	}
	_ = publicClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = publicClient.Read(buffer)
	if err != nil || string(buffer[:n]) != "echo:still-public" {
		t.Fatalf("public UDP flow did not recover after oversize drop: %q, %v", buffer[:n], err)
	}
	if listener, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(deniedPort))); err == nil {
		_ = listener.Close()
		t.Fatal("source-denied UDP listener was not bound")
	}
	deniedClient, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(deniedPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer deniedClient.Close()
	for range 32 {
		if _, err := deniedClient.Write([]byte("deny")); err != nil {
			t.Fatal(err)
		}
	}
	_ = deniedClient.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if n, err := deniedClient.Read(buffer); err == nil {
		t.Fatalf("source-denied UDP endpoint answered: %q", buffer[:n])
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("source-denied UDP probe failed unexpectedly: %v", err)
		}
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(quicCertificate)
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs, ServerName: "example.com"},
		QUICConfig:      &quic.Config{InitialPacketSize: contractv1.MaxUDPDatagram, DisablePathMTUDiscovery: true},
	}
	defer transport.Close()
	h3Client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	response, err := h3Client.Get("https://127.0.0.1:" + strconv.Itoa(quicPort) + "/")
	if err != nil {
		t.Fatalf("HTTP/3 handshake through UDP tunnel: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.ProtoMajor != 3 || string(body) != "quic-ok" {
		t.Fatalf("HTTP/3 response: protocol=%s body=%q error=%v", response.Proto, body, err)
	}
	privateQUIC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quicConnectorConfig := config
	quicConnectorConfig.GrantID = quicGrant.GrantID
	quicConnectorConfig.TokenID = quicGrant.TokenID
	quicConnectorConfig.Token = quicConnectorToken
	quicConnectorConfig.ListenAddress = privateQUIC.LocalAddr().String()
	privateQUICDone := make(chan error, 1)
	go func() {
		privateQUICDone <- connector.ServeUDP(ctx, privateQUIC, quicConnectorConfig, privateConnectorDiscardLogger())
	}()
	response, err = h3Client.Get("https://" + privateQUIC.LocalAddr().String() + "/")
	if err != nil {
		t.Fatalf("private Connector HTTP/3 handshake: %v", err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.ProtoMajor != 3 || string(body) != "quic-ok" {
		t.Fatalf("private HTTP/3 response: protocol=%s body=%q error=%v", response.Proto, body, err)
	}
	publicManager.Close()
	cancel()
	if err := <-publicDone; err != nil {
		t.Fatal(err)
	}
	if err := <-privateQUICDone; err != nil {
		t.Fatal(err)
	}
	if err := <-connectorDone; err != nil {
		t.Fatal(err)
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
}

func startHTTP3Service(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "quic-ok") }))
	t.Cleanup(fixture.Close)
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "quic-ok") }),
		TLSConfig:  http3.ConfigureTLSConfig(&tls.Config{Certificates: fixture.TLS.Certificates}),
		QUICConfig: &quic.Config{InitialPacketSize: contractv1.MaxUDPDatagram, DisablePathMTUDiscovery: true},
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = <-done })
	return listener.LocalAddr().String(), fixture.Certificate()
}

func startUDPEchoService(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(append([]byte("echo:"), buffer[:n]...), peer)
		}
	}()
	return listener.LocalAddr().String()
}
