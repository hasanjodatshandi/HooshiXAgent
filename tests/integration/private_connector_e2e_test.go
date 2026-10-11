package runtimegate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
)

// privateTunnel is the shared half of the private-connector fixture: a real
// Gateway handler serving tunnel and connector flows over TLS, a real Agent
// runner holding its own state tree, one echo service exposed as an RDP
// endpoint, and one live connector grant pointing at that endpoint.
type privateTunnel struct {
	serverGateway *gateway.Gateway
	metadata      *gateway.SnapshotMetadata
	wssBase       string
	caFile        string
	grant         contractv2.ConnectorGrant
	token         string
	publicPort    int
	ctx           context.Context
	cancel        context.CancelFunc
	agentDone     chan error
	httpClient    *http.Client
}

// startPrivateTunnel returns only once the Agent tunnel is healthy, so a caller
// can dial a connector immediately.
func startPrivateTunnel(t *testing.T) privateTunnel {
	t.Helper()
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
	t.Cleanup(server.Close)
	caFile := filepath.Join(stateDir, "gateway-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	wssBase := "wss" + strings.TrimPrefix(server.URL, "https")
	if err := agent.SaveConfig(stateDir, agent.Config{
		Version: agent.ConfigVersion, GatewayURL: wssBase + "/agent/v1/connect", CAFile: caFile,
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
	t.Cleanup(cancel)
	agentDone := make(chan error, 1)
	go func() { agentDone <- runner.Run(ctx) }()
	waitFor(t, 3*time.Second, runner.HealthyTunnel)

	return privateTunnel{
		serverGateway: serverGateway, metadata: metadata, wssBase: wssBase, caFile: caFile,
		grant: grant, token: connectorToken, publicPort: publicPort,
		ctx: ctx, cancel: cancel, agentDone: agentDone, httpClient: server.Client(),
	}
}

// waitForEcho drives one half-closed request through a loopback connector port
// and asserts the echo service's answer, which is only reachable over the Agent
// tunnel.
func waitForEcho(t *testing.T, address string, payload string) {
	t.Helper()
	client := dialTCPEventually(t, address).(*net.TCPConn)
	if _, err := client.Write([]byte(payload)); err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	_ = client.Close()
	if err != nil {
		t.Fatalf("read echo through %s: %v", address, err)
	}
	if want := "echo:" + payload; string(response) != want {
		t.Fatalf("response=%q want %q", response, want)
	}
}

func TestPrivateTCPConnectorEndToEndThroughRealAgent(t *testing.T) {
	tunnel := startPrivateTunnel(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connectorConfig := connector.DefaultConfig()
	connectorConfig.GatewayURL = tunnel.wssBase + "/connector/v1/connect"
	connectorConfig.GrantID, connectorConfig.TokenID, connectorConfig.Token = tunnel.grant.GrantID, tunnel.grant.TokenID, tunnel.token
	connectorConfig.ListenAddress = listener.Addr().String()
	connectorConfig.HTTPClient = tunnel.httpClient
	connectorDone := make(chan error, 1)
	go func() {
		connectorDone <- connector.Serve(tunnel.ctx, listener, connectorConfig, privateConnectorDiscardLogger())
	}()

	waitForEcho(t, listener.Addr().String(), "hello")

	publicManager, err := gateway.NewPublicTCPManager(tunnel.serverGateway, tunnel.metadata, gateway.PublicTCPConfig{
		BindHost: "127.0.0.1", PortMin: tunnel.publicPort, PortMax: tunnel.publicPort, ReconcileInterval: 20 * time.Millisecond,
	}, privateConnectorDiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	publicDone := make(chan error, 1)
	go func() { publicDone <- publicManager.Run(tunnel.ctx) }()
	waitForEcho(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(tunnel.publicPort)), "public")

	tunnel.cancel()
	if err := <-publicDone; err != nil {
		t.Fatal(err)
	}
	if err := <-connectorDone; err != nil {
		t.Fatal(err)
	}
	if err := <-tunnel.agentDone; err != nil {
		t.Fatal(err)
	}
}

// requiredConnectorBinary follows requiredBinaries: the Executable Runtime Gate
// must execute the shipped connector binary, so in CI a missing path is a
// failure and never a silent skip.
func requiredConnectorBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("HOOSHIX_CONNECTOR_BINARY")
	if binary == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("CI must set HOOSHIX_CONNECTOR_BINARY: build ./cmd/hooshix-connector and export its path (see scripts/ci/runtime-gate.sh); a runtime assertion must not be skipped into a passing gate")
		}
		t.Skip("set HOOSHIX_CONNECTOR_BINARY")
	}
	return binary
}

// panelBundle encodes a grant exactly the way hooshix-panel's
// buildConnectorBundle does, so the executable is driven with the same string an
// operator pastes rather than a format only this test knows.
func panelBundle(t *testing.T, gatewayURL, grantID, tokenID, token string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"v": 1, "gateway": gatewayURL, "grant_id": grantID, "token_id": tokenID,
		"token": token, "protocol": "tcp", "max_connections": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return connector.BundlePrefix + base64.RawURLEncoding.EncodeToString(payload)
}

// TestRealConnectorExecutableCarriesPrivateTCPBytes is the runtime procedure for
// cmd/hooshix-connector: it launches the built executable with a bundle and a
// private trust anchor, proves bytes travel through the real Agent tunnel, and
// proves the loopback port is released when the process is asked to exit.
func TestRealConnectorExecutableCarriesPrivateTCPBytes(t *testing.T) {
	binary := requiredConnectorBinary(t)
	tunnel := startPrivateTunnel(t)
	listenAddress := "127.0.0.1:" + strconv.Itoa(reserveTCPPort(t))

	command := exec.Command(binary,
		"-bundle", panelBundle(t, tunnel.wssBase+"/connector/v1/connect", tunnel.grant.GrantID, tunnel.grant.TokenID, tunnel.token),
		"-listen", listenAddress,
		"-ca-file", tunnel.caFile,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	// exited carries exactly one value, so every later receiver must know whether
	// the process result has already been taken.
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		_ = command.Process.Kill()
		<-exited
	})

	// The bytes only arrive if the process parsed the bundle, trusted the anchor
	// through -ca-file, and opened its authenticated connector flow.
	waitForEcho(t, listenAddress, "executable")

	// A malformed bundle is refused before any socket opens, with the CLI's own
	// usage exit code instead of a listener that fails later.
	rejected := exec.Command(binary, "-bundle", "hx1.not-a-bundle")
	output, err := rejected.CombinedOutput()
	var exitStatus *exec.ExitError
	if !errors.As(err, &exitStatus) || exitStatus.ExitCode() != 2 {
		t.Fatalf("malformed bundle exit=%v output=%s, want exit status 2", err, output)
	}
	if !strings.Contains(string(output), "connect bundle") {
		t.Fatalf("malformed bundle diagnostic lost: %s", output)
	}

	// Exiting must release the port so the next grant can be bound.
	if runtime.GOOS == "windows" {
		// os/exec cannot deliver SIGTERM on Windows, so only the kill path is
		// exercisable there; graceful shutdown is asserted where a real signal
		// can be sent.
		_ = command.Process.Kill()
	} else if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal connector: %v", err)
	}
	select {
	case err := <-exited:
		stopped = true
		if runtime.GOOS != "windows" && err != nil {
			t.Fatalf("connector exited abnormally: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		stopped = true
		_ = command.Process.Kill()
		<-exited
		t.Fatal("connector process did not exit after being asked to")
	}
	if connection, err := net.DialTimeout("tcp", listenAddress, 300*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("the loopback connector port survived the executable exiting")
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
