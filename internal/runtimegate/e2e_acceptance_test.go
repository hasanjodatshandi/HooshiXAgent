package runtimegate_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const e2ePublicHost = "demo.hooshix.test"

func TestAgentGatewayEndToEndAcceptance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("E2E process orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)

	stateDir := t.TempDir()
	metadataDir := t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	gatewayAddress := reserveAddress(t)
	gatewayBaseURL := "https://" + gatewayAddress
	gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"

	localAddress, stopLocal := startLocalHTTPService(t)
	defer stopLocal()

	publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
	writeValidatedMetadata(t, metadataDir, publicKey, token, metadataOptions{})

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
	)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)

	// A valid external route with no authenticated Agent must fail closed.
	response, err := publicRequest(client, gatewayBaseURL, "/offline-before-agent", "")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("offline route status=%d want=%d", response.StatusCode, http.StatusServiceUnavailable)
	}

	agentOne := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	first := waitTunnel(t, client, gatewayBaseURL, "/accepted", "payload-one")
	if first != "e2e-local:/accepted:payload-one" {
		t.Fatalf("unexpected E2E response: %q", first)
	}

	// The stable test hostname is authoritative; an unknown public host must not route.
	unknownHostResponse, err := publicRequestWithHost(client, gatewayBaseURL, "/unknown-host", "", "unknown.hooshix.test")
	if err != nil {
		t.Fatal(err)
	}
	unknownHostResponse.Body.Close()
	if unknownHostResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown host status=%d want=%d", unknownHostResponse.StatusCode, http.StatusNotFound)
	}

	// Gateway restart: keep the real Agent process running and prove its reconnect loop restores the route.
	gateway.stop(t)
	waitFor(t, 3*time.Second, func() bool {
		_, err := client.Get(gatewayBaseURL + "/healthz")
		return err != nil
	})
	gateway = startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
	)
	waitGatewayHealth(t, client, gatewayBaseURL)
	second := waitTunnel(t, client, gatewayBaseURL, "/after-gateway-restart", "payload-two")
	if second != "e2e-local:/after-gateway-restart:payload-two" {
		t.Fatalf("unexpected post-Gateway-restart response: %q", second)
	}

	// Agent restart with the same state directory proves identity/state persistence and re-authentication.
	agentOne.stop(t)
	waitFor(t, 5*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/offline-after-agent-stop", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusServiceUnavailable
	})
	agentTwo := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agentTwo.stop(t)
	defer gateway.stop(t)
	third := waitTunnel(t, client, gatewayBaseURL, "/after-agent-restart", "payload-three")
	if third != "e2e-local:/after-agent-restart:payload-three" {
		t.Fatalf("unexpected post-Agent-restart response: %q", third)
	}

	status := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if stringField(t, status, "public_key") != publicKey {
		t.Fatal("Agent identity changed after restart")
	}
	statusJSON, _ := json.Marshal(status)
	combinedLogs := gateway.stderr.String() + agentOne.stderr.String() + agentTwo.stderr.String()
	if bytes.Contains(statusJSON, []byte(token)) || strings.Contains(combinedLogs, token) {
		t.Fatal("E2E evidence leaked the session token")
	}
}

func TestAgentGatewayAuthorizationExpiryFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("E2E process orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)

	stateDir := t.TempDir()
	metadataDir := t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	gatewayAddress := reserveAddress(t)
	gatewayBaseURL := "https://" + gatewayAddress
	gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"
	localAddress, stopLocal := startLocalHTTPService(t)
	defer stopLocal()

	publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
	writeValidatedMetadata(t, metadataDir, publicKey, token, metadataOptions{authorizationTTL: 8 * time.Second})

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
	)
	defer gateway.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)

	agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	if body := waitTunnel(t, client, gatewayBaseURL, "/before-authorization-expiry", "one"); body != "e2e-local:/before-authorization-expiry:one" {
		t.Fatalf("unexpected pre-expiry response: %q", body)
	}

	waitFor(t, 25*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/after-authorization-expiry", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusServiceUnavailable
	})
	// Give the real Agent a bounded opportunity to consume session_revoked before collecting its process output.
	time.Sleep(500 * time.Millisecond)
	agent.stop(t)
	if !strings.Contains(agent.stderr.String(), "agent session revoked") {
		t.Fatalf("real Agent did not observe explicit session revocation after authorization expiry; stderr=%q", agent.stderr.String())
	}
}

func TestAgentGatewayEndToEndSecurityNegatives(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("E2E process orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)

	t.Run("wrong session token cannot authenticate", func(t *testing.T) {
		stateDir := t.TempDir()
		metadataDir := t.TempDir()
		certPath, keyPath, roots := writeCertificate(t)
		gatewayAddress := reserveAddress(t)
		gatewayBaseURL := "https://" + gatewayAddress
		gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"
		localAddress, stopLocal := startLocalHTTPService(t)
		defer stopLocal()

		publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
		wrongToken := token
		for wrongToken == token {
			wrongToken = randomToken(t)
		}
		writeValidatedMetadata(t, metadataDir, publicKey, wrongToken, metadataOptions{})

		gateway := startProcess(t, gatewayBinary,
			"-listen", gatewayAddress,
			"-tls-cert", certPath,
			"-tls-key", keyPath,
			"-metadata-dir", metadataDir,
		)
		defer gateway.stop(t)
		client := trustedClient(roots)
		waitGatewayHealth(t, client, gatewayBaseURL)
		agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
		defer agent.stop(t)

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			response, err := publicRequest(client, gatewayBaseURL, "/bad-auth", "")
			if err == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					t.Fatal("wrong-token Agent unexpectedly authenticated")
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("raw local target in external route is rejected", func(t *testing.T) {
		stateDir := t.TempDir()
		metadataDir := t.TempDir()
		certPath, keyPath, roots := writeCertificate(t)
		gatewayAddress := reserveAddress(t)
		gatewayBaseURL := "https://" + gatewayAddress
		gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"
		localAddress, stopLocal := startLocalHTTPService(t)
		defer stopLocal()

		publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
		writeValidatedMetadata(t, metadataDir, publicKey, token, metadataOptions{})
		routePath := filepath.Join(metadataDir, "routes", "route.json")
		routeBytes, err := os.ReadFile(routePath)
		if err != nil {
			t.Fatal(err)
		}
		var route map[string]any
		if err := json.Unmarshal(routeBytes, &route); err != nil {
			t.Fatal(err)
		}
		route["local_target"] = "169.254.169.254:80"
		writeJSON(t, routePath, route)

		gateway := startProcess(t, gatewayBinary,
			"-listen", gatewayAddress,
			"-tls-cert", certPath,
			"-tls-key", keyPath,
			"-metadata-dir", metadataDir,
		)
		defer gateway.stop(t)
		client := trustedClient(roots)
		waitGatewayHealth(t, client, gatewayBaseURL)
		agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
		defer agent.stop(t)

		response, err := publicRequest(client, gatewayBaseURL, "/raw-target", "")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("raw-target route status=%d want=%d", response.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("unapproved local endpoint never reaches a raw target", func(t *testing.T) {
		stateDir := t.TempDir()
		metadataDir := t.TempDir()
		certPath, keyPath, roots := writeCertificate(t)
		gatewayAddress := reserveAddress(t)
		gatewayBaseURL := "https://" + gatewayAddress
		gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"
		localAddress, stopLocal := startLocalHTTPService(t)
		defer stopLocal()

		publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
		writeValidatedMetadata(t, metadataDir, publicKey, token, metadataOptions{localEndpointID: "not-configured-locally"})

		gateway := startProcess(t, gatewayBinary,
			"-listen", gatewayAddress,
			"-tls-cert", certPath,
			"-tls-key", keyPath,
			"-metadata-dir", metadataDir,
		)
		defer gateway.stop(t)
		client := trustedClient(roots)
		waitGatewayHealth(t, client, gatewayBaseURL)
		agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
		defer agent.stop(t)

		waitFor(t, 5*time.Second, func() bool {
			response, err := publicRequest(client, gatewayBaseURL, "/unapproved-local", "")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			return response.StatusCode == http.StatusBadGateway
		})
	})
}

type metadataOptions struct {
	localEndpointID  string
	authorizationTTL time.Duration
}

func writeValidatedMetadata(t *testing.T, root, publicKey, token string, options metadataOptions) {
	t.Helper()
	localEndpointID := options.localEndpointID
	if localEndpointID == "" {
		localEndpointID = "local-http-001"
	}
	now := time.Now().UTC()
	authorizationTTL := options.authorizationTTL
	if authorizationTTL <= 0 {
		authorizationTTL = time.Hour
	}
	digest := sha256.Sum256([]byte(token))
	authorization := contractv1.DeviceSessionAuthorization{
		ContractVersion: contractv1.ProtocolVersion,
		AuthorizationID: "auth-runtime-001",
		DeviceID:        "device-runtime-001",
		DevicePublicKey: publicKey,
		TokenID:         "token-runtime-001",
		TokenSHA256:     hex.EncodeToString(digest[:]),
		IssuedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(authorizationTTL).Format(time.RFC3339),
		Disabled:        false,
	}
	route := contractv1.EndpointRouteAssignment{
		ContractVersion: contractv1.ProtocolVersion,
		AssignmentID:    "assign-runtime-001",
		EndpointID:      "endpoint-runtime-001",
		PublicHostname:  e2ePublicHost,
		DeviceID:        "device-runtime-001",
		LocalEndpointID: localEndpointID,
		Enabled:         true,
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
	}
	authJSON, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contractv1.ParseDeviceSessionAuthorization(authJSON, now); err != nil {
		t.Fatalf("authorization fixture does not satisfy external contract: %v", err)
	}
	routeJSON, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contractv1.ParseEndpointRouteAssignment(routeJSON, now); err != nil {
		t.Fatalf("route fixture does not satisfy external contract: %v", err)
	}
	writeJSON(t, filepath.Join(root, "authorizations", "auth.json"), authorization)
	writeJSON(t, filepath.Join(root, "routes", "route.json"), route)
}

func requiredBinaries(t *testing.T) (string, string) {
	t.Helper()
	agentBinary := os.Getenv("HOOSHIX_AGENT_BINARY")
	gatewayBinary := os.Getenv("HOOSHIX_GATEWAY_BINARY")
	if agentBinary == "" || gatewayBinary == "" {
		t.Skip("set HOOSHIX_AGENT_BINARY and HOOSHIX_GATEWAY_BINARY")
	}
	return agentBinary, gatewayBinary
}

func configureRealAgent(t *testing.T, agentBinary, stateDir, gatewayWSS, certPath, localAddress string) (string, string) {
	t.Helper()
	identity := runAgentJSON(t, agentBinary, nil, "init", "--state-dir", stateDir, "--json")
	publicKey := stringField(t, identity, "public_key")
	token := randomToken(t)
	configure := exec.Command(agentBinary,
		"configure", "--state-dir", stateDir,
		"--gateway", gatewayWSS,
		"--ca-file", certPath,
		"--device-id", "device-runtime-001",
		"--authorization-id", "auth-runtime-001",
		"--token-id", "token-runtime-001",
		"--token-stdin",
	)
	configure.Stdin = strings.NewReader(token + "\n")
	if output, err := configure.CombinedOutput(); err != nil {
		t.Fatalf("configure Agent: %v\n%s", err, output)
	}
	if output, err := exec.Command(agentBinary, "expose", "add", "--state-dir", stateDir, "--id", "local-http-001", "--target", localAddress).CombinedOutput(); err != nil {
		t.Fatalf("configure local exposure: %v\n%s", err, output)
	}
	return publicKey, token
}

func randomToken(t *testing.T) string {
	t.Helper()
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func trustedClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Timeout:   3 * time.Second,
	}
}

func waitGatewayHealth(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool {
		response, err := client.Get(baseURL + "/healthz")
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
}

func startLocalHTTPService(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := netListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "e2e-local:"+r.URL.Path+":"+string(body))
	})}
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String(), func() {
		_ = server.Close()
		_ = listener.Close()
	}
}

func netListenLoopback() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func publicRequestWithHost(client *http.Client, baseURL, path, body, host string) (*http.Response, error) {
	var reader io.Reader
	method := http.MethodGet
	if body != "" {
		method = http.MethodPost
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	request.Host = host
	return client.Do(request)
}
