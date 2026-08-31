package runtimegate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const (
	prototypeHostOne = "app-one.hooshix.test"
	prototypeHostTwo = "app-two.hooshix.test"
)

func TestFirstPrototypeSmoke(t *testing.T) {
	agentBinary, gatewayBinary := requiredBinaries(t)

	stateDir := t.TempDir()
	metadataDir := t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	gatewayAddress := reserveAddress(t)
	gatewayBaseURL := "https://" + gatewayAddress
	gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"

	localOne, stopOne := startPrototypeHTTPService(t, "service-one")
	defer stopOne()
	localTwo, stopTwo := startPrototypeHTTPService(t, "service-two")
	defer stopTwo()
	if localOne == localTwo {
		t.Fatal("prototype services unexpectedly share one address")
	}

	publicKey, token := configurePrototypeAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localOne, localTwo)
	writePrototypeMetadata(t, metadataDir, publicKey, token)

	status := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if got := int(status["endpoint_count"].(float64)); got != 2 {
		t.Fatalf("status endpoint_count=%d want=2", got)
	}
	if got := stringField(t, status, "public_key"); got != publicKey {
		t.Fatalf("status public_key changed: got=%q want=%q", got, publicKey)
	}
	if credentials, ok := status["credentials_present"].(bool); !ok || !credentials {
		t.Fatal("status did not confirm credentials are present")
	}

	doctorOutput, err := exec.Command(agentBinary, "doctor", "--state-dir", stateDir, "--dial-local").CombinedOutput()
	if err != nil {
		t.Fatalf("Agent doctor failed: %v\n%s", err, doctorOutput)
	}
	if !strings.Contains(string(doctorOutput), "doctor: PASSED") || !strings.Contains(string(doctorOutput), "endpoints=2") {
		t.Fatalf("unexpected doctor output: %s", doctorOutput)
	}

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
		"-metadata-mode", "static",
	)
	defer killPrototypeProcess(t, gateway)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)

	agentOne := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer killPrototypeProcess(t, agentOne)
	responseOne := waitPrototypeRoute(t, client, gatewayBaseURL, prototypeHostOne, "/alpha", "payload-a")
	if responseOne != "service-one:/alpha:payload-a" {
		t.Fatalf("route one response=%q", responseOne)
	}
	responseTwo := waitPrototypeRoute(t, client, gatewayBaseURL, prototypeHostTwo, "/beta", "payload-b")
	if responseTwo != "service-two:/beta:payload-b" {
		t.Fatalf("route two response=%q", responseTwo)
	}

	killPrototypeProcess(t, agentOne)
	waitPrototypeOffline(t, client, gatewayBaseURL, prototypeHostOne)
	waitPrototypeOffline(t, client, gatewayBaseURL, prototypeHostTwo)

	agentTwo := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer killPrototypeProcess(t, agentTwo)
	responseOne = waitPrototypeRoute(t, client, gatewayBaseURL, prototypeHostOne, "/after-restart-one", "again-a")
	if responseOne != "service-one:/after-restart-one:again-a" {
		t.Fatalf("route one after restart response=%q", responseOne)
	}
	responseTwo = waitPrototypeRoute(t, client, gatewayBaseURL, prototypeHostTwo, "/after-restart-two", "again-b")
	if responseTwo != "service-two:/after-restart-two:again-b" {
		t.Fatalf("route two after restart response=%q", responseTwo)
	}

	restartedStatus := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if got := stringField(t, restartedStatus, "public_key"); got != publicKey {
		t.Fatal("Agent identity changed across prototype restart")
	}
	statusBytes, _ := json.Marshal(restartedStatus)
	killPrototypeProcess(t, agentTwo)
	killPrototypeProcess(t, gateway)
	combinedLogs := gateway.stderr.String() + agentOne.stderr.String() + agentTwo.stderr.String()
	if strings.Contains(string(statusBytes), token) || strings.Contains(combinedLogs, token) {
		t.Fatal("prototype evidence leaked session token")
	}
}

func configurePrototypeAgent(t *testing.T, agentBinary, stateDir, gatewayWSS, certPath, localOne, localTwo string) (string, string) {
	t.Helper()
	identity := runAgentJSON(t, agentBinary, nil, "init", "--state-dir", stateDir, "--json")
	publicKey := stringField(t, identity, "public_key")
	token := randomToken(t)
	configure := exec.Command(agentBinary,
		"configure", "--state-dir", stateDir,
		"--gateway", gatewayWSS,
		"--ca-file", certPath,
		"--device-id", "device-prototype-001",
		"--authorization-id", "auth-prototype-001",
		"--token-id", "token-prototype-001",
		"--token-stdin",
	)
	configure.Stdin = strings.NewReader(token + "\n")
	if output, err := configure.CombinedOutput(); err != nil {
		t.Fatalf("configure prototype Agent: %v\n%s", err, output)
	}
	for id, target := range map[string]string{
		"local-prototype-one": localOne,
		"local-prototype-two": localTwo,
	} {
		if output, err := exec.Command(agentBinary, "expose", "add", "--state-dir", stateDir, "--id", id, "--target", target).CombinedOutput(); err != nil {
			t.Fatalf("configure prototype exposure %s: %v\n%s", id, err, output)
		}
	}
	return publicKey, token
}

func writePrototypeMetadata(t *testing.T, root, publicKey, token string) {
	t.Helper()
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(token))
	authorization := contractv1.DeviceSessionAuthorization{
		ContractVersion: contractv1.ProtocolVersion,
		AuthorizationID: "auth-prototype-001",
		DeviceID:        "device-prototype-001",
		DevicePublicKey: publicKey,
		TokenID:         "token-prototype-001",
		TokenSHA256:     hex.EncodeToString(digest[:]),
		IssuedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
		Disabled:        false,
	}
	authJSON, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contractv1.ParseDeviceSessionAuthorization(authJSON, now); err != nil {
		t.Fatalf("prototype authorization violates external contract: %v", err)
	}
	writeJSON(t, filepath.Join(root, "authorizations", "prototype-auth.json"), authorization)

	routes := []contractv1.EndpointRouteAssignment{
		{
			ContractVersion: contractv1.ProtocolVersion,
			AssignmentID:    "assign-prototype-one",
			EndpointID:      "endpoint-prototype-one",
			PublicHostname:  prototypeHostOne,
			DeviceID:        "device-prototype-001",
			LocalEndpointID: "local-prototype-one",
			Enabled:         true,
			NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
		},
		{
			ContractVersion: contractv1.ProtocolVersion,
			AssignmentID:    "assign-prototype-two",
			EndpointID:      "endpoint-prototype-two",
			PublicHostname:  prototypeHostTwo,
			DeviceID:        "device-prototype-001",
			LocalEndpointID: "local-prototype-two",
			Enabled:         true,
			NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
		},
	}
	for i, route := range routes {
		routeJSON, err := json.Marshal(route)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := contractv1.ParseEndpointRouteAssignment(routeJSON, now); err != nil {
			t.Fatalf("prototype route %d violates external contract: %v", i+1, err)
		}
		writeJSON(t, filepath.Join(root, "routes", fmt.Sprintf("prototype-route-%d.json", i+1)), route)
	}
}

func startPrototypeHTTPService(t *testing.T, name string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, name+":"+r.URL.Path+":"+string(body))
	})}
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String(), func() {
		_ = server.Close()
		_ = listener.Close()
	}
}

func waitPrototypeRoute(t *testing.T, client *http.Client, baseURL, host, path, body string) string {
	t.Helper()
	var result string
	waitFor(t, 8*time.Second, func() bool {
		response, err := publicRequestWithHost(client, baseURL, path, body, host)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusOK {
			return false
		}
		result = string(data)
		return true
	})
	return result
}

func waitPrototypeOffline(t *testing.T, client *http.Client, baseURL, host string) {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool {
		response, err := publicRequestWithHost(client, baseURL, "/offline", "", host)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusServiceUnavailable
	})
}

func killPrototypeProcess(t *testing.T, process *process) {
	t.Helper()
	if process == nil || process.cmd == nil || process.cmd.Process == nil || process.cmd.ProcessState != nil {
		return
	}
	_ = process.cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- process.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("process %s did not exit after kill", process.cmd.Path)
	}
}
