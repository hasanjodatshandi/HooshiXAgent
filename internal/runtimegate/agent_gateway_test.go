package runtimegate_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRealAgentGatewayRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("runtime gate orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary := os.Getenv("HOOSHIX_AGENT_BINARY")
	gatewayBinary := os.Getenv("HOOSHIX_GATEWAY_BINARY")
	if agentBinary == "" || gatewayBinary == "" {
		t.Skip("set HOOSHIX_AGENT_BINARY and HOOSHIX_GATEWAY_BINARY")
	}

	stateDir := t.TempDir()
	metadataDir := t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	gatewayAddress := reserveAddress(t)
	gatewayBaseURL := "https://" + gatewayAddress
	gatewayWSS := "wss://" + gatewayAddress + "/agent/v1/connect"

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-HooshiX-Local", "true")
		fmt.Fprintf(w, "real-agent:%s:%s", r.URL.Path, body)
	}))
	defer local.Close()
	localTarget := strings.TrimPrefix(local.URL, "http://")

	identityOne := runAgentJSON(t, agentBinary, nil, "init", "--state-dir", stateDir, "--json")
	identityTwo := runAgentJSON(t, agentBinary, nil, "init", "--state-dir", stateDir, "--json")
	publicKey := stringField(t, identityOne, "public_key")
	if publicKey != stringField(t, identityTwo, "public_key") {
		t.Fatal("Agent identity did not persist across init executions")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
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
	if output, err := exec.Command(agentBinary, "expose", "add", "--state-dir", stateDir, "--id", "local-http-001", "--target", localTarget).CombinedOutput(); err != nil {
		t.Fatalf("configure exposure: %v\n%s", err, output)
	}

	writeMetadata(t, metadataDir, publicKey, token)

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
		"-metadata-mode", "static",
	)
	defer gateway.stop(t)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Timeout:   3 * time.Second,
	}
	waitFor(t, 5*time.Second, func() bool {
		response, err := client.Get(gatewayBaseURL + "/healthz")
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == http.StatusOK
	})

	doctorOutput, err := exec.Command(agentBinary, "doctor", "--state-dir", stateDir, "--dial-local").CombinedOutput()
	if err != nil {
		t.Fatalf("Agent doctor: %v\n%s", err, doctorOutput)
	}
	if !strings.Contains(string(doctorOutput), "PASSED") {
		t.Fatalf("unexpected doctor output: %q", doctorOutput)
	}

	agentOne := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	responseBody := waitTunnel(t, client, gatewayBaseURL, "/first", "payload-one")
	if responseBody != "real-agent:/first:payload-one" {
		t.Fatalf("unexpected first tunnel body: %q", responseBody)
	}

	status := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if stringField(t, status, "public_key") != publicKey {
		t.Fatal("status returned a different persisted identity")
	}
	statusJSON, _ := json.Marshal(status)
	if bytes.Contains(statusJSON, []byte(token)) {
		t.Fatal("Agent status leaked the session token")
	}

	agentOne.stop(t)
	waitFor(t, 5*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/offline", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusServiceUnavailable
	})

	agentTwo := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agentTwo.stop(t)
	responseBody = waitTunnel(t, client, gatewayBaseURL, "/second", "payload-two")
	if responseBody != "real-agent:/second:payload-two" {
		t.Fatalf("unexpected reconnect tunnel body: %q", responseBody)
	}

	combinedLogs := agentOne.stderr.String() + agentTwo.stderr.String() + gateway.stderr.String()
	if strings.Contains(combinedLogs, token) {
		t.Fatal("runtime logs leaked the session token")
	}

	serviceOutput, err := exec.Command(agentBinary, "service-spec", "--state-dir", stateDir).CombinedOutput()
	if err != nil || len(serviceOutput) == 0 {
		t.Fatalf("service-spec foundation failed: %v\n%s", err, serviceOutput)
	}
	updateOutput, err := exec.Command(agentBinary, "update-info", "--state-dir", stateDir, "--json").CombinedOutput()
	if err != nil || !bytes.Contains(updateOutput, []byte(`"channel":"stable"`)) {
		t.Fatalf("update-info foundation failed: %v\n%s", err, updateOutput)
	}
}

func waitTunnel(t *testing.T, client *http.Client, baseURL, path, body string) string {
	t.Helper()
	var result string
	waitFor(t, 8*time.Second, func() bool {
		response, err := publicRequest(client, baseURL, path, body)
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

func publicRequest(client *http.Client, baseURL, path, body string) (*http.Response, error) {
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
	request.Host = "demo.hooshix.test"
	return client.Do(request)
}

type process struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func startProcess(t *testing.T, binary string, args ...string) *process {
	t.Helper()
	process := &process{cmd: exec.Command(binary, args...)}
	process.cmd.Stdout = &process.stdout
	process.cmd.Stderr = &process.stderr
	if err := process.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	return process
}

func (process *process) stopGracefully(t *testing.T, timeout time.Duration) {
	t.Helper()
	if process == nil || process.cmd == nil || process.cmd.Process == nil || process.cmd.ProcessState != nil {
		return
	}
	if err := process.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal process for graceful shutdown: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- process.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process did not exit cleanly after interrupt: %v\nstderr=%s", err, process.stderr.String())
		}
	case <-time.After(timeout):
		_ = process.cmd.Process.Kill()
		<-done
		t.Fatalf("process exceeded graceful shutdown deadline %s\nstderr=%s", timeout, process.stderr.String())
	}
}

func (process *process) stop(t *testing.T) {
	t.Helper()
	if process == nil || process.cmd == nil || process.cmd.Process == nil || process.cmd.ProcessState != nil {
		return
	}
	if err := process.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = process.cmd.Process.Kill()
	}
	done := make(chan error, 1)
	go func() { done <- process.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = process.cmd.Process.Kill()
		<-done
	}
}

func runAgentJSON(t *testing.T, binary string, stdin io.Reader, args ...string) map[string]any {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Stdin = stdin
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Agent command %v: %v\n%s", args, err, output)
	}
	var value map[string]any
	if err := json.Unmarshal(output, &value); err != nil {
		t.Fatalf("decode Agent JSON %v: %v\n%s", args, err, output)
	}
	return value
}

func stringField(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	text, ok := value[key].(string)
	if !ok || text == "" {
		t.Fatalf("missing string field %q in %#v", key, value)
	}
	return text
}

func writeMetadata(t *testing.T, root, publicKey, token string) {
	t.Helper()
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(token))
	authorization := map[string]any{
		"contract_version":  1,
		"authorization_id":  "auth-runtime-001",
		"device_id":         "device-runtime-001",
		"device_public_key": publicKey,
		"token_id":          "token-runtime-001",
		"token_sha256":      hex.EncodeToString(digest[:]),
		"issued_at":         now.Add(-time.Minute).Format(time.RFC3339),
		"not_before":        now.Add(-time.Minute).Format(time.RFC3339),
		"expires_at":        now.Add(time.Hour).Format(time.RFC3339),
		"disabled":          false,
	}
	route := map[string]any{
		"contract_version":  1,
		"assignment_id":     "assign-runtime-001",
		"endpoint_id":       "endpoint-runtime-001",
		"public_hostname":   "demo.hooshix.test",
		"device_id":         "device-runtime-001",
		"local_endpoint_id": "local-http-001",
		"enabled":           true,
		"not_before":        now.Add(-time.Minute).Format(time.RFC3339),
		"expires_at":        now.Add(time.Hour).Format(time.RFC3339),
	}
	writeJSON(t, filepath.Join(root, "authorizations", "auth.json"), authorization)
	writeJSON(t, filepath.Join(root, "routes", "route.json"), route)
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func writeCertificate(t *testing.T) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certPath = filepath.Join(dir, "gateway.crt")
	keyPath = filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append generated certificate")
	}
	return certPath, keyPath, roots
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
