package runtimegate_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAgentGatewayFailoverBetweenGateways proves the Phase-3 HA model: an
// Agent configured with a primary and an alias gateway keeps public routing
// available when the primary dies and the bounded reconnect failover reaches
// the secondary with the same persisted identity.
func TestAgentGatewayFailoverBetweenGateways(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("failover process orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)

	stateDir := t.TempDir()
	metadataPrimary := t.TempDir()
	metadataSecondary := t.TempDir()

	// Two independent gateways, each with its own TLS and metadata snapshot.
	certPrimary, keyPrimary, rootsPrimary := writeCertificate(t)
	primaryAddress := reserveAddress(t)
	primaryBase := "https://" + primaryAddress
	primaryWSS := "wss://" + primaryAddress + "/agent/v1/connect"

	certSecondary, keySecondary, _ := writeCertificate(t)
	secondaryAddress := reserveAddress(t)
	secondaryBase := "https://" + secondaryAddress
	secondaryWSS := "wss://" + secondaryAddress + "/agent/v1/connect"

	localAddress, stopLocal := startLocalHTTPService(t)
	defer stopLocal()

	// The Agent CA bundle must trust both gateways so a single transport can
	// verify either endpoint during failover.
	primaryPEM, err := os.ReadFile(certPrimary)
	if err != nil {
		t.Fatal(err)
	}
	secondaryPEM, err := os.ReadFile(certSecondary)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(bundlePath, append(append([]byte(nil), primaryPEM...), secondaryPEM...), 0o600); err != nil {
		t.Fatal(err)
	}

	publicKey, token := configureFailoverAgent(t, agentBinary, stateDir, primaryWSS, secondaryWSS, bundlePath, localAddress)
	writeValidatedMetadata(t, metadataPrimary, publicKey, token, metadataOptions{})
	writeValidatedMetadata(t, metadataSecondary, publicKey, token, metadataOptions{})

	primary := startProcess(t, gatewayBinary,
		"-listen", primaryAddress,
		"-tls-cert", certPrimary,
		"-tls-key", keyPrimary,
		"-metadata-dir", metadataPrimary,
		"-metadata-mode", "static",
	)
	secondary := startProcess(t, gatewayBinary,
		"-listen", secondaryAddress,
		"-tls-cert", certSecondary,
		"-tls-key", keySecondary,
		"-metadata-dir", metadataSecondary,
		"-metadata-mode", "static",
	)
	defer secondary.stop(t)

	primaryClient := trustedClient(rootsPrimary)
	waitGatewayHealth(t, primaryClient, primaryBase)
	secondaryClient := trustedClientFromBundle(t, bundlePath)
	waitGatewayHealth(t, secondaryClient, secondaryBase)

	agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agent.stop(t)

	first := waitTunnel(t, primaryClient, primaryBase, "/before-failover", "payload-one")
	if first != "e2e-local:/before-failover:payload-one" {
		t.Fatalf("unexpected pre-failover response: %q", first)
	}

	// Kill the primary: the route through it disappears with the process
	// (connection refused), proving fail-closed behavior while the bounded
	// failover schedule rotates to the alias gateway.
	primary.stop(t)

	// The Agent's bounded failover reconnect must reach the secondary and
	// restore the same route through the alias gateway. Allow generous
	// headroom for the reconnect backoff plus a full failover dial cycle.
	var second string
	var converged bool
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := publicRequest(secondaryClient, secondaryBase, "/after-failover", "payload-two")
		if err == nil {
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				second = string(data)
				converged = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !converged {
		t.Fatalf("failover did not converge agent_stderr=%s", agent.stderr.String())
	}
	if second != "e2e-local:/after-failover:payload-two" {
		t.Fatalf("unexpected post-failover response: %q agent_stderr=%s", second, agent.stderr.String())
	}

	status := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if stringField(t, status, "public_key") != publicKey {
		t.Fatal("failover changed the persisted Agent identity")
	}
	combinedLogs := agent.stderr.String() + primary.stderr.String() + secondary.stderr.String()
	if strings.Contains(combinedLogs, token) {
		t.Fatal("failover evidence leaked the session token")
	}
}

func configureFailoverAgent(t *testing.T, binary, stateDir, primaryWSS, secondaryWSS, caBundle, localAddress string) (string, string) {
	t.Helper()
	identity := runAgentJSON(t, binary, nil, "init", "--state-dir", stateDir, "--json")
	publicKey := stringField(t, identity, "public_key")
	token := randomToken(t)
	configure := exec.Command(binary,
		"configure", "--state-dir", stateDir,
		"--gateway", primaryWSS,
		"--gateway-alias", secondaryWSS,
		"--ca-file", caBundle,
		"--device-id", "device-runtime-001",
		"--authorization-id", "auth-runtime-001",
		"--token-id", "token-runtime-001",
		"--token-stdin",
	)
	configure.Stdin = strings.NewReader(token + "\n")
	if output, err := configure.CombinedOutput(); err != nil {
		t.Fatalf("configure failover Agent: %v\n%s", err, output)
	}
	if output, err := exec.Command(binary, "expose", "add", "--state-dir", stateDir, "--id", "local-http-001", "--target", localAddress).CombinedOutput(); err != nil {
		t.Fatalf("configure failover exposure: %v\n%s", err, output)
	}
	return publicKey, token
}

// trustedClientFromBundle builds an HTTPS client trusting the concatenated
// PEM bundle used by the failover scenario.
func trustedClientFromBundle(t *testing.T, bundlePath string) *http.Client {
	t.Helper()
	pemData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		t.Fatal("append failover bundle certificates")
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		Timeout:   3 * time.Second,
	}
}
