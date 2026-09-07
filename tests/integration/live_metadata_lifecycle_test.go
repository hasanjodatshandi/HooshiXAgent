package runtimegate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const liveUpdatedHost = "live-next.hooshix.test"

func TestAgentGatewayLiveMetadataRouteStaleRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("live metadata process orchestration uses POSIX interrupt semantics in CI")
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
	publishRuntimeLiveGeneration(t, metadataDir, 1, "generation-1", e2ePublicHost, publicKey, token, nil)

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
		"-metadata-refresh-interval", "50ms",
		"-metadata-max-age", "3s",
	)
	defer gateway.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)
	waitRuntimeReady(t, client, gatewayBaseURL, http.StatusOK)
	publishRuntimeLiveGeneration(t, metadataDir, 2, "generation-2", e2ePublicHost, publicKey, token, nil)

	agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agent.stop(t)
	if got := waitTunnel(t, client, gatewayBaseURL, "/live-initial", "initial"); got != "e2e-local:/live-initial:initial" {
		t.Fatalf("initial live route response=%q", got)
	}

	publishRuntimeLiveGeneration(t, metadataDir, 3, "generation-3", liveUpdatedHost, publicKey, token, nil)
	waitFor(t, 3*time.Second, func() bool {
		response, err := publicRequestWithHost(client, gatewayBaseURL, "/live-updated", "updated", liveUpdatedHost)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	oldRoute, err := publicRequestWithHost(client, gatewayBaseURL, "/old-route", "", e2ePublicHost)
	if err != nil {
		t.Fatal(err)
	}
	oldRoute.Body.Close()
	if oldRoute.StatusCode != http.StatusNotFound {
		t.Fatalf("old route survived atomic generation replacement: status=%d", oldRoute.StatusCode)
	}

	// No new generation is published. The accepted generation's fixed local deadline must expire;
	// successful polls of the same revision must never extend its authority.
	waitRuntimeReady(t, client, gatewayBaseURL, http.StatusServiceUnavailable)
	staleRoute, err := publicRequestWithHost(client, gatewayBaseURL, "/stale", "", liveUpdatedHost)
	if err != nil {
		t.Fatal(err)
	}
	staleRoute.Body.Close()
	if staleRoute.StatusCode == http.StatusOK {
		t.Fatal("stale live metadata continued routing new ingress")
	}
	health, err := client.Get(gatewayBaseURL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("metadata staleness changed process liveness: status=%d", health.StatusCode)
	}

	publishRuntimeLiveGeneration(t, metadataDir, 4, "generation-4", liveUpdatedHost, publicKey, token, nil)
	waitRuntimeReady(t, client, gatewayBaseURL, http.StatusOK)
	waitFor(t, 3*time.Second, func() bool {
		response, err := publicRequestWithHost(client, gatewayBaseURL, "/recovered", "recovered", liveUpdatedHost)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
}

func TestAgentGatewayLiveMetadataRevocationTerminatesSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("live metadata process orchestration uses POSIX interrupt semantics in CI")
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
	publishRuntimeLiveGeneration(t, metadataDir, 1, "generation-1", e2ePublicHost, publicKey, token, nil)
	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
		"-metadata-mode", "live",
		"-metadata-refresh-interval", "50ms",
		"-metadata-max-age", "30s",
	)
	defer gateway.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)
	waitRuntimeReady(t, client, gatewayBaseURL, http.StatusOK)

	agent := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agent.stop(t)
	if got := waitTunnel(t, client, gatewayBaseURL, "/before-live-revocation", "before"); got != "e2e-local:/before-live-revocation:before" {
		t.Fatalf("pre-revocation response=%q", got)
	}

	revocation := &contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-live-e2e-001",
		SubjectKind:     "device_session_authorization",
		SubjectID:       "auth-runtime-001",
		EffectiveAt:     time.Now().UTC().Add(-time.Second).Format(time.RFC3339),
		ReasonCode:      "credential_revoked",
	}
	publishRuntimeLiveGeneration(t, metadataDir, 2, "generation-2", e2ePublicHost, publicKey, token, revocation)

	// Existing sessions are revalidated on the existing bounded heartbeat lifecycle. The default
	// interval is 15 seconds; allow one interval plus refresh/scheduling headroom.
	waitFor(t, 18*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/after-live-revocation", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusServiceUnavailable
	})
	waitRuntimeReady(t, client, gatewayBaseURL, http.StatusOK)
}

func publishRuntimeLiveGeneration(t *testing.T, root string, revision uint64, generation, hostname, publicKey, token string, revocation *contractv1.RevocationSignal) {
	t.Helper()
	now := time.Now().UTC()
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
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
		Disabled:        false,
	}
	route := contractv1.EndpointRouteAssignment{
		ContractVersion: contractv1.ProtocolVersion,
		AssignmentID:    "assign-runtime-live-001",
		EndpointID:      "endpoint-runtime-live-001",
		PublicHostname:  hostname,
		DeviceID:        "device-runtime-001",
		LocalEndpointID: "local-http-001",
		Enabled:         true,
		NotBefore:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
	}
	generationRoot := filepath.Join(root, "generations", generation)
	writeJSON(t, filepath.Join(generationRoot, "authorizations", "authorization.json"), authorization)
	writeJSON(t, filepath.Join(generationRoot, "routes", "route.json"), route)
	if revocation == nil {
		if err := os.MkdirAll(filepath.Join(generationRoot, "revocations"), 0o700); err != nil {
			t.Fatal(err)
		}
	} else {
		writeJSON(t, filepath.Join(generationRoot, "revocations", "revocation.json"), *revocation)
	}
	manifest := map[string]any{
		"contract_version": contractv1.ProtocolVersion,
		"revision":         revision,
		"generation":       generation,
		"published_at":     now.Format(time.RFC3339Nano),
		"valid_until":      now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	manifestPath := filepath.Join(root, "current.json")
	tmpPath := manifestPath + ".tmp"
	writeJSON(t, tmpPath, manifest)
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		t.Fatal(err)
	}
}

func waitRuntimeReady(t *testing.T, client *http.Client, baseURL string, want int) {
	t.Helper()
	waitFor(t, 6*time.Second, func() bool {
		response, err := client.Get(baseURL + "/readyz")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == want
	})
}
