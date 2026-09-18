package runtimegate_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRealTunnelHEADAndSSE(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process control; executed in the Linux runtime gate")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)
	stateDir, metadataDir := t.TempDir(), t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	address := reserveAddress(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			_, _ = io.WriteString(w, "data: hello\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(4 * time.Second):
			}
			return
		}
		w.Header().Set("Content-Length", "5")
		_, _ = io.WriteString(w, "hello")
	}))
	defer local.Close()
	key, token := configureRealAgent(t, agentBinary, stateDir, "wss://"+address+"/agent/v1/connect", certPath, strings.TrimPrefix(local.URL, "http://"))
	writeMetadata(t, metadataDir, key, token)
	gw, ops := startGatewayProcess(t, gatewayBinary, "-listen", address, "-tls-cert", certPath, "-tls-key", keyPath, "-metadata-dir", metadataDir, "-metadata-mode", "static")
	defer gw.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, ops)
	ag := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer ag.stop(t)
	waitTunnel(t, client, "https://"+address, "/warmup", "")
	t.Run("HEAD", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodHead, "https://"+address+"/head", nil)
		req.Host = e2ePublicHost
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != 200 || len(data) != 0 || res.ContentLength != 5 {
			t.Fatalf("HEAD: status=%d length=%d body=%q err=%v", res.StatusCode, res.ContentLength, data, err)
		}
	})
	t.Run("SSE-first-event", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/events", nil)
		req.Host = e2ePublicHost
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data := make([]byte, len("data: hello\n\n"))
		if _, err := io.ReadFull(res.Body, data); err != nil || string(data) != "data: hello\n\n" {
			t.Fatalf("first event before upstream completion: %q, %v", data, err)
		}
	})
}

func TestRealAgentRecoversAfterLongMetadataOutage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process control; executed in the Linux runtime gate")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)
	stateDir, metadataDir := t.TempDir(), t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	address := reserveAddress(t)
	localAddress, stopLocal := startLocalHTTPService(t)
	defer stopLocal()
	key, token := configureRealAgent(t, agentBinary, stateDir, "wss://"+address+"/agent/v1/connect", certPath, localAddress)
	publishRuntimeLiveGeneration(t, metadataDir, 1, "outage-1", e2ePublicHost, key, token, nil)
	gw, ops := startGatewayProcess(t, gatewayBinary, "-listen", address, "-tls-cert", certPath, "-tls-key", keyPath, "-metadata-dir", metadataDir, "-metadata-refresh-interval", "50ms", "-metadata-max-age", "3s")
	defer gw.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, ops)
	ag := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer ag.stop(t)
	waitTunnel(t, client, "https://"+address, "/before", "")
	waitRuntimeReady(t, client, ops, http.StatusServiceUnavailable)
	// Cross at least one real 15-second heartbeat, unlike the shorter stale
	// route test: the old session must lose authorization and reconnect.
	timer := time.NewTimer(17 * time.Second)
	<-timer.C
	deadline := time.Now().Add(15 * time.Second)
	for revision := uint64(2); time.Now().Before(deadline); revision++ {
		publishRuntimeLiveGeneration(t, metadataDir, revision, fmt.Sprintf("recovery-%d", revision), e2ePublicHost, key, token, nil)
		res, err := publicRequestWithHost(client, "https://"+address, "/after", "", e2ePublicHost)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("Agent did not reauthenticate after valid metadata returned")
}
