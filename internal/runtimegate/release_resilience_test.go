package runtimegate_test

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkInterruptionAndColdRestartRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release resilience process orchestration uses POSIX interrupt semantics in CI")
	}
	agentBinary, gatewayBinary := requiredBinaries(t)

	stateDir := t.TempDir()
	metadataDir := t.TempDir()
	certPath, keyPath, roots := writeCertificate(t)
	gatewayAddress := reserveAddress(t)
	gatewayBaseURL := "https://" + gatewayAddress

	proxy, err := newInterruptibleTCPProxy(gatewayAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	gatewayWSS := "wss://" + proxy.Addr() + "/agent/v1/connect"

	localAddress, stopLocal := startLocalHTTPService(t)
	defer stopLocal()
	publicKey, token := configureRealAgent(t, agentBinary, stateDir, gatewayWSS, certPath, localAddress)
	writeValidatedMetadata(t, metadataDir, publicKey, token, metadataOptions{})

	gateway := startProcess(t, gatewayBinary,
		"-listen", gatewayAddress,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
		"-metadata-dir", metadataDir,
		"-metadata-mode", "static",
	)
	defer gateway.stop(t)
	client := trustedClient(roots)
	waitGatewayHealth(t, client, gatewayBaseURL)

	agentOne := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	if body := waitTunnel(t, client, gatewayBaseURL, "/before-network-cut", "one"); body != "e2e-local:/before-network-cut:one" {
		t.Fatalf("unexpected pre-interruption body: %q", body)
	}

	proxy.Pause()
	waitFor(t, 5*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/during-network-cut", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 503
	})
	// Keep the path unavailable long enough for at least one bounded reconnect attempt.
	time.Sleep(1200 * time.Millisecond)
	proxy.Resume()
	if body := waitTunnel(t, client, gatewayBaseURL, "/after-network-restore", "two"); body != "e2e-local:/after-network-restore:two" {
		t.Fatalf("unexpected post-interruption body: %q", body)
	}

	// A fresh process with the same persisted state is the release-gate cold-start boundary.
	// Native startup registration is validated independently on each supported OS package.
	agentOne.stop(t)
	waitFor(t, 5*time.Second, func() bool {
		response, err := publicRequest(client, gatewayBaseURL, "/cold-start-offline", "")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 503
	})
	agentTwo := startProcess(t, agentBinary, "run", "--state-dir", stateDir)
	defer agentTwo.stop(t)
	if body := waitTunnel(t, client, gatewayBaseURL, "/after-cold-start", "three"); body != "e2e-local:/after-cold-start:three" {
		t.Fatalf("unexpected post-cold-start body: %q", body)
	}
	status := runAgentJSON(t, agentBinary, nil, "status", "--state-dir", stateDir, "--json")
	if stringField(t, status, "public_key") != publicKey {
		t.Fatal("Agent identity changed across cold restart")
	}
	combinedLogs := agentOne.stderr.String() + agentTwo.stderr.String() + gateway.stderr.String()
	if token != "" && containsSecret(combinedLogs, token) {
		t.Fatal("release resilience evidence leaked the session token")
	}
}

func containsSecret(text, secret string) bool {
	return secret != "" && len(text) >= len(secret) && stringContains(text, secret)
}

func stringContains(text, fragment string) bool {
	for i := 0; i+len(fragment) <= len(text); i++ {
		if text[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

type interruptibleTCPProxy struct {
	listener net.Listener
	upstream string
	paused   atomic.Bool
	mu       sync.Mutex
	pairs    map[*proxyPair]struct{}
}

type proxyPair struct {
	downstream net.Conn
	upstream   net.Conn
}

func newInterruptibleTCPProxy(upstream string) (*interruptibleTCPProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &interruptibleTCPProxy{listener: listener, upstream: upstream, pairs: make(map[*proxyPair]struct{})}
	go proxy.acceptLoop()
	return proxy, nil
}

func (proxy *interruptibleTCPProxy) Addr() string {
	return proxy.listener.Addr().String()
}

func (proxy *interruptibleTCPProxy) Pause() {
	proxy.paused.Store(true)
	proxy.closeActivePairs()
}

func (proxy *interruptibleTCPProxy) Resume() {
	proxy.paused.Store(false)
}

func (proxy *interruptibleTCPProxy) Close() {
	proxy.paused.Store(true)
	_ = proxy.listener.Close()
	proxy.closeActivePairs()
}

func (proxy *interruptibleTCPProxy) acceptLoop() {
	for {
		downstream, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		if proxy.paused.Load() {
			_ = downstream.Close()
			continue
		}
		upstream, err := net.DialTimeout("tcp", proxy.upstream, time.Second)
		if err != nil {
			_ = downstream.Close()
			continue
		}
		pair := &proxyPair{downstream: downstream, upstream: upstream}
		proxy.mu.Lock()
		proxy.pairs[pair] = struct{}{}
		proxy.mu.Unlock()
		go proxy.bridge(pair)
	}
}

func (proxy *interruptibleTCPProxy) bridge(pair *proxyPair) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(pair.upstream, pair.downstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(pair.downstream, pair.upstream)
		done <- struct{}{}
	}()
	<-done
	_ = pair.downstream.Close()
	_ = pair.upstream.Close()
	proxy.mu.Lock()
	delete(proxy.pairs, pair)
	proxy.mu.Unlock()
}

func (proxy *interruptibleTCPProxy) closeActivePairs() {
	proxy.mu.Lock()
	pairs := make([]*proxyPair, 0, len(proxy.pairs))
	for pair := range proxy.pairs {
		pairs = append(pairs, pair)
	}
	proxy.mu.Unlock()
	for _, pair := range pairs {
		_ = pair.downstream.Close()
		_ = pair.upstream.Close()
	}
}
