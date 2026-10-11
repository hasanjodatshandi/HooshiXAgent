package connector

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWithCAClientTrustsPrivateAnchor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.GatewayURL = "wss://" + server.Listener.Addr().String() + "/connector/v1/connect"
	config.GrantID, config.TokenID, config.Token = "grant-1", "token-1", testToken()
	config.ListenAddress = "127.0.0.1:0"

	if _, err := (&http.Client{}).Get(server.URL); err == nil {
		t.Fatal("system trust accepted the test certificate; the negative case is meaningless")
	}

	config.CAFile = writeTrustAnchor(t, server)
	withAnchor, err := config.withCAClient()
	if err != nil {
		t.Fatalf("trust anchor rejected: %v", err)
	}
	response, err := withAnchor.HTTPClient.Get(server.URL)
	if err != nil {
		t.Fatalf("GET through configured anchor: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestWithCAClientKeepsSuppliedHTTPClient(t *testing.T) {
	// A caller that passed its own client owns its trust: the GUI and the
	// in-process tests do, and a stray CAFile must not be loaded behind them.
	config := DefaultConfig()
	config.HTTPClient = &http.Client{}
	config.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	kept, err := config.withCAClient()
	if err != nil {
		t.Fatalf("supplied client overruled: %v", err)
	}
	if kept.HTTPClient != config.HTTPClient {
		t.Fatal("withCAClient replaced the supplied HTTPClient")
	}
}

func TestWithCAClientRejectsUnusableTrustAnchors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(privateKey, []byte("-----BEGIN PRIVATE KEY-----\nZGVhZGJlZWY=\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.pem"), empty, privateKey, dir} {
		config := DefaultConfig()
		config.CAFile = path
		if _, err := config.withCAClient(); err == nil {
			t.Fatalf("unusable trust anchor accepted: %s", path)
		}
	}
}

func writeTrustAnchor(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway-ca.pem")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
