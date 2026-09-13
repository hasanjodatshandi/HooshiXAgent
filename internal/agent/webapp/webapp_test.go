package webapp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

func readIfExists(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}

func newTestApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingCapability(dir, capability); err != nil {
		t.Fatal(err)
	}
	app, err := NewApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return app, capability
}

// TestPairingRejectsCrossSiteFormPosts proves the LocalSystem pairing UI
// cannot be mutated by a cross-site form POST: a browser-originated request
// carrying a foreign Origin must be rejected before any state change.
func TestPairingRejectsCrossSiteFormPosts(t *testing.T) {
	app, capability := newTestApp(t)
	handler := app.Handler()

	forms := map[string]string{
		"/pair":          "pairing=%7B%7D",
		"/expose/add":    "id=evil&target=127.0.0.1:9999",
		"/expose/remove": "id=web-001",
	}
	for path, body := range forms {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "https://attacker.example")
		request.Header.Set("X-HooshiX-Pairing-Capability", capability)
		request.Host = "127.0.0.1:8799"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s cross-site POST status=%d want=403", path, recorder.Code)
		}
	}
}

// TestPairingAcceptsLocalCapabilityRequests proves deliberate local clients
// (curl-style with no Origin, or a same-origin browser form) can still use
// the mutating endpoints after the CSRF guard.
func TestPairingRequiresInstalledCapability(t *testing.T) {
	app, capability := newTestApp(t)
	handler := app.Handler()

	request := httptest.NewRequest(http.MethodPost, "/expose/add", strings.NewReader("id=web-001&target=127.0.0.1:4000"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-HooshiX-Local", "1")
	request.Host = "127.0.0.1:8799"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated local mutation status=%d want=401", recorder.Code)
	}

	csrf := app.ensureCSRFToken()
	body := "id=web-002&target=127.0.0.1%3A4001&hooshix_csrf=" + csrf
	request = httptest.NewRequest(http.MethodPost, "/expose/add?cap="+capability, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	request.Host = "127.0.0.1:8799"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("authenticated same-origin mutation status=%d want=303", recorder.Code)
	}
}

func TestPairingNoticeEscapesHTML(t *testing.T) {
	app, capability := newTestApp(t)
	app.setNotice(`<script>alert("xss")</script>`)
	request := httptest.NewRequest(http.MethodGet, "/?cap="+capability, nil)
	request.Host = "127.0.0.1:8799"
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if strings.Contains(recorder.Body.String(), `<script>alert`) {
		t.Fatal("notice rendered executable HTML")
	}
	if !strings.Contains(recorder.Body.String(), `&lt;script&gt;`) {
		t.Fatal("escaped notice was not rendered")
	}
}

func TestJSONPairingAcceptsCapabilityAndCSRFHeaders(t *testing.T) {
	app, capability := newTestApp(t)
	body := `{"gateway_url":"wss://gateway.example/agent/v1/connect","device_id":"device-test-000001","authorization_id":"auth-test-000001","token_id":"token-test-000001","token":"test_session_token_0123456789ABCDEF"}`
	request := httptest.NewRequest(http.MethodPost, "/pair", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-HooshiX-Local", "1")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", app.ensureCSRFToken())
	request.Host = "127.0.0.1:8799"
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("authenticated JSON pairing status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
}

// TestPairingLegacyTokenCopyIsNotWritten proves ApplyPairing never writes
// the plaintext token.txt record: the credential lives only in the secret
// store.
func TestPairingLegacyTokenCopyIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.WritePairingCapability(dir, capability); err != nil {
		t.Fatal(err)
	}
	app, err := NewApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := PairingPayload{
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		DeviceID:        "device-test-000001",
		AuthorizationID: "auth-test-000001",
		TokenID:         "token-test-000001",
		Token:           "test_session_token_0123456789ABCDEF",
	}
	if err := app.ApplyPairing(payload); err != nil {
		t.Fatal(err)
	}
	if tokenBytes, readErr := readIfExists(dir, "token.txt"); readErr == nil {
		t.Fatalf("ApplyPairing wrote a plaintext token.txt: %q", tokenBytes)
	}
}
