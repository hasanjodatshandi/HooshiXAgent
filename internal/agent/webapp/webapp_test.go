package webapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

func readIfExists(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}

// newLoopbackRequest builds a request that appears to come from the loopback
// listener, which every accepted connection on the pairing UI necessarily
// does. Tests must set this explicitly: httptest defaults to a non-loopback
// RemoteAddr and the guard rejects that.
func newLoopbackRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:8799"
	return request
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

// writeTestCAPEM writes a real self-signed CA certificate as PEM, which is the
// shape a self-hosted operator points ca_file at.
func writeTestCAPEM(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HooshiX pairing test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTestECKeyPEM writes a PEM PRIVATE KEY: valid PEM, but not a trust anchor.
func writeTestECKeyPEM(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pairingJSON(device, authorization, tokenID string) string {
	return `{"gateway_url":"wss://gateway.example/agent/v1/connect","device_id":"` + device +
		`","authorization_id":"` + authorization + `","token_id":"` + tokenID +
		`","token":"test_session_token_0123456789ABCDEF"}`
}

// postPair submits the pairing form exactly as the page renders it, optionally
// with the CA file field the operator types into.
func postPair(t *testing.T, app *App, capability, csrf, pairing, caFile string) *httptest.ResponseRecorder {
	t.Helper()
	form := "hooshix_csrf=" + url.QueryEscape(csrf) + "&pairing=" + url.QueryEscape(pairing)
	if caFile != "" {
		form += "&ca_file=" + url.QueryEscape(caFile)
	}
	request := newLoopbackRequest(http.MethodPost, "/pair?cap="+capability, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

func getPage(t *testing.T, app *App, capability string) string {
	t.Helper()
	request := newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("page status=%d want=200", recorder.Code)
	}
	return recorder.Body.String()
}

// TestPairingRejectsCrossSiteFormPosts proves the LocalSystem pairing UI
// cannot be mutated by a cross-site form POST. The request carries a VALID
// capability and a VALID CSRF token, so it can only be rejected by the
// origin control — which is exactly the DNS-rebinding case (Host header set
// by the attacker's own name, Origin naming the attacker's site).
func TestPairingRejectsCrossSiteFormPosts(t *testing.T) {
	const gateway = "wss://attacker.example/agent/v1/connect"
	app, capability := newTestApp(t)
	handler := app.Handler()
	csrf := app.ensureCSRFToken()
	payload := `{"gateway_url":"` + gateway + `","device_id":"device-evil-000001","authorization_id":"auth-evil-000001","token_id":"token-evil-000001","token":"test_session_token_0123456789ABCDEF"}`
	forms := map[string]string{
		"/pair":           "hooshix_csrf=" + csrf + "&pairing=" + url.QueryEscape(payload),
		"/pairing/rotate": "hooshix_csrf=" + csrf,
		"/unpair":         "hooshix_csrf=" + csrf + "&reset_identity=true",
		"/expose/add":     "hooshix_csrf=" + csrf + "&id=evil&target=127.0.0.1:9999",
		"/expose/remove":  "hooshix_csrf=" + csrf + "&id=web-001",
	}
	for path, body := range forms {
		for _, host := range []string{"127.0.0.1:8799", "attacker.example:8799"} {
			request := newLoopbackRequest(http.MethodPost, path+"?cap="+capability, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "https://attacker.example")
			request.Host = host
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s cross-site POST (host=%s) status=%d want=403", path, host, recorder.Code)
			}
		}
	}
	// The rejected pairing must not have replaced the configured gateway.
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL == gateway {
		t.Fatalf("cross-site POST replaced the gateway with %s", gateway)
	}
}

// TestRejectsNonLoopbackRemoteAddress proves the guard fails closed for a
// connection that did not come from the loopback interface, even with a valid
// capability and no Origin header.
func TestRejectsNonLoopbackRemoteAddress(t *testing.T) {
	app, capability := newTestApp(t)
	request := httptest.NewRequest(http.MethodGet, "/?cap="+capability, nil)
	request.RemoteAddr = "10.0.0.7:4000"
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-loopback request status=%d want=403", recorder.Code)
	}
}

// TestRootPageRequiresCapability proves an unauthenticated GET / returns the
// bootstrap page and discloses NEITHER the pairing capability NOR the CSRF
// token. Before the fix this request returned the real page containing both.
func TestRootPageRequiresCapability(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()

	request := newLoopbackRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bootstrap GET status=%d want=200", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, capability) {
		t.Fatalf("unauthenticated root page disclosed the pairing capability:\n%s", body)
	}
	if strings.Contains(body, csrf) {
		t.Fatalf("unauthenticated root page disclosed the CSRF token:\n%s", body)
	}
	if !strings.Contains(body, "Pairing authorization required") {
		t.Fatalf("bootstrap page missing its notice:\n%s", body)
	}

	// A wrong capability must not fall through to the real page either.
	request = newLoopbackRequest(http.MethodGet, "/?cap="+strings.Repeat("A", 43), nil)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if strings.Contains(recorder.Body.String(), csrf) {
		t.Fatalf("wrong-capability root page disclosed the CSRF token:\n%s", recorder.Body.String())
	}

	// With the capability the real page is served (and carries both secrets,
	// which is now acceptable: the caller already holds them).
	request = newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated GET status=%d want=200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), csrf) {
		t.Fatalf("authenticated page must embed the CSRF token:\n%s", recorder.Body.String())
	}
}

// TestRootPageDoesNotCreateState proves rendering the page is read-only: an
// unauthenticated GET must not create an identity or any secret material in
// the state directory.
func TestRootPageDoesNotCreateState(t *testing.T) {
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
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	request := newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("root GET status=%d want=200", recorder.Code)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("GET / created state: before=%d entries after=%d entries", len(before), len(after))
	}
	for _, name := range []string{"secrets.json", "secrets.dpapi", "config.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("GET / created %s", name)
		}
	}
}

// TestCapabilityRotatesAfterPairing proves a successful pairing invalidates
// the old capability (and the URL that carried it) and issues a new one.
func TestCapabilityRotatesAfterPairing(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	payload := `{"gateway_url":"wss://gateway.example/agent/v1/connect","device_id":"device-test-000001","authorization_id":"auth-test-000001","token_id":"token-test-000001","token":"test_session_token_0123456789ABCDEF"}`
	request := newLoopbackRequest(http.MethodPost, "/pair?cap="+capability,
		strings.NewReader("hooshix_csrf="+csrf+"&pairing="+url.QueryEscape(payload)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("pairing status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	rotated := app.currentCapability()
	if rotated == capability {
		t.Fatal("capability was not rotated after a successful pairing")
	}
	onDisk, err := agent.LoadPairingCapability(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != rotated {
		t.Fatalf("in-memory capability %q != on-disk %q", rotated, onDisk)
	}
	// The old capability must no longer authenticate.
	request = newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if strings.Contains(recorder.Body.String(), csrf) {
		t.Fatal("the rotated-away capability still authenticated")
	}
}

// TestRotateCapabilityRequiresCSRF proves the explicit rotate action cannot be
// triggered by a request that lacks the per-process CSRF token.
func TestRotateCapabilityRequiresCSRF(t *testing.T) {
	app, capability := newTestApp(t)
	request := newLoopbackRequest(http.MethodPost, "/pairing/rotate?cap="+capability, strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("rotate without CSRF status=%d want=403", recorder.Code)
	}
	if app.currentCapability() != capability {
		t.Fatal("capability rotated without CSRF")
	}
}

// TestListenPublishesVerifiableEndpoint proves a bound listener publishes the
// port and identity token the tray uses to attribute the loopback port to the
// service, and that the identity probe (the only route reachable without the
// capability) discloses exactly that token and nothing else.
func TestListenPublishesVerifiableEndpoint(t *testing.T) {
	app, capability := newTestApp(t)
	listener, err := app.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint, err := agent.LoadPairingEndpoint(app.StateDir())
	if err != nil {
		t.Fatalf("listener did not publish an endpoint record: %v", err)
	}
	if len(endpoint.Token) != 43 {
		t.Fatalf("endpoint token=%q is not 256 bits of base64url", endpoint.Token)
	}
	address := listener.Addr().String()
	if fmt.Sprintf("127.0.0.1:%d", endpoint.Port) != address {
		t.Fatalf("published port %d does not match listener address %s", endpoint.Port, address)
	}
	server := &http.Server{Handler: app.Handler()}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	response, err := http.Get("http://" + address + "/pairing/identity")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("identity probe status=%d want=200", response.StatusCode)
	}
	var identity struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Token != endpoint.Token {
		t.Fatalf("probe token=%q want the published token %q", identity.Token, endpoint.Token)
	}
	if strings.Contains(identity.Token, capability) {
		t.Fatal("the identity probe disclosed the pairing capability")
	}
}

// TestServeListenerWithdrawsEndpointRecord proves the published record is
// removed on shutdown, so the tray can never verify against a listener that
// has gone away and then leak the capability to whoever takes the port next.
func TestServeListenerWithdrawsEndpointRecord(t *testing.T) {
	app, _ := newTestApp(t)
	listener, err := app.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	address := listener.Addr().String()
	go func() {
		done <- app.ServeListener(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := http.Get("http://" + address + "/pairing/identity")
		if err == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pairing listener never started serving: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeListener: %v", err)
	}
	if _, err := agent.LoadPairingEndpoint(app.StateDir()); err == nil {
		t.Fatal("the endpoint record survived listener shutdown")
	}
}

// TestLoopbackOriginValidation pins the origin grammar: only exact ASCII
// loopback http/https origins pass, including that a same-name Host header
// cannot launder a foreign origin.
func TestLoopbackOriginValidation(t *testing.T) {
	accepted := []string{
		"http://127.0.0.1:8799",
		"http://127.0.0.1",
		"https://localhost:8799/pair",
		"http://[::1]:8799/",
	}
	for _, value := range accepted {
		if !isLoopbackOrigin(value) {
			t.Fatalf("origin %q should be accepted", value)
		}
	}
	rejected := []string{
		"https://attacker.example",
		"http://attacker.example:8799",
		"https://127.0.0.1@attacker.example",
		"null",
		"",
		"http://localho\u017ft:8799",
		"http://127.0.0.1.attacker.example",
		"ftp://127.0.0.1",
		":/evil",
	}
	for _, value := range rejected {
		if isLoopbackOrigin(value) {
			t.Fatalf("origin %q must be rejected", value)
		}
	}
}

func TestOriginIsAuthoritativeOverReferer(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	request := newLoopbackRequest(http.MethodPost, "/pairing/rotate?cap="+capability, strings.NewReader("hooshix_csrf="+csrf))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	request.Header.Set("Referer", "https://privacy-extension.invalid/stripped")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("same-origin POST with rewritten Referer status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRefererRejectsCrossSitePostWhenOriginMissing(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	request := newLoopbackRequest(http.MethodPost, "/pairing/rotate?cap="+capability, strings.NewReader("hooshix_csrf="+csrf))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", "https://attacker.example/form")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-site Referer without Origin status=%d want=403", recorder.Code)
	}
}

// TestTunnelHealthRendersStatusSnapshot proves the pairing page surfaces the
// service-written status.json fields (connection, reconnects, last error) and
// escapes error text derived from remote input.
func TestTunnelHealthRendersStatusSnapshot(t *testing.T) {
	app, capability := newTestApp(t)
	health := TunnelHealth{
		Phase:        "running",
		State:        "connected",
		Reconnects:   7,
		LastError:    `failed dial <script>alert("x")</script>`,
		LastUpdateAt: "2026-09-16T07:00:00Z",
	}
	data, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.StateDir(), "status.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	request := newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("root GET status=%d want=200", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"Tunnel status", "connected", "7", "Tunnel status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q in body:\n%s", want, body)
		}
	}
	// Error text must be escaped, never rendered as markup.
	if strings.Contains(body, "<script>") {
		t.Fatalf("last error rendered unescaped:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected escaped error text in body:\n%s", body)
	}
}

// TestTunnelHealthMissingFileShowsNeutralRow proves a missing status.json
// (service stopped, first boot) renders the neutral "status unavailable"
// row instead of failing the page.
func TestTunnelHealthMissingFileShowsNeutralRow(t *testing.T) {
	app, capability := newTestApp(t)
	request := newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("root GET status=%d want=200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "status unavailable") {
		t.Fatalf("missing neutral status row:\n%s", recorder.Body.String())
	}
}

// TestPairingRequiresInstalledCapability proves deliberate local clients
// (curl-style with no Origin, or a same-origin browser form) can still use the
// mutating endpoints, but only with the installer-written capability and the
// CSRF token.
func TestPairingRequiresInstalledCapability(t *testing.T) {
	app, capability := newTestApp(t)
	handler := app.Handler()

	request := newLoopbackRequest(http.MethodPost, "/expose/add", strings.NewReader("id=web-001&target=127.0.0.1:4000"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated local mutation status=%d want=401", recorder.Code)
	}

	cspr := app.ensureCSRFToken()
	body := "id=web-002&target=127.0.0.1%3A4001&hooshix_csrf=" + cspr
	request = newLoopbackRequest(http.MethodPost, "/expose/add?cap="+capability, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("authenticated same-origin mutation status=%d want=303", recorder.Code)
	}
}

func TestPairingNoticeEscapesHTML(t *testing.T) {
	app, capability := newTestApp(t)
	app.setNotice(`<script>alert("xss")</script>`)
	request := newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
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
	request := newLoopbackRequest(http.MethodPost, "/pair", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", app.ensureCSRFToken())
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

// TestPairingStoresSuppliedCAFile proves a CA file supplied through the
// pairing UI is validated and stored, so a self-hosted deployment can trust a
// private CA without installing it into the machine trust store. Before this
// the payload had no CA field at all and the UI could not express it.
func TestPairingStoresSuppliedCAFile(t *testing.T) {
	app, capability := newTestApp(t)
	caPath := filepath.Join(t.TempDir(), "private-ca.crt")
	writeTestCAPEM(t, caPath)
	csrf := app.ensureCSRFToken()

	// The CA file is trust material: it must not be settable without the CSRF
	// token, even with a valid capability.
	recorder := postPair(t, app, capability, "", pairingJSON("device-test-000001", "auth-test-000001", "token-test-000001"), caPath)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("CA file pairing without CSRF status=%d want=403", recorder.Code)
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != "" {
		t.Fatalf("CA file was stored without the CSRF gate: %q", config.CAFile)
	}

	recorder = postPair(t, app, capability, csrf, pairingJSON("device-test-000001", "auth-test-000001", "token-test-000001"), caPath)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("pairing with CA file status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	config, err = agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != caPath {
		t.Fatalf("configured CA file=%q want=%q", config.CAFile, caPath)
	}
	page := getPage(t, app, app.currentCapability())
	if !strings.Contains(page, `name="ca_file"`) {
		t.Fatalf("pairing form does not render the CA file field:\n%s", page)
	}
	if !strings.Contains(page, caPath) {
		t.Fatalf("the page does not report the configured CA file %q:\n%s", caPath, page)
	}
}

// TestPairingWithoutCAFilePreservesConfiguredOne proves pairing never silently
// drops a configured trust anchor: a request that carries no CA file keeps the
// existing value, while an explicitly supplied one wins.
func TestPairingWithoutCAFilePreservesConfiguredOne(t *testing.T) {
	app, capability := newTestApp(t)
	caDir := t.TempDir()
	configuredPath := filepath.Join(caDir, "configured-ca.crt")
	writeTestCAPEM(t, configuredPath)
	replacementPath := filepath.Join(caDir, "replacement-ca.crt")
	writeTestCAPEM(t, replacementPath)

	// The state a `configure --ca-file` invocation leaves behind.
	if err := agent.SaveConfig(app.StateDir(), agent.Config{
		Version:       agent.ConfigVersion,
		CAFile:        configuredPath,
		UpdateChannel: "stable",
	}); err != nil {
		t.Fatal(err)
	}
	csrf := app.ensureCSRFToken()

	recorder := postPair(t, app, capability, csrf, pairingJSON("device-test-000001", "auth-test-000001", "token-test-000001"), "")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("pairing without CA file status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != configuredPath {
		t.Fatalf("pairing without a CA file dropped the configured trust anchor: ca_file=%q want=%q", config.CAFile, configuredPath)
	}
	if !strings.Contains(getPage(t, app, app.currentCapability()), configuredPath) {
		t.Fatal("the page does not report the preserved CA file")
	}

	// An explicitly supplied value wins over the preserved one. The capability
	// rotated on the successful pairing above, so the second form uses the live
	// value the tray would have handed the operator.
	recorder = postPair(t, app, app.currentCapability(), csrf, pairingJSON("device-test-000002", "auth-test-000002", "token-test-000002"), replacementPath)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("pairing with replacement CA status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	config, err = agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != replacementPath {
		t.Fatalf("supplied CA file did not win: ca_file=%q want=%q", config.CAFile, replacementPath)
	}
}

// TestPairingRejectsInvalidCAFile proves a path that is not an existing,
// readable file holding a PEM trust anchor is rejected with a clear error and
// leaves the Agent state unpaired and unchanged. The supplied path is read by
// the service account, so this is what keeps a pairing request from becoming
// an arbitrary file-read primitive.
func TestPairingRejectsInvalidCAFile(t *testing.T) {
	app, capability := newTestApp(t)
	scratch := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(scratch, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	directory := filepath.Join(scratch, "ca-directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(scratch, "private-key.pem")
	writeTestECKeyPEM(t, privateKeyPath)
	emptyPath := writeFile("empty.crt", "")
	textPath := writeFile("not-a-certificate.txt", "this file is not a certificate\n")

	cases := []struct {
		name string
		path string
		// want is the reason fragment the operator must see; the directory case
		// may fail either at open or at the regular-file check depending on
		// platform open semantics for directories.
		want []string
	}{
		{"missing file", filepath.Join(scratch, "absent.crt"), []string{"open CA file"}},
		{"directory", directory, []string{"open CA file", "regular file"}},
		{"empty file", emptyPath, []string{"empty"}},
		{"not PEM", textPath, []string{"no PEM certificate"}},
		{"PEM private key only", privateKeyPath, []string{"no PEM certificate"}},
	}
	config := agent.Config{}
	for _, testCase := range cases {
		recorder := postPair(t, app, capability, app.ensureCSRFToken(),
			pairingJSON("device-test-000001", "auth-test-000001", "token-test-000001"), testCase.path)
		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("%s: status=%d want=303", testCase.name, recorder.Code)
		}
		page := getPage(t, app, capability)
		if !strings.Contains(page, "ca_file") {
			t.Fatalf("%s: rejection was not reported as a CA file error:\n%s", testCase.name, page)
		}
		matched := false
		for _, want := range testCase.want {
			if strings.Contains(page, want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("%s: page does not explain the rejection (want one of %q):\n%s", testCase.name, testCase.want, page)
		}
		// Nothing may be stored: the rejected pairing leaves the device unpaired
		// with its previous trust anchor untouched.
		var err error
		config, err = agent.LoadConfig(app.StateDir())
		if err != nil {
			t.Fatal(err)
		}
		if config.CAFile != "" || config.GatewayURL != "" || config.DeviceID != "" {
			t.Fatalf("%s: rejected pairing mutated state: %+v", testCase.name, config)
		}
	}
}

// pairedApp returns an app whose state directory holds a complete pairing,
// together with the public key the pairing registered and the CSRF token.
func pairedApp(t *testing.T) (*App, string, string, ed25519.PublicKey) {
	t.Helper()
	app, capability := newTestApp(t)
	store := agent.NewPlatformSecretStore(app.StateDir())
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	if err := agent.SaveConfig(app.StateDir(), agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      "wss://gateway.example/agent/v1/connect",
		GatewayAliases:  []string{"wss://backup.example/agent/v1/connect"},
		DeviceID:        "device-unpair-000001",
		AuthorizationID: "auth-unpair-000001",
		TokenID:         "token-unpair-000001",
		UpdateChannel:   "stable",
		Endpoints:       []agent.Endpoint{{ID: "local-http-001", Target: "127.0.0.1:4000"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetSessionToken(store, "test_session_token_0123456789ABCDEF"); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	return app, capability, app.ensureCSRFToken(), publicKey
}

// postUnpair submits the clear-pairing form exactly as the page renders it.
func postUnpair(t *testing.T, app *App, capability, csrf, resetIdentity string) *httptest.ResponseRecorder {
	t.Helper()
	form := "hooshix_csrf=" + url.QueryEscape(csrf)
	if resetIdentity != "" {
		form += "&reset_identity=" + url.QueryEscape(resetIdentity)
	}
	request := newLoopbackRequest(http.MethodPost, "/unpair?cap="+capability, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

// TestUnpairFromThePageClearsThePairing proves the UI action the operator can
// click is the same atomic operation the CLI performs: the pairing record and
// the session token are cleared, the device returns to the pending_config
// state, and the identity is preserved so re-pairing does not mint a second
// key the panel never authorized.
func TestUnpairFromThePageClearsThePairing(t *testing.T) {
	app, capability, csrf, publicKey := pairedApp(t)
	store := agent.NewPlatformSecretStore(app.StateDir())

	recorder := postUnpair(t, app, capability, csrf, "")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("unpair status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || len(config.GatewayAliases) != 0 || config.CAFile != "" ||
		config.DeviceID != "" || config.AuthorizationID != "" || config.TokenID != "" {
		t.Fatalf("unpair left pairing material behind: %+v", config)
	}
	if err := config.ValidateRuntime(); err == nil {
		t.Fatal("the agent did not return to the unpaired (pending_config) state")
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("unpair left the session token in the secret store")
	}
	after, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatalf("unpair destroyed the device identity: %v", err)
	}
	if !bytes.Equal(publicKey, after) {
		t.Fatal("unpair replaced the device identity")
	}
	if len(config.Endpoints) != 1 {
		t.Fatalf("unpair dropped local endpoint mappings: %+v", config.Endpoints)
	}
	if _, err := os.Stat(filepath.Join(app.StateDir(), ".state-transaction")); !os.IsNotExist(err) {
		t.Fatalf("unpair left a state transaction journal behind: %v", err)
	}
	page := getPage(t, app, capability)
	if !strings.Contains(page, "Unpair this device") {
		t.Fatalf("the page does not offer the clear-pairing action:\n%s", page)
	}
	if !strings.Contains(page, "unpaired") {
		t.Fatalf("the page does not report the unpair:\n%s", page)
	}
}

// TestUnpairFromThePageRequiresCapabilityAndCSRF proves the new action is
// behind exactly the same gates as every other mutating route, so a request
// without the capability or the per-process CSRF token cannot clear a pairing.
func TestUnpairFromThePageRequiresCapabilityAndCSRF(t *testing.T) {
	app, capability, csrf, _ := pairedApp(t)

	recorder := postUnpair(t, app, capability, "", "")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unpair without CSRF status=%d want=403", recorder.Code)
	}
	request := newLoopbackRequest(http.MethodPost, "/unpair", strings.NewReader("hooshix_csrf="+url.QueryEscape(csrf)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unpair without capability status=%d want=401", recorder.Code)
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL == "" || config.DeviceID == "" {
		t.Fatalf("a rejected unpair still cleared the pairing: %+v", config)
	}
	if token, err := agent.LoadSessionToken(agent.NewPlatformSecretStore(app.StateDir())); err != nil || token == "" {
		t.Fatalf("a rejected unpair still cleared the session token: token=%q err=%v", token, err)
	}
}

// TestUnpairFromThePageWithResetIdentityReplacesTheKey proves the checkbox is
// the only page path that mints a replacement identity, and that the fresh key
// is minted by the process serving the UI (the only process that can read it
// back) inside the same transaction.
func TestUnpairFromThePageWithResetIdentityReplacesTheKey(t *testing.T) {
	app, capability, csrf, publicKey := pairedApp(t)
	store := agent.NewPlatformSecretStore(app.StateDir())

	recorder := postUnpair(t, app, capability, csrf, "true")
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("unpair status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	after, _, err := agent.LoadIdentity(store)
	if err != nil {
		t.Fatalf("reset-identity unpair left no usable identity: %v", err)
	}
	if bytes.Equal(publicKey, after) {
		t.Fatal("reset_identity did not replace the device identity")
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("unpair left the session token in the secret store")
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || config.DeviceID != "" {
		t.Fatalf("reset_identity unpair left pairing material behind: %+v", config)
	}
	// The page shows the new key so the operator can register it.
	page := getPage(t, app, capability)
	if !strings.Contains(page, agent.PublicKeyBase64(after)) {
		t.Fatalf("the page does not show the replacement public key:\n%s", page)
	}
}

// TestUnpairJSONClientReportsTheOutcome proves the machine-readable answer the
// `unpair` command consumes is returned to an authenticated JSON client,
// including the already-unpaired case that must succeed rather than fail.
func TestUnpairJSONClientReportsTheOutcome(t *testing.T) {
	app, capability, csrf, publicKey := pairedApp(t)
	store := agent.NewPlatformSecretStore(app.StateDir())

	call := func() map[string]any {
		request := newLoopbackRequest(http.MethodPost, "/unpair", strings.NewReader(""))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-HooshiX-Pairing-Capability", capability)
		request.Header.Set("X-HooshiX-CSRF", csrf)
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("JSON unpair status=%d want=200: %s", recorder.Code, recorder.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode unpair JSON: %v\n%s", err, recorder.Body.String())
		}
		return result
	}

	first := call()
	if first["already_unpaired"] != false || first["identity_preserved"] != true {
		t.Fatalf("unexpected first unpair result: %#v", first)
	}
	if first["device_id"] != "device-unpair-000001" {
		t.Fatalf("unpair did not report the cleared device id: %#v", first)
	}
	if first["public_key"] != agent.PublicKeyBase64(publicKey) {
		t.Fatalf("unpair did not report the preserved identity: %#v", first)
	}
	if _, err := agent.LoadSessionToken(store); err == nil {
		t.Fatal("the JSON unpair path left the session token in the secret store")
	}
	// Idempotent: the second call succeeds and says there was nothing to clear.
	second := call()
	if second["already_unpaired"] != true {
		t.Fatalf("second unpair did not report an already-unpaired agent: %#v", second)
	}
}
