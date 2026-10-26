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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
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
	"github.com/hasanjodatshandi/HooshiXAgent/internal/enrollment"
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

// newEnrollmentPanel serves the panel API the enrollment client speaks to:
// create → 201 with a fixed user code, proof → 204, claim → claimed
// credentials bound to a fixed gateway.
func newEnrollmentPanel(t *testing.T) *httptest.Server {
	t.Helper()
	panel := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/api/v1/agent/enrollments":
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"enrollment_id":    "enroll-ABCDEFGHIJKL",
				"user_code":        "ABCD-EFGH",
				"poll_token":       strings.Repeat("p", 43),
				"challenge":        base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				"verification_uri": "https://panel.hooshix.test/enroll",
				"expires_at":       time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
			})
		case strings.HasSuffix(request.URL.Path, "/proof"):
			response.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(request.URL.Path, "/claim"):
			_ = json.NewEncoder(response).Encode(map[string]string{
				"state": "claimed", "device_id": "device-001", "authorization_id": "auth-001",
				"token_id": "token-001", "token": strings.Repeat("t", 43),
				"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
				"gateway_url": "wss://tunnel.hooshix.test/agent/v1/connect",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(panel.Close)
	return panel
}

func TestServiceOwnedEnrollmentCommitsCredentialsAndRotatesCapability(t *testing.T) {
	app, capability := newTestApp(t)
	store := agent.NewPlatformSecretStore(app.StateDir())
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	panel := newEnrollmentPanel(t)
	app.enrollmentClient = enrollment.NewClient(panel.Client())
	listener, err := app.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- app.ServeListener(ctx, listener, slog.Default()) }()
	defer func() {
		cancel()
		if err := <-serveDone; err != nil {
			t.Errorf("serve enrollment UI: %v", err)
		}
	}()

	started, err := agent.StartServiceEnrollment(app.StateDir(), panel.URL, "office PC")
	if err != nil || started.UserCode != "ABCD-EFGH" {
		t.Fatalf("start = %+v, %v", started, err)
	}
	claimed, err := agent.ClaimServiceEnrollment(app.StateDir())
	if err != nil || claimed.State != "claimed" || claimed.DeviceID != "device-001" {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.DeviceID != "device-001" || config.GatewayURL != "wss://tunnel.hooshix.test/agent/v1/connect" {
		t.Fatalf("config = %+v", config)
	}
	if token, err := agent.LoadSessionToken(store); err != nil || token != strings.Repeat("t", 43) {
		t.Fatalf("stored token = %q, %v", token, err)
	}
	// A successful claim rotates the pairing capability; the claim response
	// must carry the fresh value because the page URL embeds it.
	rotated := app.currentCapability()
	if rotated == capability {
		t.Fatal("successful enrollment did not rotate the pairing capability")
	}
	if claimed.Capability != rotated {
		t.Fatalf("claim response capability=%q does not match the live capability %q", claimed.Capability, rotated)
	}
	onDisk, err := agent.LoadPairingCapability(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != rotated {
		t.Fatalf("in-memory capability %q != on-disk %q", rotated, onDisk)
	}
	// The old capability must no longer authenticate against the state API.
	if stale := getStateResponse(t, app, capability); stale.Code != http.StatusUnauthorized {
		t.Fatalf("the rotated-away capability still authenticated (status=%d)", stale.Code)
	}
	if fresh := getState(t, app, rotated); fresh.CSRF == "" {
		t.Fatal("the rotated capability did not unlock /api/state")
	}
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

func enrollmentStartBody(t *testing.T, serverURL, deviceName, caFile string) string {
	t.Helper()
	payload := map[string]string{"server_url": serverURL, "device_name": deviceName}
	if caFile != "" {
		payload["ca_file"] = caFile
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// postEnrollmentStart submits the enrollment start request exactly as the
// page's script does: JSON body, CSRF header, capability in the query.
func postEnrollmentStart(t *testing.T, app *App, capability, csrf, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLoopbackRequest(http.MethodPost, "/enrollment/start?cap="+capability, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		request.Header.Set("X-HooshiX-CSRF", csrf)
	}
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

// postEnrollmentClaim polls the claim endpoint the same way the page's
// polling script does.
func postEnrollmentClaim(t *testing.T, app *App, capability, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLoopbackRequest(http.MethodPost, "/enrollment/claim?cap="+capability, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		request.Header.Set("X-HooshiX-CSRF", csrf)
	}
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

// enrollWithPanel wires the app to a fresh mock panel and runs start+claim,
// returning the claim recorder. It creates the device identity because Begin
// signs the enrollment proof with the device key.
func enrollWithPanel(t *testing.T, app *App, capability, csrf, caFile string) *httptest.ResponseRecorder {
	t.Helper()
	store := agent.NewPlatformSecretStore(app.StateDir())
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	panel := newEnrollmentPanel(t)
	app.enrollmentClient = enrollment.NewClient(panel.Client())
	started := postEnrollmentStart(t, app, capability, csrf, enrollmentStartBody(t, panel.URL, "office PC", caFile))
	if started.Code != http.StatusCreated {
		t.Fatalf("enrollment start status=%d want=201: %s", started.Code, started.Body.String())
	}
	return postEnrollmentClaim(t, app, capability, csrf)
}

// getStateResponse fetches the state document the SPA renders from, using the
// same capability-in-query authentication the page URL carries.
func getStateResponse(t *testing.T, app *App, capability string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLoopbackRequest(http.MethodGet, "/api/state?cap="+url.QueryEscape(capability), nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

func getState(t *testing.T, app *App, capability string) uiStateResponse {
	t.Helper()
	recorder := getStateResponse(t, app, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	var state uiStateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode state: %v\n%s", err, recorder.Body.String())
	}
	return state
}

// TestPairingRejectsCrossSiteFormPosts proves the LocalSystem pairing UI
// cannot be mutated by a cross-site POST. The request carries a VALID
// capability and a VALID CSRF token, so it can only be rejected by the
// origin control — which is exactly the DNS-rebinding case (Host header set
// by the attacker's own name, Origin naming the attacker's site).
func TestPairingRejectsCrossSiteFormPosts(t *testing.T) {
	app, capability := newTestApp(t)
	handler := app.Handler()
	csrf := app.ensureCSRFToken()
	forms := map[string]struct {
		contentType string
		body        string
	}{
		"/enrollment/start": {"application/json", `{"server_url":"https://panel.hooshix-agent.ir","device_name":"evil"}`},
		"/enrollment/claim": {"application/json", `{}`},
		"/pairing/rotate":   {"application/x-www-form-urlencoded", "hooshix_csrf=" + csrf},
		"/unpair":           {"application/x-www-form-urlencoded", "hooshix_csrf=" + csrf + "&reset_identity=true"},
		"/expose/add":       {"application/x-www-form-urlencoded", "hooshix_csrf=" + csrf + "&id=evil&target=127.0.0.1:9999"},
		"/expose/remove":    {"application/x-www-form-urlencoded", "hooshix_csrf=" + csrf + "&id=web-001"},
	}
	for path, form := range forms {
		for _, host := range []string{"127.0.0.1:8799", "attacker.example:8799"} {
			request := newLoopbackRequest(http.MethodPost, path+"?cap="+capability, strings.NewReader(form.body))
			request.Header.Set("Content-Type", form.contentType)
			request.Header.Set("Origin", "https://attacker.example")
			request.Host = host
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s cross-site POST (host=%s) status=%d want=403", path, host, recorder.Code)
			}
		}
	}
	// None of the rejected requests may have written pairing material.
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "" || config.DeviceID != "" {
		t.Fatalf("cross-site POST wrote pairing material: %+v", config)
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
// capability-free bootstrap page and discloses NEITHER the pairing capability
// NOR the CSRF token. The authenticated shell is a static build artifact, so
// the CSRF token comes from the separately gated state endpoint.
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

	// A wrong capability must not fall through to the shell or the state API.
	request = newLoopbackRequest(http.MethodGet, "/?cap="+strings.Repeat("A", 43), nil)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	body = recorder.Body.String()
	if strings.Contains(body, csrf) || strings.Contains(body, `id="root"`) {
		t.Fatalf("wrong-capability root page disclosed the shell or CSRF token:\n%s", body)
	}
	if !strings.Contains(body, "Pairing authorization required") {
		t.Fatalf("wrong-capability root page is not the bootstrap page:\n%s", body)
	}

	// Without a capability the state document is refused outright.
	if rejected := getStateResponse(t, app, ""); rejected.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated state status=%d want=401", rejected.Code)
	}

	// With the capability the static shell is served. It embeds no secret:
	// state, including the CSRF token, arrives from /api/state.
	request = newLoopbackRequest(http.MethodGet, "/?cap="+capability, nil)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated GET status=%d want=200", recorder.Code)
	}
	shell := recorder.Body.String()
	if !strings.Contains(shell, `id="root"`) {
		t.Fatalf("authenticated GET did not serve the SPA shell:\n%s", shell)
	}
	if strings.Contains(shell, csrf) || strings.Contains(shell, capability) {
		t.Fatal("the static shell embeds a state secret")
	}
	state := getState(t, app, capability)
	if state.CSRF != csrf {
		t.Fatalf("state CSRF token=%q want the live token", state.CSRF)
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
	// The state endpoint loads the config and public key but must not create
	// either: a GET is a read, not a provisioning step.
	if stateResponse := getStateResponse(t, app, capability); stateResponse.Code != http.StatusOK {
		t.Fatalf("state GET status=%d want=200: %s", stateResponse.Code, stateResponse.Body.String())
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

func TestNullOriginAcceptsOnlyUserInitiatedSameOriginLoopbackNavigation(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	newRequest := func() *http.Request {
		request := newLoopbackRequest(http.MethodPost, "/pairing/rotate?cap="+capability, strings.NewReader("hooshix_csrf="+csrf))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "null")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		request.Header.Set("Sec-Fetch-User", "?1")
		return request
	}

	request := newRequest()
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("same-origin null-Origin navigation status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}

	for name, mutate := range map[string]func(*http.Request){
		"foreign host": func(request *http.Request) { request.Host = "attacker.example" },
		"cross-site":   func(request *http.Request) { request.Header.Set("Sec-Fetch-Site", "cross-site") },
		"scripted":     func(request *http.Request) { request.Header.Del("Sec-Fetch-User") },
		"fetch":        func(request *http.Request) { request.Header.Set("Sec-Fetch-Mode", "cors") },
		"subresource":  func(request *http.Request) { request.Header.Set("Sec-Fetch-Dest", "empty") },
	} {
		t.Run(name, func(t *testing.T) {
			// The accepted request rotated the capability, so authenticate the
			// rejection cases with the current value to isolate the origin gate.
			capability = app.currentCapability()
			request := newRequest()
			mutate(request)
			recorder := httptest.NewRecorder()
			app.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d want=403", recorder.Code)
			}
		})
	}
}

// TestTunnelHealthSnapshotReachesState proves the state endpoint surfaces the
// service-written status.json fields (connection, reconnects, last error) and
// that remote-derived error text is JSON-encoded rather than embedded as
// markup.
func TestTunnelHealthSnapshotReachesState(t *testing.T) {
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

	recorder := getStateResponse(t, app, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state GET status=%d want=200", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "failed dial <script>") {
		t.Fatalf("last error was emitted as markup:\n%s", recorder.Body.String())
	}
	state := getState(t, app, capability)
	if state.Tunnel != health {
		t.Fatalf("tunnel health=%+v want=%+v", state.Tunnel, health)
	}
}

// TestTunnelHealthMissingFileShowsNeutralRow proves a missing status.json
// (service stopped, first boot) yields the neutral "status unavailable" state
// instead of failing the state document.
func TestTunnelHealthMissingFileShowsNeutralRow(t *testing.T) {
	app, capability := newTestApp(t)
	state := getState(t, app, capability)
	if state.Tunnel.Phase != "unknown" || state.Tunnel.State != "status-unavailable" {
		t.Fatalf("missing status.json produced %+v", state.Tunnel)
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

// TestPairingNoticeIsJSONEncoded proves an operator notice containing markup
// is delivered as a JSON string the SPA renders as text, never as executable
// markup.
func TestPairingNoticeIsJSONEncoded(t *testing.T) {
	app, capability := newTestApp(t)
	const notice = `<script>alert("xss")</script>`
	app.setNotice(notice)
	recorder := getStateResponse(t, app, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state GET status=%d want=200", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), `<script>alert`) {
		t.Fatal("notice was emitted as executable HTML")
	}
	if state := getState(t, app, capability); state.Notice != notice {
		t.Fatalf("notice=%q want=%q", state.Notice, notice)
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
// enrollment form is validated and stored, so a self-hosted deployment can
// trust a private CA without installing it into the machine trust store.
func TestPairingStoresSuppliedCAFile(t *testing.T) {
	app, capability := newTestApp(t)
	caPath := filepath.Join(t.TempDir(), "private-ca.crt")
	writeTestCAPEM(t, caPath)
	csrf := app.ensureCSRFToken()

	// The CA file is trust material: it must not be settable without the CSRF
	// token, even with a valid capability.
	recorder := postEnrollmentStart(t, app, capability, "", enrollmentStartBody(t, "https://panel.hooshix.test", "office PC", caPath))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("enrollment start without CSRF status=%d want=403", recorder.Code)
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != "" {
		t.Fatalf("CA file was stored without the CSRF gate: %q", config.CAFile)
	}

	recorder = enrollWithPanel(t, app, capability, csrf, caPath)
	if recorder.Code != http.StatusOK {
		t.Fatalf("enrollment claim status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	config, err = agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != caPath {
		t.Fatalf("configured CA file=%q want=%q", config.CAFile, caPath)
	}
	if state := getState(t, app, app.currentCapability()); state.Config.CAFile != caPath {
		t.Fatalf("the state document does not report the configured CA file %q: %q", caPath, state.Config.CAFile)
	}
}

// TestPairingWithoutCAFilePreservesConfiguredOne proves an enrollment never
// silently drops a configured trust anchor: a start that carries no CA file
// keeps the existing value, while an explicitly supplied one wins.
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

	recorder := enrollWithPanel(t, app, capability, csrf, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("enrollment claim status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	if config.CAFile != configuredPath {
		t.Fatalf("enrollment without a CA file dropped the configured trust anchor: ca_file=%q want=%q", config.CAFile, configuredPath)
	}
	if state := getState(t, app, app.currentCapability()); state.Config.CAFile != configuredPath {
		t.Fatalf("the state document does not report the preserved CA file: %q", state.Config.CAFile)
	}

	// An explicitly supplied value wins over the preserved one. The capability
	// rotated on the successful claim above, so the second round uses the live
	// value the tray would have handed the operator.
	recorder = enrollWithPanel(t, app, app.currentCapability(), csrf, replacementPath)
	if recorder.Code != http.StatusOK {
		t.Fatalf("enrollment claim with replacement CA status=%d want=200: %s", recorder.Code, recorder.Body.String())
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
// readable file holding a PEM trust anchor is rejected at enrollment start
// with a clear error and leaves the Agent state unpaired and unchanged. The
// supplied path is read by the service account, so this is what keeps an
// enrollment request from becoming an arbitrary file-read primitive.
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
	for _, testCase := range cases {
		recorder := postEnrollmentStart(t, app, capability, app.ensureCSRFToken(),
			enrollmentStartBody(t, "https://panel.hooshix.test", "office PC", testCase.path))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d want=400", testCase.name, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, "ca_file") {
			t.Fatalf("%s: rejection was not reported as a CA file error:\n%s", testCase.name, body)
		}
		matched := false
		for _, want := range testCase.want {
			if strings.Contains(body, want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("%s: response does not explain the rejection (want one of %q):\n%s", testCase.name, testCase.want, body)
		}
		// Nothing may be stored: the rejected start leaves no pending session
		// and the device unpaired with its previous trust anchor untouched.
		if app.pendingEnrollmentSnapshot() != nil {
			t.Fatalf("%s: rejected start left a pending enrollment behind", testCase.name)
		}
		config, err := agent.LoadConfig(app.StateDir())
		if err != nil {
			t.Fatal(err)
		}
		if config.CAFile != "" || config.GatewayURL != "" || config.DeviceID != "" {
			t.Fatalf("%s: rejected enrollment mutated state: %+v", testCase.name, config)
		}
	}
}

// TestStateExposesUnpairedEnrollmentDefaults proves an unpaired agent's state
// document carries everything the enrollment form needs, and nothing that
// would leak a credential.
func TestStateExposesUnpairedEnrollmentDefaults(t *testing.T) {
	app, capability := newTestApp(t)
	recorder := getStateResponse(t, app, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	state := getState(t, app, capability)
	if state.Paired {
		t.Fatal("a fresh agent reported itself paired")
	}
	if state.Pending != nil {
		t.Fatalf("a fresh agent reported a pending enrollment: %+v", state.Pending)
	}
	if state.DefaultPanelURL != defaultEnrollmentPanelURL {
		t.Fatalf("default panel URL=%q want=%q", state.DefaultPanelURL, defaultEnrollmentPanelURL)
	}
	if strings.TrimSpace(state.Hostname) == "" {
		t.Fatal("state did not report a hostname for the device-name default")
	}
	if state.Config.Endpoints == nil {
		t.Fatal("endpoints must be an empty array, not null")
	}
	if len(state.Config.Endpoints) != 0 {
		t.Fatalf("a fresh agent reported endpoints: %+v", state.Config.Endpoints)
	}
	if state.CSRF == "" {
		t.Fatal("the state document did not carry the CSRF token")
	}
	if strings.Contains(recorder.Body.String(), "test_session_token") {
		t.Fatal("the state document leaked a session token")
	}
}

// TestStateExposesPendingEnrollment proves a live pending session reaches the
// SPA as the user code, verification URI and expiry — and that the poll token
// used to claim it never leaves the service process.
func TestStateExposesPendingEnrollment(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	store := agent.NewPlatformSecretStore(app.StateDir())
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		t.Fatal(err)
	}
	panel := newEnrollmentPanel(t)
	app.enrollmentClient = enrollment.NewClient(panel.Client())
	recorder := postEnrollmentStart(t, app, capability, csrf, enrollmentStartBody(t, panel.URL, "office PC", ""))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("enrollment start status=%d want=201: %s", recorder.Code, recorder.Body.String())
	}
	stateRecorder := getStateResponse(t, app, capability)
	if stateRecorder.Code != http.StatusOK {
		t.Fatalf("state status=%d want=200: %s", stateRecorder.Code, stateRecorder.Body.String())
	}
	if strings.Contains(stateRecorder.Body.String(), strings.Repeat("p", 43)) {
		t.Fatal("the state document leaked the enrollment poll token")
	}
	state := getState(t, app, capability)
	if state.Pending == nil {
		t.Fatal("the state document omitted the live pending enrollment")
	}
	if state.Pending.UserCode != "ABCD-EFGH" {
		t.Fatalf("pending user code=%q", state.Pending.UserCode)
	}
	if state.Pending.VerificationURI != "https://panel.hooshix.test/enroll" {
		t.Fatalf("pending verification URI=%q", state.Pending.VerificationURI)
	}
	if !state.Pending.ExpiresAt.After(time.Now()) {
		t.Fatalf("pending enrollment already expired at %s", state.Pending.ExpiresAt)
	}
}

// TestStateExposesPairedStatus proves a paired agent's state document reports
// the pairing and public key the SPA renders.
func TestStateExposesPairedStatus(t *testing.T) {
	app, capability, _, publicKey := pairedApp(t)
	state := getState(t, app, capability)
	if !state.Paired {
		t.Fatal("a paired agent reported itself unpaired")
	}
	if state.Config.DeviceID != "device-unpair-000001" {
		t.Fatalf("device id=%q", state.Config.DeviceID)
	}
	if state.Config.GatewayURL != "wss://gateway.example/agent/v1/connect" {
		t.Fatalf("gateway URL=%q", state.Config.GatewayURL)
	}
	if state.PublicKey != agent.PublicKeyBase64(publicKey) {
		t.Fatalf("public key=%q want=%q", state.PublicKey, agent.PublicKeyBase64(publicKey))
	}
	if state.Pending != nil {
		t.Fatalf("a paired agent reported a pending enrollment: %+v", state.Pending)
	}
}

// TestShippedUIBundleHasNoRemoteDesktopControl proves the Remote Desktop
// convenience shipped in the UI is a pure form prefill: the bundle names the
// RDP loopback target and the panel-side follow-up, and never grows an
// Agent-side control for Windows' own remote-connections setting (ADR-0017).
func TestShippedUIBundleHasNoRemoteDesktopControl(t *testing.T) {
	entries, err := fs.ReadDir(uiFiles, "assets")
	if err != nil {
		t.Fatalf("the embedded UI bundle has no assets: %v", err)
	}
	var bundle strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".js") {
			continue
		}
		data, err := fs.ReadFile(uiFiles, "assets/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		bundle.Write(data)
	}
	if bundle.Len() == 0 {
		t.Fatal("the embedded UI bundle contains no JavaScript")
	}
	for _, want := range []string{"rdp-001", "127.0.0.1:3389"} {
		if !strings.Contains(bundle.String(), want) {
			t.Fatalf("the shipped UI bundle is missing the Remote Desktop preset value %q", want)
		}
	}
	for _, forbidden := range []string{"fDenyTSConnections", "TSEnable", "Enable Remote Desktop", "Disable Remote Desktop"} {
		if strings.Contains(bundle.String(), forbidden) {
			t.Fatalf("the shipped UI bundle offers an Agent-side RDP control (%q)", forbidden)
		}
	}
}

// TestRemoteDesktopPresetValuesCommit proves the three values the Remote
// Desktop button prefills are the values /expose/add actually commits for a
// paired Agent, and that the same submit stays capability + CSRF gated. The
// button only fills form fields: an unauthenticated submit must persist
// nothing.
func TestRemoteDesktopPresetValuesCommit(t *testing.T) {
	app, capability, csrf, _ := pairedApp(t)
	const preset = "id=rdp-001&protocol=tcp&target=127.0.0.1%3A3389"

	request := newLoopbackRequest(http.MethodPost, "/expose/add?cap="+capability, strings.NewReader(preset))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("preset submit without CSRF status=%d want=403", recorder.Code)
	}
	config, err := agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range config.Endpoints {
		if endpoint.ID == "rdp-001" {
			t.Fatalf("CSRF-less preset submit persisted %q", endpoint.ID)
		}
	}

	request = newLoopbackRequest(http.MethodPost, "/expose/add?cap="+capability,
		strings.NewReader(preset+"&hooshix_csrf="+url.QueryEscape(csrf)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("preset submit status=%d want=303: %s", recorder.Code, recorder.Body.String())
	}
	config, err = agent.LoadConfig(app.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range config.Endpoints {
		if endpoint.ID != "rdp-001" {
			continue
		}
		if endpoint.Target != "127.0.0.1:3389" || endpoint.Protocol != "tcp" {
			t.Fatalf("preset committed %+v want 127.0.0.1:3389/tcp", endpoint)
		}
		return
	}
	t.Fatalf("preset did not commit rdp-001: %+v", config.Endpoints)
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
	state := getState(t, app, capability)
	if state.Paired {
		t.Fatalf("the state document still reports a pairing: %+v", state.Config)
	}
	if !strings.Contains(state.Notice, "unpaired") {
		t.Fatalf("the state document does not report the unpair: %q", state.Notice)
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
	// The state document shows the new key so the operator can register it.
	if state := getState(t, app, capability); state.PublicKey != agent.PublicKeyBase64(after) {
		t.Fatalf("the state document does not show the replacement public key: %q", state.PublicKey)
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

// uiAssetNames lists the public build artifacts the capability gate must let
// through: the two root files and every hashed file under assets/.
func uiAssetNames(t *testing.T) []string {
	t.Helper()
	names := []string{"boot.js", "favicon.svg"}
	entries, err := fs.ReadDir(uiFiles, "assets")
	if err != nil {
		t.Fatalf("the embedded UI bundle has no assets: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, "assets/"+entry.Name())
	}
	return names
}

// TestStateAcceptsQueryOrHeaderCapability pins both credential shapes the SPA
// and the tray use, and proves a wrong or missing capability is rejected.
func TestStateAcceptsQueryOrHeaderCapability(t *testing.T) {
	app, capability := newTestApp(t)
	if recorder := getStateResponse(t, app, capability); recorder.Code != http.StatusOK {
		t.Fatalf("query capability status=%d want=200", recorder.Code)
	}
	request := newLoopbackRequest(http.MethodGet, "/api/state", nil)
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("header capability status=%d want=200", recorder.Code)
	}
	for name, rejected := range map[string]*httptest.ResponseRecorder{
		"missing": getStateResponse(t, app, ""),
		"wrong":   getStateResponse(t, app, strings.Repeat("A", 43)),
	} {
		if rejected.Code != http.StatusUnauthorized {
			t.Fatalf("%s capability status=%d want=401", name, rejected.Code)
		}
	}
	wrongHeader := newLoopbackRequest(http.MethodGet, "/api/state", nil)
	wrongHeader.Header.Set("X-HooshiX-Pairing-Capability", strings.Repeat("B", 43))
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, wrongHeader)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong header capability status=%d want=401", recorder.Code)
	}
}

// TestStateDisclosesNoCredential proves the state document carries the
// rendering data and the CSRF token but never the session token, private key
// or pairing capability.
func TestStateDisclosesNoCredential(t *testing.T) {
	app, capability, _, publicKey := pairedApp(t)
	recorder := getStateResponse(t, app, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("state status=%d want=200", recorder.Code)
	}
	body := recorder.Body.String()
	for name, secret := range map[string]string{
		"session token":      "test_session_token_0123456789ABCDEF",
		"pairing capability": capability,
		"private key":        "private_key",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("the state document disclosed the %s", name)
		}
	}
	state := getState(t, app, capability)
	if state.PublicKey != agent.PublicKeyBase64(publicKey) {
		t.Fatal("the state document did not carry the public device key")
	}
	if state.CSRF == "" {
		t.Fatal("the state document did not carry the CSRF token")
	}
}

// TestPublicAssetsAreCapabilityExemptAndSecretFree proves the browser can load
// the SPA's static artifacts without the capability (and without putting it in
// asset URLs), and that no artifact embeds a state secret.
func TestPublicAssetsAreCapabilityExemptAndSecretFree(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	for _, name := range uiAssetNames(t) {
		request := newLoopbackRequest(http.MethodGet, "/"+name, nil)
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d want=200", name, recorder.Code)
		}
		if recorder.Body.Len() == 0 {
			t.Fatalf("%s served an empty body", name)
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType == "" {
			t.Fatalf("%s served no Content-Type", name)
		}
		body := recorder.Body.String()
		if strings.Contains(body, capability) || strings.Contains(body, csrf) {
			t.Fatalf("%s embeds a state secret", name)
		}
		cacheControl := recorder.Header().Get("Cache-Control")
		if strings.HasPrefix(name, "assets/") {
			if !strings.Contains(cacheControl, "immutable") {
				t.Fatalf("%s Cache-Control=%q want immutable", name, cacheControl)
			}
		} else if cacheControl != "no-cache" {
			t.Fatalf("%s Cache-Control=%q want no-cache", name, cacheControl)
		}
	}
}

// TestUIAssetResolutionRejectsNonPublicPaths pins the public-asset rule:
// only the two root files and flat hashed files under assets/ qualify, so a
// traversal or nested path can never bypass the capability check.
func TestUIAssetResolutionRejectsNonPublicPaths(t *testing.T) {
	for _, requestPath := range []string{
		"/assets/",
		"/assets/nested/app.js",
		"/assets/.hidden.js",
		"/assets/../index.html",
		"/assets/%2e%2e/index.html",
		"/index.html",
		"/boot.js/extra",
		"/favicon.svg/extra",
		"/api/state",
		"/?cap=ignored",
	} {
		if name, ok := uiPublicAssetName(requestPath); ok {
			t.Fatalf("%q resolved to public asset %q", requestPath, name)
		}
	}
	for _, requestPath := range []string{"/boot.js", "/favicon.svg", "/assets/index-abc123.js"} {
		if _, ok := uiPublicAssetName(requestPath); !ok {
			t.Fatalf("%q should be a public asset", requestPath)
		}
	}
}

// TestShellIsServedOnlyAtRoot proves /index.html and unknown paths do not
// expose the executable shell outside the root route, so HashRouter and the
// capability gate stay aligned.
func TestShellIsServedOnlyAtRoot(t *testing.T) {
	app, capability := newTestApp(t)
	for _, requestPath := range []string{"/index.html", "/dashboard", "/assets/nested/app.js", "/assets/"} {
		request := newLoopbackRequest(http.MethodGet, requestPath+"?cap="+url.QueryEscape(capability), nil)
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d want=404", requestPath, recorder.Code)
		}
	}
}

// TestSecurityHeadersAreAppliedToEveryResponse pins the headers that constrain
// the SPA: no inline or remote script, no framing, no referrer, no caching of
// state, and immutable caching only for hashed assets.
func TestSecurityHeadersAreAppliedToEveryResponse(t *testing.T) {
	app, capability := newTestApp(t)
	check := func(name string, recorder *httptest.ResponseRecorder, wantCache string) {
		t.Helper()
		header := recorder.Header()
		if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
			!strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s CSP=%q is not restrictive", name, csp)
		}
		for key, value := range map[string]string{
			"X-Content-Type-Options":     "nosniff",
			"X-Frame-Options":            "DENY",
			"Referrer-Policy":            "no-referrer",
			"Cross-Origin-Opener-Policy": "same-origin",
		} {
			if got := header.Get(key); got != value {
				t.Fatalf("%s %s=%q want %q", name, key, got, value)
			}
		}
		if !strings.Contains(header.Get("Permissions-Policy"), "camera=()") {
			t.Fatalf("%s served no Permissions-Policy", name)
		}
		if !strings.Contains(header.Get("Cache-Control"), wantCache) {
			t.Fatalf("%s Cache-Control=%q want %q", name, header.Get("Cache-Control"), wantCache)
		}
	}

	bootstrap := httptest.NewRecorder()
	app.Handler().ServeHTTP(bootstrap, newLoopbackRequest(http.MethodGet, "/", nil))
	check("bootstrap", bootstrap, "no-store")

	boot := httptest.NewRecorder()
	app.Handler().ServeHTTP(boot, newLoopbackRequest(http.MethodGet, "/boot.js", nil))
	check("boot.js", boot, "no-cache")

	hashed := ""
	for _, name := range uiAssetNames(t) {
		if strings.HasPrefix(name, "assets/") {
			hashed = name
			break
		}
	}
	if hashed == "" {
		t.Fatal("the UI bundle has no hashed assets")
	}
	asset := httptest.NewRecorder()
	app.Handler().ServeHTTP(asset, newLoopbackRequest(http.MethodGet, "/"+hashed, nil))
	check(hashed, asset, "immutable")

	shell := httptest.NewRecorder()
	app.Handler().ServeHTTP(shell, newLoopbackRequest(http.MethodGet, "/?cap="+url.QueryEscape(capability), nil))
	check("shell", shell, "no-store")

	state := getStateResponse(t, app, capability)
	check("/api/state", state, "no-store")
}

// TestRotateJSONReturnsFreshCapability proves the SPA's rotate action receives
// the new capability in the response (the page URL embeds it) and that the old
// value stops authenticating immediately.
func TestRotateJSONReturnsFreshCapability(t *testing.T) {
	app, capability := newTestApp(t)
	csrf := app.ensureCSRFToken()
	request := newLoopbackRequest(http.MethodPost, "/pairing/rotate", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", csrf)
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotate JSON status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Capability string `json:"capability"`
		Notice     string `json:"notice"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode rotate response: %v\n%s", err, recorder.Body.String())
	}
	if result.Capability == "" || result.Capability == capability {
		t.Fatalf("rotate did not return a fresh capability: %q", result.Capability)
	}
	if result.Capability != app.currentCapability() {
		t.Fatalf("rotate returned capability %q but the app holds %q", result.Capability, app.currentCapability())
	}
	if !strings.Contains(result.Notice, "rotated") {
		t.Fatalf("rotate notice=%q", result.Notice)
	}
	if stale := getStateResponse(t, app, capability); stale.Code != http.StatusUnauthorized {
		t.Fatalf("the rotated-away capability still authenticated (status=%d)", stale.Code)
	}
	if fresh := getStateResponse(t, app, result.Capability); fresh.Code != http.StatusOK {
		t.Fatalf("the fresh capability did not authenticate (status=%d)", fresh.Code)
	}
}

// postJSONForm submits a form-encoded mutation with the headers the SPA sends:
// CSRF and capability as headers, Accept: application/json.
func postJSONForm(t *testing.T, app *App, target, form, capability, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	request := newLoopbackRequest(http.MethodPost, target, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", csrf)
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	return recorder
}

// TestExposeJSONMutationsReportTheNewEndpointList proves the services page can
// add and remove mappings in one round trip: the response carries the complete
// endpoint list and the notice, while an unknown id is a client error.
func TestExposeJSONMutationsReportTheNewEndpointList(t *testing.T) {
	app, capability, csrf, _ := pairedApp(t)
	type endpointsResponse struct {
		Endpoints []agent.Endpoint `json:"endpoints"`
		Notice    string           `json:"notice"`
	}

	recorder := postJSONForm(t, app, "/expose/add", "id=web-002&protocol=tcp&target=127.0.0.1%3A4001", capability, csrf)
	if recorder.Code != http.StatusOK {
		t.Fatalf("add status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	var added endpointsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode add response: %v\n%s", err, recorder.Body.String())
	}
	if !strings.Contains(added.Notice, "web-002") {
		t.Fatalf("add notice=%q", added.Notice)
	}
	addedEndpoint := false
	for _, endpoint := range added.Endpoints {
		if endpoint.ID != "web-002" {
			continue
		}
		addedEndpoint = true
		if endpoint.Target != "127.0.0.1:4001" || endpoint.Protocol != "tcp" {
			t.Fatalf("added endpoint=%+v want 127.0.0.1:4001/tcp", endpoint)
		}
	}
	if !addedEndpoint {
		t.Fatalf("add response omitted web-002: %+v", added.Endpoints)
	}

	recorder = postJSONForm(t, app, "/expose/remove", "id=absent", capability, csrf)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown remove status=%d want=400: %s", recorder.Code, recorder.Body.String())
	}
	var removalError struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &removalError); err != nil || !strings.Contains(removalError.Error, "absent") {
		t.Fatalf("unknown remove error=%q decode=%v", removalError.Error, err)
	}

	recorder = postJSONForm(t, app, "/expose/remove", "id=web-002", capability, csrf)
	if recorder.Code != http.StatusOK {
		t.Fatalf("remove status=%d want=200: %s", recorder.Code, recorder.Body.String())
	}
	var removed endpointsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &removed); err != nil {
		t.Fatalf("decode remove response: %v\n%s", err, recorder.Body.String())
	}
	if !strings.Contains(removed.Notice, "removed") {
		t.Fatalf("remove notice=%q", removed.Notice)
	}
	for _, endpoint := range removed.Endpoints {
		if endpoint.ID == "web-002" {
			t.Fatalf("removed endpoint still present: %+v", removed.Endpoints)
		}
	}

	// The state document and the tooling listing reflect the same mapping.
	state := getState(t, app, capability)
	for _, endpoint := range state.Config.Endpoints {
		if endpoint.ID == "web-002" {
			t.Fatal("the state document still reports the removed endpoint")
		}
	}
	if unauthorized := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, newLoopbackRequest(http.MethodGet, "/expose", nil))
		return recorder
	}(); unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("/expose without capability status=%d want=401", unauthorized.Code)
	}
	listing := httptest.NewRecorder()
	app.Handler().ServeHTTP(listing, newLoopbackRequest(http.MethodGet, "/expose?cap="+url.QueryEscape(capability), nil))
	if listing.Code != http.StatusOK {
		t.Fatalf("/expose status=%d want=200", listing.Code)
	}
	var endpoints []agent.Endpoint
	if err := json.Unmarshal(listing.Body.Bytes(), &endpoints); err != nil {
		t.Fatalf("decode /expose: %v\n%s", err, listing.Body.String())
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == "web-002" {
			t.Fatal("/expose still lists the removed endpoint")
		}
	}
}
