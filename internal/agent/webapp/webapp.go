// Package webapp implements the local, loopback-only Agent pairing UI.
//
// The UI is intentionally minimal: a single page served on 127.0.0.1 that
// shows the device public key for panel registration and accepts a pasted
// pairing JSON (device_id, authorization_id, token_id, token, gateway_url,
// optional aliases) that is applied atomically to the Agent state.
package webapp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// PairingPayload is the single-paste format produced by the panel.
type PairingPayload struct {
	GatewayURL      string `json:"gateway_url"`
	GatewayAliases  string `json:"gateway_aliases,omitempty"`
	DeviceID        string `json:"device_id"`
	AuthorizationID string `json:"authorization_id"`
	TokenID         string `json:"token_id"`
	Token           string `json:"token"`
}

// App wires the HTTP handlers to Agent state.
type App struct {
	stateDir string
	logger   *slog.Logger

	mu         sync.Mutex
	notice     string
	noticeAt   time.Time
	csrfToken  string
	capability string
}

// NewApp creates the pairing app for a state directory.
func NewApp(stateDir string, logger *slog.Logger) (*App, error) {
	normalized, err := agent.NormalizeStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	capability, err := agent.LoadPairingCapability(normalized)
	if err != nil {
		return nil, fmt.Errorf("load pairing capability: %w", err)
	}
	return &App{stateDir: normalized, logger: logger, capability: capability}, nil
}

// StateDir exposes the normalized state directory.
func (app *App) StateDir() string { return app.stateDir }

// Handler builds the http.Handler with all routes.
func (app *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/pair", app.handlePair)
	mux.HandleFunc("/expose", app.handleExpose)
	mux.HandleFunc("/expose/add", app.handleExposeAdd)
	mux.HandleFunc("/expose/remove", app.handleExposeRemove)
	return app.requireCapability(app.sameOrigin(mux))
}

func (app *App) requireCapability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.URL.Query().Get("cap")
		if provided == "" {
			provided = r.Header.Get("X-HooshiX-Pairing-Capability")
		}
		if !agent.PairingCapabilityMatches(app.capability, provided) {
			http.Error(w, "pairing authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireLocalRequest rejects requests that did not originate from a local
// browser navigation on the loopback UI. Browsers send Origin/Referer on
// cross-site form posts; a same-origin (or same-site loopback) request is
// identifiable by host match. Anything else — including absent headers on
// state-changing verbs — is rejected to prevent DNS rebinding and
// cross-site request forgery against the LocalSystem service.
func (app *App) requireLocalRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	host := r.Host
	for _, header := range []string{"Origin", "Referer"} {
		value := r.Header.Get(header)
		if value == "" {
			continue
		}
		if sameLoopbackOrigin(value, host) {
			return true
		}
		// Any explicitly present, non-loopback Origin/Referer on a mutating
		// request is a cross-site attempt: reject without falling through.
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return false
	}
	// No Origin and no Referer at all: this can be a curl-style local tool or
	// an old browser. Require the explicit local capability header so only
	// deliberate local clients can mutate state.
	if r.Header.Get("X-HooshiX-Local") != "1" {
		http.Error(w, "missing local request capability header", http.StatusForbidden)
		return false
	}
	return true
}

// sameLoopbackOrigin reports whether the Origin/Referer value points at the
// same loopback host as the request host (scheme and path are ignored).
func sameLoopbackOrigin(originOrReferer, requestHost string) bool {
	value := strings.TrimSpace(originOrReferer)
	if value == "" {
		return false
	}
	if idx := strings.Index(value, "://"); idx >= 0 {
		value = value[idx+3:]
	}
	if idx := strings.IndexAny(value, "/?#"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.LastIndex(value, "@"); idx >= 0 {
		value = value[idx+1:]
	}
	if value != requestHost {
		return false
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		host = requestHost
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// sameOrigin protects mutating endpoints against browser cross-site posts.
func (app *App) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !app.requireLocalRequest(w, r) {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// PublicKey returns the current (creating if needed) device public key.
func (app *App) PublicKey() (string, error) {
	store := agent.NewPlatformSecretStore(app.stateDir)
	publicKey, _, err := agent.LoadOrCreateIdentity(store)
	if err != nil {
		return "", err
	}
	return agent.PublicKeyBase64(publicKey), nil
}

func (app *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	publicKey, keyErr := app.PublicKey()
	config, configErr := agent.LoadConfig(app.stateDir)
	paired := configErr == nil && config.ValidateRuntime() == nil
	notice := ""
	csrf := app.ensureCSRFToken()
	app.mu.Lock()
	if time.Since(app.noticeAt) < 10*time.Minute {
		notice = app.notice
	}
	app.mu.Unlock()
	// The notice text may echo attacker-controlled payload fragments from
	// validation failures, so it is HTML-escaped at the single render site.
	fmt.Fprintf(w, pageTemplate,
		htmlEscape(publicKey),
		keyErrText(keyErr),
		pairedText(paired, config.GatewayURL, config.DeviceID),
		htmlEscape(url.QueryEscape(app.capability)),
		htmlEscape(csrf),
		htmlEscape(notice),
		htmlEscape(url.QueryEscape(app.capability)),
		htmlEscape(csrf),
		exposeRowsHTML(config.Endpoints, csrf, app.capability),
		exposeOptionsHTML(config.Endpoints),
		tunnelHealthHTML(loadTunnelHealth(app.stateDir)),
	)
}

// TunnelHealth mirrors the service-written status.json snapshot.
type TunnelHealth struct {
	Phase        string `json:"phase"`
	State        string `json:"state"`
	Reconnects   int64  `json:"reconnects"`
	LastError    string `json:"last_error,omitempty"`
	LastUpdateAt string `json:"last_update_at"`
}

// loadTunnelHealth reads the supervisor-written status.json from the state
// directory. A missing or unreadable file is not an error for rendering: the
// UI shows a neutral "status unavailable" row instead (the service may be
// stopped or the status writer has not run yet).
func loadTunnelHealth(stateDir string) TunnelHealth {
	health := TunnelHealth{Phase: "unknown", State: "status-unavailable"}
	data, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
	if err != nil {
		return health
	}
	if jsonErr := json.Unmarshal(data, &health); jsonErr != nil {
		return TunnelHealth{Phase: "unknown", State: "status-unavailable"}
	}
	return health
}

// tunnelHealthHTML renders the tunnel health block for the pairing page.
// Every interpolated value is HTML-escaped: status fields can embed
// error strings derived from remote input.
func tunnelHealthHTML(health TunnelHealth) string {
	var builder strings.Builder
	builder.WriteString("<h2>Tunnel status</h2>\n<table>")
	builder.WriteString("<tr><th>connection</th><th>reconnects</th><th>last error</th></tr>")
	connection := htmlEscape(displayConnection(health))
	lastError := strings.TrimSpace(health.LastError)
	if lastError == "" {
		lastError = "—"
	}
	fmt.Fprintf(&builder, "<tr><td>%s</td><td>%d</td><td>%s</td></tr></table>\n",
		connection, health.Reconnects, htmlEscape(lastError))
	return builder.String()
}

// displayConnection converts the raw phase/state pair into a short,
// user-friendly connection description.
func displayConnection(health TunnelHealth) string {
	switch {
	case health.Phase == "unknown":
		return "status unavailable"
	case health.Phase == "running" && health.State == "connected":
		return "connected"
	case health.Phase == "running":
		return health.State
	case health.Phase == "reconnecting":
		return "reconnecting"
	case health.Phase == "pending_config":
		return "waiting for pairing"
	case health.Phase == "terminal":
		return "stopped (error)"
	case health.Phase == "stopped":
		return "stopped"
	default:
		return health.Phase + ": " + health.State
	}
}

func keyErrText(err error) string {
	if err != nil {
		return "<p class=\"error\">public key unavailable: " + htmlEscape(err.Error()) + "</p>"
	}
	return ""
}

func pairedText(paired bool, gateway, device string) string {
	if paired {
		return "<p class=\"ok\">Paired with " + htmlEscape(device) + " via " + htmlEscape(gateway) + ". This page can be closed.</p>"
	}
	return "<p class=\"info\">Paste the pairing text from the panel below.</p>"
}

func exposeRowsHTML(endpoints []agent.Endpoint, csrfToken, capability string) string {
	if len(endpoints) == 0 {
		return "<tr><td colspan=\"3\">no local services exposed yet</td></tr>"
	}
	rows := ""
	for _, endpoint := range endpoints {
		rows += "<tr><td><code>" + htmlEscape(endpoint.ID) + "</code></td><td>" + htmlEscape(endpoint.Target) +
			"</td><td><form method=\"post\" action=\"/expose/remove?cap=" + htmlEscape(url.QueryEscape(capability)) +
			"\"><input type=\"hidden\" name=\"id\" value=\"" + htmlEscape(endpoint.ID) +
			"\"><input type=\"hidden\" name=\"hooshix_csrf\" value=\"" + htmlEscape(csrfToken) + "\"><button>Remove</button></form></td></tr>"
	}
	return rows
}

func exposeOptionsHTML(endpoints []agent.Endpoint) string {
	options := ""
	for _, endpoint := range endpoints {
		options += "<option value=\"" + htmlEscape(endpoint.ID) + "\">"
	}
	return options
}

// ensureCSRFToken returns the per-process pairing-UI CSRF token, creating
// it once from OS entropy. Every mutating form carries it; every mutating
// handler requires it. An attacker site cannot read it (same-origin policy)
// and cannot guess it (256 bits of OS entropy), so cross-site posts fail
// even if a future Origin/Referer check regresses.
func (app *App) ensureCSRFToken() string {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.csrfToken == "" {
		entropy := make([]byte, 32)
		if _, err := rand.Read(entropy); err != nil {
			// Entropy failure must fail closed: return a token that no form
			// can satisfy rather than reusing an empty/predictable value.
			return ""
		}
		app.csrfToken = base64.RawURLEncoding.EncodeToString(entropy)
	}
	return app.csrfToken
}

// validCSRFToken reports whether the request carries the current token.
// An empty server token (entropy failure) rejects everything: fail closed.
func (app *App) validCSRFToken(value string) bool {
	app.mu.Lock()
	token := app.csrfToken
	app.mu.Unlock()
	if token == "" || value == "" || len(value) > 128 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(value)) == 1
}

// requireCSRF validates the hooshix_csrf form field on browser-form posts.
// It is called after the same-origin check inside every mutating handler.
func (app *App) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	provided := r.Header.Get("X-HooshiX-CSRF")
	if provided == "" {
		provided = r.PostFormValue("hooshix_csrf")
	}
	if app.validCSRFToken(provided) {
		return true
	}
	http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
	return false
}

// handlePair applies the pasted pairing payload.
func (app *App) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(16 * 1024); err != nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse form failed", http.StatusBadRequest)
			return
		}
	}
	if !app.requireCSRF(w, r) {
		return
	}
	contentType := r.Header.Get("Content-Type")
	var raw []byte
	if strings.HasPrefix(contentType, "application/json") {
		body := io.LimitReader(r.Body, 16*1024)
		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		raw = data
	} else {
		// HTML form submit: pairing text arrives as the "pairing" field.
		raw = []byte(r.PostFormValue("pairing"))
	}
	var payload PairingPayload
	text := htmlUnescape(strings.TrimSpace(string(raw)))
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		// Also accept the panel's fenced-block copy format.
		fenced := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "```"), "```"))
		if jsonErr := json.Unmarshal([]byte(htmlUnescape(fenced)), &payload); jsonErr != nil {
			app.setNotice("invalid pairing text")
			app.redirectHome(w, r)
			return
		}
	}
	if err := app.ApplyPairing(payload); err != nil {
		app.setNotice("pairing failed: " + err.Error())
		app.logger.Warn("pairing failed")
	} else {
		app.setNotice("paired successfully; the agent service will connect automatically")
		app.logger.Info("agent paired", "device", payload.DeviceID, "gateway", payload.GatewayURL)
	}
	app.redirectHome(w, r)
}

// ApplyPairing validates the complete normalized configuration and then
// persists config and secret atomically through the Agent state transaction.
// The previous working state is preserved on any validation or I/O failure.
func (app *App) ApplyPairing(payload PairingPayload) error {
	payload.Token = strings.TrimSpace(payload.Token)
	if !agent.SessionTokenPattern.MatchString(payload.Token) {
		return fmt.Errorf("session token must be 32..512 base64url-safe characters")
	}
	if err := agent.ValidateGatewayURL(payload.GatewayURL); err != nil {
		return err
	}
	config := agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      payload.GatewayURL,
		DeviceID:        payload.DeviceID,
		AuthorizationID: payload.AuthorizationID,
		TokenID:         payload.TokenID,
		UpdateChannel:   "stable",
	}
	if raw := strings.TrimSpace(payload.GatewayAliases); raw != "" {
		aliases := strings.Split(raw, ",")
		for i := range aliases {
			aliases[i] = strings.TrimSpace(aliases[i])
		}
		config.GatewayAliases = aliases
	}
	if err := config.ValidateRuntime(); err != nil {
		return err
	}
	store := agent.NewPlatformSecretStore(app.stateDir)
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		return err
	}
	if _, err := agent.ConfigureAgentStateForUI(app.stateDir, store, config, payload.Token); err != nil {
		return err
	}
	return nil
}

func (app *App) setNotice(message string) {
	app.mu.Lock()
	app.notice = message
	app.noticeAt = time.Now()
	app.mu.Unlock()
}

// handleExposeAdd persists a new local service mapping from the UI form.
func (app *App) handleExposeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form failed", http.StatusBadRequest)
		return
	}
	if !app.requireCSRF(w, r) {
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	target := strings.TrimSpace(r.PostFormValue("target"))
	if err := agent.MutateConfig(app.stateDir, func(config *agent.Config) error {
		config.SetEndpoint(agent.Endpoint{ID: id, Target: target})
		return config.ValidateRuntime()
	}); err != nil {
		app.setNotice("expose failed: " + err.Error())
		app.logger.Warn("expose add failed", "error", err)
	} else {
		app.setNotice("exposed " + id + " -> " + target + " (restart the service from the tray to apply)")
		app.logger.Info("local service exposed via ui", "id", id, "target", target)
	}
	app.redirectHome(w, r)
}

// handleExposeRemove drops a local service mapping from the UI form.
func (app *App) handleExposeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form failed", http.StatusBadRequest)
		return
	}
	if !app.requireCSRF(w, r) {
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	if err := agent.MutateConfig(app.stateDir, func(config *agent.Config) error {
		if !config.RemoveEndpoint(id) {
			return fmt.Errorf("unknown local endpoint %q", id)
		}
		return config.ValidateRuntime()
	}); err != nil {
		app.setNotice("remove failed: " + err.Error())
	} else {
		app.setNotice("removed " + id + " (restart the service from the tray to apply)")
	}
	app.redirectHome(w, r)
}

func (app *App) redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/?cap="+app.capability, http.StatusSeeOther)
}

// handleExpose returns the current local endpoints as JSON (for tooling).
func (app *App) handleExpose(w http.ResponseWriter, r *http.Request) {
	config, err := agent.LoadConfig(app.stateDir)
	if err != nil {
		http.Error(w, "load config failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config.Endpoints)
}

// Serve runs the loopback listener until ctx is done.
func (app *App) Serve(ctx context.Context, listenAddr string, logger *slog.Logger) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	host, _, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr == nil && host != "127.0.0.1" && host != "::1" && host != "localhost" {
		listener.Close()
		return fmt.Errorf("refusing to serve pairing UI on non-loopback %s", host)
	}
	server := &http.Server{
		Handler:           app.Handler(),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("pairing ui listening", "addr", listener.Addr().String())
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(value)
}

// htmlUnescape reverses the common HTML entities the panel uses (esc), so
// copy-pasted pairing blocks that went through HTML rendering still parse.
func htmlUnescape(value string) string {
	replacer := strings.NewReplacer("&quot;", `"`, "&#34;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#39;", "'")
	return replacer.Replace(value)
}

var pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>HooshiX Agent</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  .key { background: #f4f4f8; border: 1px solid #ccc; padding: .8rem; font-family: monospace; word-break: break-all; user-select: all; }
  textarea { width: 100%%; height: 8rem; font-family: monospace; }
  .ok { color: #0a7a2e; } .error { color: #b00020; } .info { color: #555; }
  button { padding: .5rem 1.2rem; }
  h1 { font-size: 1.3rem; } h2 { margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%%; }
  th, td { border: 1px solid #ddd; padding: .4rem .6rem; font-size: .9rem; }
  input { font: inherit; padding: .35rem .5rem; width: 200px; }
  #target { width: 260px; }
</style>
</head>
<body>
<h1>HooshiX Agent Setup</h1>
<h2>1. Register this device</h2>
<p>Copy this public key into your panel (Devices → Register a device):</p>
<div class="key">%s</div>
%s
<h2>2. Paste your pairing text</h2>
%s
<form method="post" action="/pair?cap=%s">
<input type="hidden" name="hooshix_csrf" value="%s">
<textarea name="pairing" placeholder='{"gateway_url":"wss://...","device_id":"device-...","authorization_id":"auth-...","token_id":"token-...","token":"..."}'></textarea>
<br><button type="submit">Pair</button>
</form>
<p class="info">%s</p>
<h2>3. Local services</h2>
<p class="info">Map a local port, then reserve a subdomain in the panel with the same endpoint id.</p>
<form method="post" action="/expose/add?cap=%s">
<input type="hidden" name="hooshix_csrf" value="%s">
<input name="id" placeholder="web-001" required pattern="[A-Za-z0-9][A-Za-z0-9._:-]{0,63}" title="endpoint id: letters, digits, . _ : -">
<input id="target" name="target" placeholder="127.0.0.1:4000" required>
<button type="submit">Add service</button>
</form>
<table><tr><th>endpoint id</th><th>local target</th><th></th></tr>
%s
</table>
<datalist id="expose-ids">%s</datalist>
%s
</body>
</html>
`

// Compile-time check: template stays parseable with the fmt verbs used.
var _ = func() error {
	_, err := template.New("page").Parse(strings.ReplaceAll(pageTemplate, "%%", "%"))
	return err
}()
