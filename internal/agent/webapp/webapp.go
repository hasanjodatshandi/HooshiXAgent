// Package webapp implements the local, loopback-only Agent pairing UI.
//
// The UI is intentionally minimal: a single page served on 127.0.0.1 that
// shows the device public key for panel registration and accepts a pasted
// pairing JSON (device_id, authorization_id, token_id, token, gateway_url,
// optional aliases, optional ca_file) plus an optional CA file path typed into
// the form, all applied atomically to the Agent state.
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// PairingPayload is the single-paste format produced by the panel.
//
// CAFile is optional and names a PEM trust anchor for self-hosted/test
// deployments (the same value `--ca-file` sets). When it is absent the
// configured trust anchor is preserved rather than cleared, so a re-pairing
// can never silently drop an operator-configured CA.
type PairingPayload struct {
	GatewayURL      string `json:"gateway_url"`
	GatewayAliases  string `json:"gateway_aliases,omitempty"`
	CAFile          string `json:"ca_file,omitempty"`
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
	// endpointToken is the per-bind listener identity published in
	// pairing.endpoint.json; a client that already holds it can prove the
	// loopback port belongs to this process before handing over the capability.
	endpointToken string
}

// currentCapability returns the live pairing capability. The value changes
// when the capability is rotated after a successful pairing, so every read
// must take the lock instead of caching the initial value.
func (app *App) currentCapability() string {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.capability
}

// currentEndpointToken returns the current listener identity token.
func (app *App) currentEndpointToken() string {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.endpointToken
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

// Handler builds the http.Handler with all routes. The local/origin guard is
// outermost so a cross-site request is rejected before any credential is even
// compared or any route handler runs.
func (app *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/pair", app.handlePair)
	mux.HandleFunc("/pairing/rotate", app.handleRotateCapability)
	mux.HandleFunc("/pairing/identity", app.handlePairingIdentity)
	mux.HandleFunc("/unpair", app.handleUnpair)
	mux.HandleFunc("/expose", app.handleExpose)
	mux.HandleFunc("/expose/add", app.handleExposeAdd)
	mux.HandleFunc("/expose/remove", app.handleExposeRemove)
	return app.requireLocalRequest(app.requireCapability(mux))
}

// requireCapability enforces the installer-written pairing capability on EVERY
// route. The capability is the only credential this UI has, so no response may
// disclose it (or the per-process CSRF token) to a request that does not
// already hold it: an unauthenticated GET / is answered with the bootstrap
// page, which contains no secret material and only asks the operator to paste
// the capability the tray/installer already handed them.
func (app *App) requireCapability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The listener-identity probe is answered without the capability: it
		// exists precisely so a caller can decide whether it is safe to hand
		// the capability to this address. It discloses only the token the
		// caller already read from the ACL-protected state directory.
		if r.URL.Path == "/pairing/identity" {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.URL.Query().Get("cap")
		if provided == "" {
			provided = r.Header.Get("X-HooshiX-Pairing-Capability")
		}
		if agent.PairingCapabilityMatches(app.currentCapability(), provided) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			app.serveBootstrap(w)
			return
		}
		http.Error(w, "pairing authorization required", http.StatusUnauthorized)
	})
}

// handlePairingIdentity answers with the bind-time listener token. A client
// that read the same token from pairing.endpoint.json (readable only by
// SYSTEM, Administrators and the interactive desktop user) therefore knows the
// loopback port is served by this process and not by a port squatter.
func (app *App) handlePairingIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	token := app.currentEndpointToken()
	if token == "" {
		http.Error(w, "pairing listener identity unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// serveBootstrap renders the capability-free landing page. It intentionally
// interpolates nothing: there is no public key, no capability, and no CSRF
// token in this response.
func (app *App) serveBootstrap(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, bootstrapTemplate)
}

// requireLocalRequest rejects requests that did not originate from a local
// browser navigation on the loopback UI. Since the server only listens on
// 127.0.0.1, any accepted TCP connection is necessarily local; the remote
// address is still checked as defence in depth.
//
// Origin/Referer are validated BEFORE any host-equality shortcut and
// regardless of the Host header: a name that resolves to loopback (the
// DNS-rebinding case) still produces an Origin/Referer naming the attacker's
// host, and the Host header is attacker-controlled in that scenario, so
// comparing the two proves nothing. Only an Origin/Referer whose host is
// exactly 127.0.0.1, ::1 or localhost is accepted.
func (app *App) requireLocalRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}
		if !isLoopbackHost(remoteHost) {
			http.Error(w, "request must originate from local machine", http.StatusForbidden)
			return
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if origin == "null" {
				// Chromium can deliberately serialize the origin as "null" for a
				// user-initiated local form navigation when Referrer-Policy is
				// no-referrer. Accept only the browser-provided Fetch Metadata
				// shape for a same-origin top-level POST to an exact loopback Host.
				// Capability and CSRF validation still run in the inner handler.
				if !isSameOriginLoopbackNavigation(r) {
					app.logger.Warn("cross-origin local UI request rejected",
						"method", r.Method,
						"path", r.URL.Path,
						"origin_null", true,
						"host_loopback", isLoopbackRequestHost(r.Host),
						"fetch_site", r.Header.Get("Sec-Fetch-Site"),
						"fetch_mode", r.Header.Get("Sec-Fetch-Mode"),
						"fetch_dest", r.Header.Get("Sec-Fetch-Dest"),
					)
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			} else if !isLoopbackOrigin(origin) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		} else if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" && !isLoopbackOrigin(referer) {
			// Origin is authoritative for browser mutations. Referer is only a
			// fallback when Origin is absent; requiring both lets privacy tools or
			// extensions rewrite Referer and break an otherwise same-origin form.
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isSameOriginLoopbackNavigation is the narrowly-scoped fallback for browsers
// that emit Origin: null for a top-level form POST from the loopback UI. A
// foreign site, iframe, fetch/XHR, scripted navigation or rebinding Host does
// not satisfy this shape.
func isSameOriginLoopbackNavigation(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		isLoopbackRequestHost(r.Host) &&
		r.Header.Get("Sec-Fetch-Site") == "same-origin" &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		r.Header.Get("Sec-Fetch-Dest") == "document" &&
		r.Header.Get("Sec-Fetch-User") == "?1"
}

func isLoopbackRequestHost(hostPort string) bool {
	host := hostPort
	if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
		host = parsedHost
	}
	return isLoopbackHost(host)
}

// isLoopbackHost reports whether host (a bare host name, without port) is one
// of the exact ASCII loopback spellings. Case-insensitive matching is
// deliberately NOT used: "localhoſt" (U+017F) and other confusables must never
// be treated as loopback.
func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "[::1]", "localhost":
		return true
	default:
		return false
	}
}

// isLoopbackOrigin reports whether an Origin/Referer header value names a
// loopback http/https origin. Unparseable values, "null", userinfo tricks
// (https://127.0.0.1@attacker.example) and every non-loopback host are
// rejected.
func isLoopbackOrigin(originOrReferer string) bool {
	value := strings.TrimSpace(originOrReferer)
	if value == "" || value == "null" {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if parsed.Scheme == "" {
		// A bare authority ("127.0.0.1:8799") parses as a path; retry as one.
		parsed, err = url.Parse("//" + value)
		if err != nil {
			return false
		}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return isLoopbackHost(parsed.Hostname())
}

// PublicKey returns the current device public key WITHOUT creating it. State
// creation is an explicit action (service startup, pairing, or the CLI), never
// a side effect of rendering a page.
func (app *App) PublicKey() (string, error) {
	store := agent.NewPlatformSecretStore(app.stateDir)
	publicKey, _, err := agent.LoadIdentity(store)
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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	capability := app.currentCapability()
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page URL and every form action carry the capability, so it must
	// never land in a browser or intermediary cache.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The notice text may echo attacker-controlled payload fragments from
	// validation failures, so it is HTML-escaped at the single render site.
	fmt.Fprintf(w, pageTemplate,
		htmlEscape(publicKey),
		keyErrText(keyErr),
		pairedText(paired, config.GatewayURL, config.DeviceID, config.CAFile),
		htmlEscape(url.QueryEscape(capability)),
		htmlEscape(csrf),
		htmlEscape(config.CAFile),
		htmlEscape(notice),
		htmlEscape(url.QueryEscape(capability)),
		htmlEscape(csrf),
		exposeRowsHTML(config.Endpoints, csrf, capability),
		exposeOptionsHTML(config.Endpoints),
		htmlEscape(url.QueryEscape(capability)),
		htmlEscape(csrf),
		tunnelHealthHTML(loadTunnelHealth(app.stateDir)),
		unpairSectionHTML(capability, csrf),
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

func pairedText(paired bool, gateway, device, caFile string) string {
	if paired {
		trust := "system trust store"
		if caFile != "" {
			trust = "configured CA file " + htmlEscape(caFile)
		}
		return "<p class=\"ok\">Paired with " + htmlEscape(device) + " via " + htmlEscape(gateway) + ". Trust anchor: " + trust + ". This page can be closed.</p>"
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

// unpairSectionHTML renders the clear-pairing form: the same operation the
// `unpair` CLI command performs, behind the same capability and CSRF gates as
// every other mutating form on the page.
func unpairSectionHTML(capability, csrfToken string) string {
	return "<h2>5. Unpair this device</h2>\n" +
		"<p class=\"info\">Clears the pairing record (gateway, device/authorization/token IDs, trust anchor) and the session token, and returns the agent to <em>waiting for pairing</em>. " +
		"The device identity above and the local service mappings are kept, so this device can be re-paired as itself without re-registering the key.</p>\n" +
		"<form method=\"post\" action=\"/unpair?cap=" + htmlEscape(url.QueryEscape(capability)) + "\">\n" +
		"<input type=\"hidden\" name=\"hooshix_csrf\" value=\"" + htmlEscape(csrfToken) + "\">\n" +
		"<label for=\"reset-identity\" style=\"width:auto\">" +
		"<input type=\"checkbox\" id=\"reset-identity\" name=\"reset_identity\" value=\"true\" style=\"width:auto\"> " +
		"Also replace the device identity (mints a NEW public key that must be registered in the panel before re-pairing)</label>\n" +
		"<br><button type=\"submit\">Unpair</button>\n" +
		"</form>\n"
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
	// The CA file is the only pairing field the operator types directly rather
	// than pasting inside the JSON block, so the form field overrides the
	// payload value when it is present. Both live behind the same capability
	// and CSRF gates as every other field.
	if typed := strings.TrimSpace(r.PostFormValue("ca_file")); typed != "" {
		payload.CAFile = typed
	}
	if err := app.ApplyPairing(payload); err != nil {
		app.setNotice("pairing failed: " + err.Error())
		app.logger.Warn("pairing failed")
	} else {
		// The capability has now been used for its one purpose. Rotating it
		// invalidates every copy of the old value (browser history, tray
		// command line, screenshots) while the freshly paired device keeps
		// working, since the session credential — not the capability — is what
		// the tunnel authenticates with.
		if err := app.rotateCapability(); err != nil {
			app.logger.Warn("rotate pairing capability failed", "error", err)
		}
		app.setNotice("paired successfully; the agent service will connect automatically")
		app.logger.Info("agent paired", "device", payload.DeviceID, "gateway", payload.GatewayURL, "ca_file", payload.CAFile)
	}
	app.redirectHome(w, r)
}

// rotateCapability replaces the on-disk and in-memory pairing capability with
// a fresh 256-bit value.
func (app *App) rotateCapability() error {
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		return err
	}
	if err := agent.WritePairingCapability(app.stateDir, capability); err != nil {
		return err
	}
	app.mu.Lock()
	app.capability = capability
	app.mu.Unlock()
	return nil
}

// handleRotateCapability rotates the pairing capability on explicit operator
// request from the authenticated root page.
func (app *App) handleRotateCapability(w http.ResponseWriter, r *http.Request) {
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
	if err := app.rotateCapability(); err != nil {
		app.logger.Warn("rotate pairing capability failed", "error", err)
		app.setNotice("rotate failed: " + err.Error())
	} else {
		app.setNotice("pairing authorization rotated; old links no longer work")
	}
	app.redirectHome(w, r)
}

// handleUnpair clears the pairing and returns the Agent to the unpaired
// (pending_config) state. It is the same authenticated action the CLI uses
// when the service owns the state, so an operator has one operation either
// way.
//
// The device identity is preserved unless the request explicitly asks for a
// replacement: re-pairing the same device must not silently mint a second
// identity the panel has not authorized. A replacement identity is created
// HERE, in the process that owns the DPAPI current-user secret store
// (the Agent service on Windows), because a key minted by any other account
// could not be read back by the service.
func (app *App) handleUnpair(w http.ResponseWriter, r *http.Request) {
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
	resetIdentity := strings.TrimSpace(r.PostFormValue("reset_identity")) == "true" ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-HooshiX-Reset-Identity")), "true")
	store := agent.NewPlatformSecretStore(app.stateDir)
	result, err := agent.UnpairAgentStateForUI(app.stateDir, store, resetIdentity)
	if err != nil {
		// The error text may carry state-directory detail; it is never
		// rendered unescaped (the notice is escaped at its render site).
		app.setNotice("unpair failed: " + err.Error())
		app.logger.Warn("unpair failed")
		if wantsJSON(r) {
			writeJSONMessage(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		app.redirectHome(w, r)
		return
	}
	switch {
	case result.AlreadyUnpaired:
		app.setNotice("already unpaired: there was no pairing record or session token to clear")
	case result.IdentityPreserved:
		app.setNotice("unpaired: the pairing record and session token were cleared. Device identity preserved; re-pair from the panel to reconnect.")
	default:
		app.setNotice("unpaired: the pairing record, session token and device identity were cleared. Register the new public key in the panel before re-pairing.")
	}
	app.logger.Info("agent unpaired", "device", result.DeviceID, "identity_preserved", result.IdentityPreserved, "already_unpaired", result.AlreadyUnpaired)
	if wantsJSON(r) {
		writeJSONMessage(w, http.StatusOK, result)
		return
	}
	app.redirectHome(w, r)
}

// wantsJSON reports whether the caller asked for a machine-readable answer.
// It only chooses the response shape: both shapes are behind the capability
// and CSRF gates.
func wantsJSON(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

func writeJSONMessage(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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
	// Validate before any state is written: this path is read by the service
	// account, so an unvalidated value must never reach config.json.
	payload.CAFile = strings.TrimSpace(payload.CAFile)
	if payload.CAFile != "" {
		if err := agent.ValidateCAFile(payload.CAFile); err != nil {
			return fmt.Errorf("ca_file %q: %w", payload.CAFile, err)
		}
	}
	config := agent.Config{
		Version:         agent.ConfigVersion,
		GatewayURL:      payload.GatewayURL,
		CAFile:          payload.CAFile,
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
	http.Redirect(w, r, "/?cap="+url.QueryEscape(app.currentCapability()), http.StatusSeeOther)
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

// Listen binds the loopback listener and publishes the pairing endpoint
// record that lets the tray verify the port before disclosing the capability.
// Passing a port of 0 asks the OS for an ephemeral loopback port.
func (app *App) Listen(listenAddr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	host, port, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr != nil || !isLoopbackHost(host) {
		listener.Close()
		return nil, fmt.Errorf("refusing to serve pairing UI on non-loopback %s", listener.Addr().String())
	}
	portNumber, convErr := strconv.Atoi(port)
	if convErr != nil || portNumber < 1 || portNumber > 65535 {
		listener.Close()
		return nil, fmt.Errorf("pairing UI listener reported an unusable port %q", port)
	}
	token, tokenErr := agent.GeneratePairingCapability()
	if tokenErr != nil {
		listener.Close()
		return nil, tokenErr
	}
	err = agent.WritePairingEndpoint(app.stateDir, agent.PairingEndpoint{
		Port:      portNumber,
		Token:     token,
		PID:       os.Getpid(),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		listener.Close()
		return nil, err
	}
	app.mu.Lock()
	app.endpointToken = token
	app.mu.Unlock()
	return listener, nil
}

// Serve binds and serves the loopback listener until ctx is done.
func (app *App) Serve(ctx context.Context, listenAddr string, logger *slog.Logger) error {
	listener, err := app.Listen(listenAddr)
	if err != nil {
		return err
	}
	return app.ServeListener(ctx, listener, logger)
}

// ServeListener serves an already-bound listener until ctx is done, then
// withdraws the published endpoint record so the tray cannot verify against a
// listener that has gone away.
func (app *App) ServeListener(ctx context.Context, listener net.Listener, logger *slog.Logger) error {
	defer func() {
		if err := agent.RemovePairingEndpoint(app.stateDir); err != nil {
			logger.Warn("withdraw pairing endpoint record failed", "error", err)
		}
	}()
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
  #ca-file { width: 320px; }
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
<br>
<label for="ca-file">CA file (optional):</label>
<input id="ca-file" name="ca_file" value="%s" placeholder="C:\certs\private-ca.pem" autocomplete="off" spellcheck="false">
<p class="info">Self-hosted/test deployments only. A supplied path must be a readable PEM certificate and replaces the trust anchor; leaving it empty keeps the configured one.</p>
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
<h2>4. Pairing authorization</h2>
<p class="info">The pairing authorization is rotated automatically after a successful pairing. Rotate it manually if this page's URL may have been seen by someone else; the tray's "Open pairing page" reads the new value.</p>
<form method="post" action="/pairing/rotate?cap=%s">
<input type="hidden" name="hooshix_csrf" value="%s">
<button type="submit">Rotate pairing authorization</button>
</form>
%s
%s
</body>
</html>
`

// bootstrapTemplate is the only page served without the pairing capability. It
// contains no public key, capability, CSRF token, or state — it is a constant,
// not a format string — so an unauthenticated read of the loopback port
// discloses nothing.
const bootstrapTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>HooshiX Agent</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  .info { color: #555; } .error { color: #b00020; }
  input { font: inherit; padding: .35rem .5rem; width: 100%; }
  button { padding: .5rem 1.2rem; margin-top: .6rem; }
  h1 { font-size: 1.3rem; }
</style>
</head>
<body>
<h1>HooshiX Agent Setup</h1>
<p class="error">Pairing authorization required.</p>
<p class="info">Open this page from the HooshiX Agent tray icon ("Open pairing page"), which supplies the pairing authorization, or paste the authorization text below. On Windows the authorization file is readable by the interactive desktop user and by Administrators.</p>
<form method="get" action="/">
<input name="cap" autocomplete="off" spellcheck="false" placeholder="pairing authorization" required>
<button type="submit">Continue</button>
</form>
</body>
</html>
`

// Compile-time check: template stays parseable with the fmt verbs used.
var _ = func() error {
	_, err := template.New("page").Parse(strings.ReplaceAll(pageTemplate, "%%", "%"))
	return err
}()
