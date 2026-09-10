// Package webapp implements the local, loopback-only Agent pairing UI.
//
// The UI is intentionally minimal: a single page served on 127.0.0.1 that
// shows the device public key for panel registration and accepts a pasted
// pairing JSON (device_id, authorization_id, token_id, token, gateway_url,
// optional aliases) that is applied atomically to the Agent state, including
// writing token.txt next to the config for the user's records.
package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// PairingPayload is the single-paste format produced by the panel.
type PairingPayload struct {
	GatewayURL     string `json:"gateway_url"`
	GatewayAliases string `json:"gateway_aliases,omitempty"`
	DeviceID       string `json:"device_id"`
	AuthorizationID string `json:"authorization_id"`
	TokenID        string `json:"token_id"`
	Token          string `json:"token"`
}

// App wires the HTTP handlers to Agent state.
type App struct {
	stateDir string
	logger   *slog.Logger

	mu       sync.Mutex
	notice   string
	noticeAt time.Time
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
	return &App{stateDir: normalized, logger: logger}, nil
}

// StateDir exposes the normalized state directory.
func (app *App) StateDir() string { return app.stateDir }

// Handler builds the http.Handler with all routes.
func (app *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/pair", app.handlePair)
	return mux
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
	app.mu.Lock()
	if time.Since(app.noticeAt) < 10*time.Minute {
		notice = app.notice
	}
	app.mu.Unlock()
	fmt.Fprintf(w, pageTemplate, publicKey, keyErrText(keyErr), pairedText(paired, config.GatewayURL, config.DeviceID), notice)
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

// handlePair applies the pasted pairing payload.
func (app *App) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
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
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse form failed", http.StatusBadRequest)
			return
		}
		raw = []byte(r.PostFormValue("pairing"))
	}
	var payload PairingPayload
	text := htmlUnescape(strings.TrimSpace(string(raw)))
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		// Also accept the panel's fenced-block copy format.
		fenced := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "```"), "```"))
		if jsonErr := json.Unmarshal([]byte(htmlUnescape(fenced)), &payload); jsonErr != nil {
			app.setNotice("invalid pairing text: " + err.Error())
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	if err := app.ApplyPairing(payload); err != nil {
		app.setNotice("pairing failed: " + err.Error())
		app.logger.Warn("pairing failed", "error", err)
	} else {
		app.setNotice("paired successfully; the agent service will connect automatically")
		app.logger.Info("agent paired", "device", payload.DeviceID, "gateway", payload.GatewayURL)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ApplyPairing validates and atomically persists the pairing payload,
// including the user-facing token.txt copy in the state directory.
func (app *App) ApplyPairing(payload PairingPayload) error {
	payload.Token = strings.TrimSpace(payload.Token)
	if !agent.SessionTokenPattern.MatchString(payload.Token) {
		return fmt.Errorf("session token must be 32..512 base64url-safe characters")
	}
	if err := agent.ValidateGatewayURL(payload.GatewayURL); err != nil {
		return err
	}
	store := agent.NewPlatformSecretStore(app.stateDir)
	if _, _, err := agent.LoadOrCreateIdentity(store); err != nil {
		return err
	}
	if err := agent.SetSessionToken(store, payload.Token); err != nil {
		return err
	}
	// token.txt user copy (documented as a convenience record; the live
	// credential remains the DPAPI secret store).
	if err := agent.WriteTokenCopy(app.stateDir, payload.Token); err != nil {
		app.logger.Warn("token.txt copy failed", "error", err)
	}
	config := agent.Config{
		GatewayURL:      payload.GatewayURL,
		DeviceID:        payload.DeviceID,
		AuthorizationID: payload.AuthorizationID,
		TokenID:         payload.TokenID,
		UpdateChannel:   "stable",
	}
	if raw := strings.TrimSpace(payload.GatewayAliases); raw != "" {
		config.GatewayAliases = strings.Split(raw, ",")
	}
	return agent.SaveConfig(app.stateDir, config)
}

func (app *App) setNotice(message string) {
	app.mu.Lock()
	app.notice = message
	app.noticeAt = time.Now()
	app.mu.Unlock()
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
	server := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second}
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

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HooshiX Agent — Pair</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  .key { background: #f4f4f8; border: 1px solid #ccc; padding: .8rem; font-family: monospace; word-break: break-all; user-select: all; }
  textarea { width: 100%%; height: 8rem; font-family: monospace; }
  .ok { color: #0a7a2e; } .error { color: #b00020; } .info { color: #555; }
  button { padding: .5rem 1.2rem; }
  h1 { font-size: 1.3rem; }
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
<form method="post" action="/pair">
<textarea name="pairing" placeholder='{"gateway_url":"wss://...","device_id":"device-...","authorization_id":"auth-...","token_id":"token-...","token":"..."}'></textarea>
<br><button type="submit">Pair</button>
</form>
<p class="info">%s</p>
</body>
</html>
`
