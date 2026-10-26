// SPA delivery and the JSON state endpoint used by the local Agent UI.
//
// The compiled React bundle is embedded at build time and committed to the
// repository (see ui/README.md). Only hashed build artifacts and the two
// root-level public files are served without the pairing capability: they
// contain no state, no capability and no CSRF token, and the shell that
// references them is still gated. Every state-bearing response stays behind
// the capability check in webapp.go.
package webapp

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

//go:embed all:ui/dist
var uiBundle embed.FS

var uiFiles = func() fs.FS {
	sub, err := fs.Sub(uiBundle, "ui/dist")
	if err != nil {
		panic("agent UI bundle is missing ui/dist: " + err.Error())
	}
	return sub
}()

const uiContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// withSecurityHeaders applies the headers that are common to every response,
// including rejections produced by the guards. Handlers may override
// Cache-Control for immutable assets.
func (app *App) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", uiContentSecurityPolicy)
		header.Set("Cache-Control", "no-store")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r)
	})
}

// uiPublicAssetName resolves a request path to a build artifact that may be
// served before the capability check. Only the exact root files and flat
// files under assets/ qualify; anything else (including traversal attempts
// and nested paths) is rejected.
func uiPublicAssetName(requestPath string) (string, bool) {
	name := strings.TrimPrefix(path.Clean("/"+requestPath), "/")
	switch name {
	case "boot.js", "favicon.svg":
		return name, true
	}
	rest, ok := strings.CutPrefix(name, "assets/")
	if !ok || rest == "" || strings.Contains(rest, "/") || strings.HasPrefix(rest, ".") {
		return "", false
	}
	return name, true
}

func (app *App) handleUIAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	name, ok := uiPublicAssetName(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	cacheControl := "no-cache"
	if strings.HasPrefix(name, "assets/") {
		cacheControl = "public, max-age=31536000, immutable"
	}
	serveUIFile(w, r, name, cacheControl)
}

func serveUIFile(w http.ResponseWriter, r *http.Request, name, cacheControl string) {
	data, err := fs.ReadFile(uiFiles, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", cacheControl)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

type uiStateConfig struct {
	GatewayURL string           `json:"gateway_url,omitempty"`
	CAFile     string           `json:"ca_file,omitempty"`
	DeviceID   string           `json:"device_id,omitempty"`
	Endpoints  []agent.Endpoint `json:"endpoints"`
}

// uiStateResponse deliberately carries no session token, private key or
// capability: every caller already holds the capability, and the CSRF token
// is only usable together with it.
type uiStateResponse struct {
	Paired          bool                   `json:"paired"`
	Config          uiStateConfig          `json:"config"`
	PublicKey       string                 `json:"public_key,omitempty"`
	PublicKeyError  string                 `json:"public_key_error,omitempty"`
	Pending         *pendingEnrollmentView `json:"pending"`
	Tunnel          TunnelHealth           `json:"tunnel"`
	Notice          string                 `json:"notice,omitempty"`
	NoticeAt        string                 `json:"notice_at,omitempty"`
	CSRF            string                 `json:"csrf"`
	Hostname        string                 `json:"hostname"`
	DefaultPanelURL string                 `json:"default_panel_url"`
	Version         string                 `json:"version"`
}

// handleState returns the single state document the SPA renders from. It is
// behind the same capability gate as the shell and never creates state (the
// public key load is read-only).
func (app *App) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	config, err := agent.LoadConfig(app.stateDir)
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, map[string]string{"error": "load config failed"})
		return
	}
	publicKey, keyErr := app.PublicKey()
	publicKeyError := ""
	if keyErr != nil {
		publicKeyError = agent.SanitizedError(keyErr)
	}
	hostname, hostErr := os.Hostname()
	if hostErr != nil || strings.TrimSpace(hostname) == "" {
		hostname = "hooshix-agent"
	}
	endpoints := endpointsOrEmpty(config.Endpoints)
	notice, noticeAt := app.currentNotice()
	writeJSONMessage(w, http.StatusOK, uiStateResponse{
		Paired: config.ValidateRuntime() == nil,
		Config: uiStateConfig{
			GatewayURL: config.GatewayURL,
			CAFile:     config.CAFile,
			DeviceID:   config.DeviceID,
			Endpoints:  endpoints,
		},
		PublicKey:       publicKey,
		PublicKeyError:  publicKeyError,
		Pending:         app.pendingEnrollmentSnapshot(),
		Tunnel:          loadTunnelHealth(app.stateDir),
		Notice:          notice,
		NoticeAt:        noticeAt,
		CSRF:            app.ensureCSRFToken(),
		Hostname:        hostname,
		DefaultPanelURL: defaultEnrollmentPanelURL,
		Version:         agent.Version,
	})
}

func endpointsOrEmpty(endpoints []agent.Endpoint) []agent.Endpoint {
	if endpoints == nil {
		return []agent.Endpoint{}
	}
	return endpoints
}

// currentNotice returns the short-lived operator notice, if any.
func (app *App) currentNotice() (string, string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if time.Since(app.noticeAt) >= 10*time.Minute {
		return "", ""
	}
	return app.notice, app.noticeAt.UTC().Format(time.RFC3339)
}
