package webapp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

const maxEnrollmentRequestBytes = 16 * 1024

type enrollmentStartRequest struct {
	ServerURL  string `json:"server_url"`
	DeviceName string `json:"device_name"`
}

func (app *App) handleEnrollmentStart(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !app.requireCSRF(response, request) {
		return
	}
	var input enrollmentStartRequest
	if err := decodeEnrollmentJSON(response, request, &input); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}

	app.enrollmentMu.Lock()
	defer app.enrollmentMu.Unlock()
	if pending := app.pendingEnrollment; pending != nil && time.Now().Before(pending.session.ExpiresAt) {
		http.Error(response, "an enrollment is already pending", http.StatusConflict)
		return
	}
	store := agent.NewPlatformSecretStore(app.stateDir)
	publicKey, privateKey, err := agent.LoadIdentity(store)
	if err != nil {
		http.Error(response, "device identity is unavailable", http.StatusInternalServerError)
		return
	}
	session, err := app.enrollmentClient.Begin(request.Context(), input.ServerURL, input.DeviceName, publicKey, privateKey)
	if err != nil {
		app.logger.Warn("device enrollment start failed", "error", err)
		http.Error(response, "the enrollment server refused the request", http.StatusBadGateway)
		return
	}
	app.pendingEnrollment = &pendingEnrollment{serverURL: strings.TrimSpace(input.ServerURL), session: session}
	writeEnrollmentJSON(response, http.StatusCreated, map[string]string{
		"state":            "pending",
		"user_code":        session.UserCode,
		"verification_uri": session.VerificationURI,
		"expires_at":       session.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (app *App) handleEnrollmentClaim(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !app.requireCSRF(response, request) {
		return
	}

	app.enrollmentMu.Lock()
	defer app.enrollmentMu.Unlock()
	pending := app.pendingEnrollment
	if pending == nil {
		http.Error(response, "no enrollment is pending", http.StatusNotFound)
		return
	}
	credentials, err := app.enrollmentClient.Claim(request.Context(), pending.serverURL, pending.session)
	if err != nil {
		app.logger.Warn("device enrollment claim failed", "error", err)
		http.Error(response, "the enrollment server refused the claim", http.StatusBadGateway)
		return
	}
	if credentials == nil {
		writeEnrollmentJSON(response, http.StatusOK, map[string]string{"state": "pending"})
		return
	}
	// Claim is one-time at the Panel. Clear the in-memory exchange before the
	// local commit so a local write failure cannot be presented as retryable.
	app.pendingEnrollment = nil
	if err := app.ApplyPairing(PairingPayload{
		GatewayURL:      credentials.GatewayURL,
		DeviceID:        credentials.DeviceID,
		AuthorizationID: credentials.AuthorizationID,
		TokenID:         credentials.TokenID,
		Token:           credentials.Token,
	}); err != nil {
		app.logger.Error("claimed enrollment could not be committed", "error", err)
		http.Error(response, "credential commit failed; start a new enrollment", http.StatusInternalServerError)
		return
	}
	if err := app.rotateCapability(); err != nil {
		app.logger.Warn("rotate pairing capability after enrollment failed", "error", err)
	}
	app.setNotice("device enrolled successfully; the service will connect automatically")
	writeEnrollmentJSON(response, http.StatusOK, map[string]string{
		"state":     "claimed",
		"device_id": credentials.DeviceID,
	})
}

func decodeEnrollmentJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	if strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		return errors.New("application/json required")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxEnrollmentRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeEnrollmentJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
