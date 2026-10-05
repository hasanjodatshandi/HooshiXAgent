package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const serviceEnrollmentTimeout = 20 * time.Second

type ServiceEnrollmentStart struct {
	State           string `json:"state"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresAt       string `json:"expires_at"`
}

type ServiceEnrollmentClaim struct {
	State    string `json:"state"`
	DeviceID string `json:"device_id,omitempty"`
}

// StartServiceEnrollment delegates enrollment to the running service so the
// private key and resulting session token stay inside the LocalSystem-owned
// DPAPI boundary on Windows.
func StartServiceEnrollment(stateDir, serverURL, deviceName string) (ServiceEnrollmentStart, error) {
	payload, err := json.Marshal(map[string]string{"server_url": serverURL, "device_name": deviceName})
	if err != nil {
		return ServiceEnrollmentStart{}, err
	}
	var result ServiceEnrollmentStart
	if err := requestPairingServiceJSON(stateDir, "/enrollment/start", payload, http.StatusCreated, &result); err != nil {
		return ServiceEnrollmentStart{}, err
	}
	if result.State != "pending" || result.UserCode == "" || result.VerificationURI == "" {
		return ServiceEnrollmentStart{}, errors.New("service returned an invalid enrollment start response")
	}
	return result, nil
}

func ClaimServiceEnrollment(stateDir string) (ServiceEnrollmentClaim, error) {
	var result ServiceEnrollmentClaim
	if err := requestPairingServiceJSON(stateDir, "/enrollment/claim", nil, http.StatusOK, &result); err != nil {
		return ServiceEnrollmentClaim{}, err
	}
	if result.State != "pending" && (result.State != "claimed" || result.DeviceID == "") {
		return ServiceEnrollmentClaim{}, errors.New("service returned an invalid enrollment claim response")
	}
	return result, nil
}

func requestPairingServiceJSON(stateDir, path string, payload []byte, expectedStatus int, result any) error {
	endpoint, err := LoadPairingEndpoint(stateDir)
	if err != nil {
		return describeServiceUnavailable(err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(endpoint.Port))
	client := &http.Client{Timeout: serviceEnrollmentTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if err := verifyServiceListener(client, address, endpoint.Token); err != nil {
		return describeServiceUnavailable(err)
	}
	capability, err := LoadPairingCapability(stateDir)
	if err != nil {
		return fmt.Errorf("read pairing capability: %w", err)
	}
	csrf, err := fetchPairingCSRFToken(client, address, capability)
	if err != nil {
		return err
	}
	body := io.Reader(http.NoBody)
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+address+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", csrf)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request enrollment from the HooshiXAgent service: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil {
		return err
	}
	if len(data) > 16*1024 {
		return errors.New("service enrollment response exceeds 16 KiB")
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("HooshiXAgent service returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode service enrollment response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("service enrollment response contains trailing JSON")
	}
	return nil
}
