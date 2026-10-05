// Package enrollment implements the short-lived browser-approved device
// enrollment exchange. It owns only the HTTPS adapter; Agent state mutation is
// performed by the caller after every returned field passes Agent validation.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxResponseBytes = 16 * 1024

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	userCodePattern   = regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`)
	tokenPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
)

type Client struct {
	httpClient *http.Client
	now        func() time.Time
}

type Session struct {
	EnrollmentID    string
	UserCode        string
	PollToken       string
	VerificationURI string
	ExpiresAt       time.Time
}

type Credentials struct {
	DeviceID        string
	AuthorizationID string
	TokenID         string
	Token           string
	ExpiresAt       time.Time
	GatewayURL      string
}

type beginResponse struct {
	EnrollmentID    string `json:"enrollment_id"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	PollToken       string `json:"poll_token"`
	Challenge       string `json:"challenge"`
	ExpiresAt       string `json:"expires_at"`
}

type claimResponse struct {
	State           string `json:"state"`
	DeviceID        string `json:"device_id"`
	AuthorizationID string `json:"authorization_id"`
	TokenID         string `json:"token_id"`
	Token           string `json:"token"`
	ExpiresAt       string `json:"expires_at"`
	GatewayURL      string `json:"gateway_url"`
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{httpClient: httpClient, now: time.Now}
}

// Begin creates an enrollment request and immediately proves possession of the
// on-device private key. The private key is used only for the domain-separated
// signature and is never serialized or sent.
func (client *Client) Begin(ctx context.Context, serverURL, deviceName string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (Session, error) {
	base, err := validateServerURL(serverURL)
	if err != nil {
		return Session{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize || !publicKey.Equal(privateKey.Public()) {
		return Session{}, errors.New("device Ed25519 key pair is invalid")
	}
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" || len(deviceName) > 64 {
		return Session{}, errors.New("device name must be 1..64 characters")
	}

	var created beginResponse
	if err := client.postJSON(ctx, base, "/api/v1/agent/enrollments", "", map[string]string{
		"device_name": deviceName,
		"public_key":  base64.RawURLEncoding.EncodeToString(publicKey),
	}, http.StatusCreated, &created); err != nil {
		return Session{}, fmt.Errorf("create enrollment: %w", err)
	}
	if err := validateBeginResponse(created, client.now()); err != nil {
		return Session{}, fmt.Errorf("invalid enrollment response: %w", err)
	}
	message := []byte("hooshix-enrollment-v1\x00" + created.EnrollmentID + "\x00" + created.Challenge + "\x00" + base64.RawURLEncoding.EncodeToString(publicKey))
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	proofPath := "/api/v1/agent/enrollments/" + url.PathEscape(created.EnrollmentID) + "/proof"
	if err := client.postJSON(ctx, base, proofPath, "", map[string]string{"signature": signature}, http.StatusNoContent, nil); err != nil {
		return Session{}, fmt.Errorf("prove enrollment key: %w", err)
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, created.ExpiresAt)
	return Session{
		EnrollmentID:    created.EnrollmentID,
		UserCode:        created.UserCode,
		PollToken:       created.PollToken,
		VerificationURI: created.VerificationURI,
		ExpiresAt:       expiresAt,
	}, nil
}

// Claim checks an enrollment without hiding pending approval as an error.
// Credentials are returned only for the single successful claim.
func (client *Client) Claim(ctx context.Context, serverURL string, session Session) (*Credentials, error) {
	base, err := validateServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	if !identifierPattern.MatchString(session.EnrollmentID) || !tokenPattern.MatchString(session.PollToken) {
		return nil, errors.New("enrollment session is invalid")
	}
	path := "/api/v1/agent/enrollments/" + url.PathEscape(session.EnrollmentID) + "/claim"
	var claimed claimResponse
	if err := client.postJSON(ctx, base, path, session.PollToken, nil, http.StatusOK, &claimed); err != nil {
		return nil, fmt.Errorf("claim enrollment: %w", err)
	}
	if claimed.State == "pending" || claimed.State == "approved" {
		return nil, nil
	}
	if claimed.State != "claimed" {
		return nil, fmt.Errorf("unexpected enrollment state %q", claimed.State)
	}
	if err := validateCredentials(claimed, client.now()); err != nil {
		return nil, fmt.Errorf("invalid enrollment credentials: %w", err)
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, claimed.ExpiresAt)
	return &Credentials{
		DeviceID:        claimed.DeviceID,
		AuthorizationID: claimed.AuthorizationID,
		TokenID:         claimed.TokenID,
		Token:           claimed.Token,
		ExpiresAt:       expiresAt,
		GatewayURL:      claimed.GatewayURL,
	}, nil
}

func (client *Client) postJSON(ctx context.Context, base *url.URL, path, bearer string, payload any, expectedStatus int, result any) error {
	var body io.Reader = http.NoBody
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	endpoint := *base
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("response exceeds 16 KiB")
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	if result == nil {
		if len(bytes.TrimSpace(data)) != 0 {
			return errors.New("unexpected response body")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("response contains trailing JSON")
	}
	return nil
}

func validateServerURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("server URL must be an origin without credentials, path, query, or fragment")
	}
	if parsed.Scheme != "https" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if parsed.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("server URL must use HTTPS (HTTP is allowed only for an IP/localhost test server)")
		}
	}
	parsed.Path = ""
	return parsed, nil
}

func validateBeginResponse(response beginResponse, now time.Time) error {
	if !identifierPattern.MatchString(response.EnrollmentID) {
		return errors.New("enrollment_id is invalid")
	}
	if !userCodePattern.MatchString(response.UserCode) {
		return errors.New("user_code is invalid")
	}
	if len(response.PollToken) < 32 {
		return errors.New("poll_token is invalid")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(response.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != response.Challenge {
		return errors.New("challenge is invalid")
	}
	verification, err := url.Parse(response.VerificationURI)
	if err != nil || verification.Host == "" || verification.User != nil || verification.RawQuery != "" || verification.Fragment != "" {
		return errors.New("verification_uri is invalid")
	}
	if verification.Scheme != "https" {
		host := verification.Hostname()
		ip := net.ParseIP(host)
		if verification.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return errors.New("verification_uri must use HTTPS")
		}
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil || !expiresAt.After(now) || expiresAt.After(now.Add(15*time.Minute)) {
		return errors.New("expires_at is outside the accepted window")
	}
	return nil
}

func validateCredentials(response claimResponse, now time.Time) error {
	for name, value := range map[string]string{
		"device_id": response.DeviceID, "authorization_id": response.AuthorizationID, "token_id": response.TokenID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if !tokenPattern.MatchString(response.Token) {
		return errors.New("token is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil || !expiresAt.After(now) {
		return errors.New("expires_at is invalid")
	}
	gateway, err := url.Parse(response.GatewayURL)
	if err != nil || gateway.Scheme != "wss" || gateway.Host == "" || gateway.Path != "/agent/v1/connect" || gateway.User != nil || gateway.RawQuery != "" || gateway.Fragment != "" {
		return errors.New("gateway_url is invalid")
	}
	return nil
}
