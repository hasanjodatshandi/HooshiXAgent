package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// serviceUnpairTimeout bounds the whole delegated conversation with the
// service-hosted pairing endpoint. It is a local loopback call, so a listener
// that cannot answer promptly is not the service.
const serviceUnpairTimeout = 15 * time.Second

// serviceProbeTimeout bounds the listener-identity challenge used to detect
// whether a service is serving a state directory.
const serviceProbeTimeout = 3 * time.Second

// maxPairingPageBytes bounds how much of the pairing page is read while
// extracting the per-process CSRF token.
const maxPairingPageBytes = 64 * 1024

// csrfFieldPattern extracts the CSRF token the authenticated pairing page
// embeds in every mutating form. The token is 256 bits of base64url, so the
// page's HTML escaping never rewrites it.
var csrfFieldPattern = regexp.MustCompile(`name="hooshix_csrf" value="([A-Za-z0-9_-]{43})"`)

// requestServiceUnpair asks the RUNNING Agent service to clear the pairing and
// waits for its verdict. It is the coordination half of the unpair design:
//
// The Windows service runs as LocalSystem and owns a DPAPI CurrentUser secret
// store, which no interactive process can read or rewrite. An operator command
// therefore cannot clear the session token (nor mint a replacement identity
// the service could decrypt) on its own. The service already exposes an
// authenticated loopback endpoint — the pairing UI it serves in service
// context — so unpair drives exactly the operation the "Unpair" button drives,
// with the same pairing-capability, same-origin and CSRF gates.
//
// The caller must already hold the pairing capability (readable only from the
// ACL-protected state directory) and must have verified the listener identity,
// so a local port squatter never receives it.
func requestServiceUnpair(stateDir string, resetIdentity bool) (UnpairResult, error) {
	endpoint, err := LoadPairingEndpoint(stateDir)
	if err != nil {
		// The record is withdrawn when the listener stops, so a missing record
		// means the service is not serving: impossible to clear its state from
		// here.
		return UnpairResult{}, describeServiceUnavailable(err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(endpoint.Port))
	client := &http.Client{
		Timeout: serviceUnpairTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// The unpair action answers a JSON client directly; a redirect means
			// the request reached the browser form path and must not be followed.
			return http.ErrUseLastResponse
		},
	}
	if err := verifyServiceListener(client, address, endpoint.Token); err != nil {
		return UnpairResult{}, describeServiceUnavailable(err)
	}
	capability, err := LoadPairingCapability(stateDir)
	if err != nil {
		return UnpairResult{}, fmt.Errorf("read pairing capability: %w", err)
	}
	csrfToken, err := fetchPairingCSRFToken(client, address, capability)
	if err != nil {
		return UnpairResult{}, err
	}
	form := url.Values{}
	if resetIdentity {
		form.Set("reset_identity", "true")
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/unpair", strings.NewReader(form.Encode()))
	if err != nil {
		return UnpairResult{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	request.Header.Set("X-HooshiX-CSRF", csrfToken)
	response, err := client.Do(request)
	if err != nil {
		return UnpairResult{}, fmt.Errorf("request unpair from the HooshiXAgent service: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return UnpairResult{}, fmt.Errorf("read unpair response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return UnpairResult{}, fmt.Errorf("the HooshiXAgent service refused to clear the pairing: %s", message)
	}
	var result UnpairResult
	if err := json.Unmarshal(body, &result); err != nil {
		return UnpairResult{}, fmt.Errorf("decode unpair response: %w", err)
	}
	return result, nil
}

// verifyServiceListener challenges the loopback port and compares the answer
// with the token published in pairing.endpoint.json. Any local process can
// bind the port, and the pairing capability is the credential that re-points
// this device at a gateway, so it is never handed to an unverified address.
func verifyServiceListener(client *http.Client, address, expectedToken string) error {
	response, err := client.Get("http://" + address + "/pairing/identity")
	if err != nil {
		return fmt.Errorf("challenge listener identity: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("listener identity probe status=%d", response.StatusCode)
	}
	var identity struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&identity); err != nil {
		return fmt.Errorf("decode listener identity: %w", err)
	}
	if !PairingCapabilityMatches(expectedToken, identity.Token) {
		return errors.New("listener identity mismatch")
	}
	return nil
}

// fetchPairingCSRFToken reads the CSRF token from the authenticated pairing
// page. The page is only served to a caller that already holds the capability,
// and the token is the same per-process value every mutating form carries, so
// this is the identical gate a browser goes through.
func fetchPairingCSRFToken(client *http.Client, address, capability string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "text/html")
	request.Header.Set("X-HooshiX-Pairing-Capability", capability)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("read pairing authorization: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pairing authorization rejected with status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPairingPageBytes))
	if err != nil {
		return "", fmt.Errorf("read pairing page: %w", err)
	}
	match := csrfFieldPattern.FindSubmatch(body)
	if match == nil {
		return "", errors.New("pairing page did not carry a CSRF token")
	}
	return string(match[1]), nil
}
