package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollmentExchangeProvesKeyAndClaimsOnce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var proofVerified atomic.Bool
	var claims atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/agent/enrollments":
			if request.Method != http.MethodPost {
				t.Fatal("create method was not POST")
			}
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"enrollment_id":    "enroll-ABCDEFGHIJKL",
				"user_code":        "ABCD-EFGH",
				"poll_token":       strings.Repeat("p", 43),
				"challenge":        base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				"verification_uri": serverURL(request) + "/",
				"expires_at":       time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
			})
		case "/api/v1/agent/enrollments/enroll-ABCDEFGHIJKL/proof":
			var body struct {
				Signature string `json:"signature"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			signature, err := base64.RawURLEncoding.DecodeString(body.Signature)
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("hooshix-enrollment-v1\x00enroll-ABCDEFGHIJKL\x00" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "\x00" + base64.RawURLEncoding.EncodeToString(publicKey))
			proofVerified.Store(ed25519.Verify(publicKey, message, signature))
			response.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/enrollments/enroll-ABCDEFGHIJKL/claim":
			if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("p", 43) {
				t.Fatal("claim omitted the poll secret")
			}
			if claims.Add(1) == 1 {
				_ = json.NewEncoder(response).Encode(map[string]string{"state": "pending"})
				return
			}
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
	defer server.Close()

	client := NewClient(server.Client())
	session, err := client.Begin(context.Background(), server.URL, "office PC", publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !proofVerified.Load() || session.UserCode != "ABCD-EFGH" {
		t.Fatalf("proof/code mismatch: verified=%v session=%+v", proofVerified.Load(), session)
	}
	credentials, err := client.Claim(context.Background(), server.URL, session)
	if err != nil || credentials != nil {
		t.Fatalf("pending claim = %+v, %v", credentials, err)
	}
	credentials, err = client.Claim(context.Background(), server.URL, session)
	if err != nil {
		t.Fatal(err)
	}
	if credentials == nil || credentials.DeviceID != "device-001" || credentials.Token == "" {
		t.Fatalf("credentials = %+v", credentials)
	}
}

func TestEnrollmentRejectsInsecureRemoteServerAndOversizedResponse(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	client := NewClient(nil)
	if _, err := client.Begin(context.Background(), "http://agent.example.com", "pc", publicKey, privateKey); err == nil {
		t.Fatal("accepted insecure remote enrollment URL")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
	}))
	defer server.Close()
	client = NewClient(server.Client())
	if _, err := client.Begin(context.Background(), server.URL, "pc", publicKey, privateKey); err == nil || !strings.Contains(err.Error(), "16 KiB") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func serverURL(request *http.Request) string {
	return "https://" + request.Host
}
