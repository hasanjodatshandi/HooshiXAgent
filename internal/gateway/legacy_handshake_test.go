package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestLegacyAgentReceivesBaselineSessionReady(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer gateway.Close(ctx)
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()
	conn, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https")+agentPath, &websocket.DialOptions{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	hello := clientHello(identity)
	if err := sendHello(ctx, conn, hello, 1); err != nil {
		t.Fatal(err)
	}
	frame := readFrameForTest(t, ctx, conn)
	var challenge contractv1.ServerChallenge
	if err := json.Unmarshal(frame.Payload, &challenge); err != nil {
		t.Fatal(err)
	}
	auth := contractv1.ClientAuth{ContractVersion: 1, MessageType: "client_auth", SessionID: challenge.SessionID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity.privateKey, contractv1.AuthTranscript(hello, challenge)))}
	if err := writeControlFrame(ctx, conn, 2, 0, auth); err != nil {
		t.Fatal(err)
	}
	ready := readFrameForTest(t, ctx, conn)
	// An old strict decoder knows only these fields. Even a present empty
	// resume_challenge breaks it, so assert absence at the wire boundary.
	var legacy struct {
		ContractVersion int    `json:"contract_version"`
		MessageType     string `json:"message_type"`
		SessionID       string `json:"session_id"`
		Heartbeat       int    `json:"heartbeat_interval_seconds"`
		Idle            int    `json:"idle_timeout_seconds"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(ready.Payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.MessageType != "session_ready" || legacy.SessionID != challenge.SessionID {
		t.Fatalf("bad ready: %+v", legacy)
	}
}
