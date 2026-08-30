package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAuditRegressionExpiredAuthorizationMustTerminateActiveSession(t *testing.T) {
	if os.Getenv("HOOSHIX_AUDIT_REGRESSION_PROOF") != "1" {
		t.Skip("R-0 regression proof is opt-in until authorization lifecycle hardening lands")
	}

	identity := newTestIdentity(t)
	source := NewSnapshotMetadata()
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	authorization.IssuedAt = now.Add(-time.Minute).Format(time.RFC3339)
	authorization.NotBefore = now.Add(-time.Minute).Format(time.RFC3339)
	authorization.ExpiresAt = now.Add(2 * time.Second).Format(time.RFC3339)

	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	routeJSON, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.addAuthorizationJSON(authorizationJSON); err != nil {
		t.Fatal(err)
	}
	if err := source.addRouteJSON(routeJSON); err != nil {
		t.Fatal(err)
	}

	limits := DefaultLimits()
	limits.HeartbeatInterval = 5 * time.Second
	limits.IdleTimeout = 15 * time.Second
	gateway, err := New(source, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer local.Close()

	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	time.Sleep(6 * time.Second)
	if _, err := source.Authorization(context.Background(), identity.authorizationID, identity.deviceID, identity.tokenID, time.Now().UTC()); err == nil {
		t.Fatal("audit fixture authorization unexpectedly remains valid after expires_at")
	}
	if gateway.sessionForDevice(identity.deviceID) != nil {
		t.Fatal("AUDIT-R0 active Agent session survived authorization expires_at")
	}
}
