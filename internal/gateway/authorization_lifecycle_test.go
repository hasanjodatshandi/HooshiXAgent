package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestActiveSessionTerminatesWhenAuthorizationExpires(t *testing.T) {
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
	activeSession := gateway.sessionForDevice(identity.deviceID)
	if activeSession == nil {
		t.Fatal("authenticated session disappeared before expiry")
	}

	select {
	case <-activeSession.done:
	case <-time.After(4 * time.Second):
		t.Fatal("session transport remained active beyond authorization expiry")
	}
	if gateway.sessionForDevice(identity.deviceID) != nil {
		t.Fatal("expired session remained routable")
	}
	if _, err := source.Authorization(context.Background(), identity.authorizationID, identity.deviceID, identity.tokenID, time.Now().UTC()); err == nil {
		t.Fatal("authorization unexpectedly remains valid after expires_at")
	}
}

func TestActiveSessionTerminatesWhenRevocationBecomesEffective(t *testing.T) {
	identity := newTestIdentity(t)
	source := NewSnapshotMetadata()
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	routeJSON, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	revocationJSON, err := json.Marshal(contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-future-runtime-001",
		SubjectKind:     "device_session_authorization",
		SubjectID:       identity.authorizationID,
		EffectiveAt:     now.Add(2 * time.Second).Format(time.RFC3339),
		ReasonCode:      "credential_revoked",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.addAuthorizationJSON(authorizationJSON); err != nil {
		t.Fatal(err)
	}
	if err := source.addRouteJSON(routeJSON); err != nil {
		t.Fatal(err)
	}
	if err := source.addRevocationJSON(revocationJSON); err != nil {
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
	activeSession := gateway.sessionForDevice(identity.deviceID)
	if activeSession == nil {
		t.Fatal("authenticated session disappeared before revocation became effective")
	}
	select {
	case <-activeSession.done:
	case <-time.After(8 * time.Second):
		t.Fatal("session transport remained active after revocation became effective")
	}
	if gateway.sessionForDevice(identity.deviceID) != nil {
		t.Fatal("revoked session remained routable")
	}
}

type authorizationErrorMetadata struct {
	MetadataSource
	err error
}

func (source authorizationErrorMetadata) Authorization(context.Context, string, string, string, time.Time) (contractv1.DeviceSessionAuthorization, error) {
	return contractv1.DeviceSessionAuthorization{}, source.err
}

func TestAuthorizationRevalidationFailsClosedWhenMetadataUnavailable(t *testing.T) {
	identity := newTestIdentity(t)
	base := testMetadata(t, identity, testRouteHost)
	sess := &session{
		gateway: &Gateway{metadata: authorizationErrorMetadata{
			MetadataSource: base,
			err:            errors.New("synthetic metadata unavailable"),
		}},
		deviceID:               identity.deviceID,
		authorizationID:        identity.authorizationID,
		tokenID:                identity.tokenID,
		authorizationExpiresAt: time.Now().Add(time.Hour),
	}

	reasonCode, err := sess.revalidateAuthorization(context.Background(), time.Now().UTC())
	if err == nil {
		t.Fatal("unavailable authorization metadata unexpectedly remained authorized")
	}
	if reasonCode != "" {
		t.Fatalf("transient/unclassified metadata failure must not be sent as permanent revocation, got %q", reasonCode)
	}
}

func TestAuthorizationRevalidationClassifiesDisabledAndShortenedExpiry(t *testing.T) {
	identity := newTestIdentity(t)
	base := testMetadata(t, identity, testRouteHost)
	now := time.Now().UTC()

	for _, test := range []struct {
		name       string
		record     contractv1.DeviceSessionAuthorization
		reasonCode string
	}{
		{
			name: "disabled",
			record: contractv1.DeviceSessionAuthorization{
				AuthorizationID: identity.authorizationID,
				DeviceID:        identity.deviceID,
				TokenID:         identity.tokenID,
				Disabled:        true,
				ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339),
			},
			reasonCode: "disabled",
		},
		{
			name: "shortened expiry",
			record: contractv1.DeviceSessionAuthorization{
				AuthorizationID: identity.authorizationID,
				DeviceID:        identity.deviceID,
				TokenID:         identity.tokenID,
				ExpiresAt:       now.Add(-time.Second).Format(time.RFC3339),
			},
			reasonCode: "expired",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sess := &session{
				gateway: &Gateway{metadata: authorizationResultMetadata{
					MetadataSource: base,
					record:         test.record,
					err:            errors.New("synthetic authorization invalid"),
				}},
				deviceID:               identity.deviceID,
				authorizationID:        identity.authorizationID,
				tokenID:                identity.tokenID,
				authorizationExpiresAt: now.Add(time.Hour),
			}
			reasonCode, err := sess.revalidateAuthorization(context.Background(), now)
			if err == nil {
				t.Fatal("invalid authorization unexpectedly remained authorized")
			}
			if reasonCode != test.reasonCode {
				t.Fatalf("reason=%q want=%q", reasonCode, test.reasonCode)
			}
		})
	}
}

type authorizationResultMetadata struct {
	MetadataSource
	record contractv1.DeviceSessionAuthorization
	err    error
}

func (source authorizationResultMetadata) Authorization(context.Context, string, string, string, time.Time) (contractv1.DeviceSessionAuthorization, error) {
	return source.record, source.err
}

func TestAuthorizationRevalidationClassifiesEffectiveRevocation(t *testing.T) {
	identity := newTestIdentity(t)
	base := testMetadata(t, identity, testRouteHost)
	now := time.Now().UTC()
	revocation := contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-auth-runtime-001",
		SubjectKind:     "device_session_authorization",
		SubjectID:       identity.authorizationID,
		EffectiveAt:     now.Add(-time.Second).Format(time.RFC3339),
		ReasonCode:      "credential_revoked",
	}
	revocationJSON, err := json.Marshal(revocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.addRevocationJSON(revocationJSON); err != nil {
		t.Fatal(err)
	}
	sess := &session{
		gateway:                &Gateway{metadata: base},
		deviceID:               identity.deviceID,
		authorizationID:        identity.authorizationID,
		tokenID:                identity.tokenID,
		authorizationExpiresAt: now.Add(time.Hour),
	}

	reasonCode, err := sess.revalidateAuthorization(context.Background(), now)
	if err == nil {
		t.Fatal("effective revocation unexpectedly remained authorized")
	}
	if reasonCode != "credential_revoked" {
		t.Fatalf("revocation reason=%q want=credential_revoked", reasonCode)
	}
}

func TestAuthorizationRevalidationPreservesSecurityHoldRevocationReason(t *testing.T) {
	identity := newTestIdentity(t)
	base := testMetadata(t, identity, testRouteHost)
	now := time.Now().UTC()
	revocationJSON, err := json.Marshal(contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-auth-security-hold-001",
		SubjectKind:     "device",
		SubjectID:       identity.deviceID,
		EffectiveAt:     now.Add(-time.Second).Format(time.RFC3339),
		ReasonCode:      "security_hold",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := base.addRevocationJSON(revocationJSON); err != nil {
		t.Fatal(err)
	}
	sess := &session{
		gateway:                &Gateway{metadata: base},
		deviceID:               identity.deviceID,
		authorizationID:        identity.authorizationID,
		tokenID:                identity.tokenID,
		authorizationExpiresAt: now.Add(time.Hour),
	}

	reasonCode, err := sess.revalidateAuthorization(context.Background(), now)
	if err == nil {
		t.Fatal("security-hold revocation unexpectedly remained authorized")
	}
	if reasonCode != "security_hold" {
		t.Fatalf("revocation reason=%q want=security_hold", reasonCode)
	}
	if !strings.Contains(err.Error(), "security_hold") {
		t.Fatalf("revocation diagnostic lost source reason: %v", err)
	}
}

func TestTerminateAuthorizationSendsSessionRevokedBeforeClose(t *testing.T) {
	limits := DefaultLimits()
	gateway := &Gateway{limits: limits}
	written := make(chan []byte, 1)
	sess := &session{
		gateway:         gateway,
		authorizationID: "auth-runtime-001",
		controlWrites:   make(chan sessionWriteRequest, 1),
		dataWrites:      make(chan sessionWriteRequest, 1),
		streams:         make(map[uint32]*stream),
		done:            make(chan struct{}),
		writeMessage: func(_ context.Context, frame []byte) error {
			written <- append([]byte(nil), frame...)
			return nil
		},
	}
	sess.authorized.Store(true)
	go sess.writeLoop()

	sess.terminateAuthorization(context.Background(), "expired", errors.New("session authorization expired"))

	if sess.authorized.Load() {
		t.Fatal("terminated authorization remained authorized")
	}
	select {
	case frameBytes := <-written:
		frame, err := contractv1.DecodeFrame(frameBytes)
		if err != nil {
			t.Fatalf("decode session_revoked frame: %v", err)
		}
		if frame.Kind != contractv1.KindControl || frame.StreamID != 0 {
			t.Fatalf("session_revoked frame scope kind=%v stream=%d", frame.Kind, frame.StreamID)
		}
		if err := contractv1.ValidateControlPayload(frame.Payload, frame.StreamID, time.Now().UTC()); err != nil {
			t.Fatalf("validate session_revoked payload: %v", err)
		}
		var revoked contractv1.SessionRevoked
		if err := json.Unmarshal(frame.Payload, &revoked); err != nil {
			t.Fatal(err)
		}
		if revoked.AuthorizationID != sess.authorizationID || revoked.ReasonCode != "expired" {
			t.Fatalf("session_revoked=%+v", revoked)
		}
	case <-time.After(time.Second):
		t.Fatal("session_revoked control frame was not written")
	}
	select {
	case <-sess.done:
	default:
		t.Fatal("session was not closed after session_revoked write")
	}
}
