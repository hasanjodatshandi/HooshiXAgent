package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestSnapshotDirectoryRejectsDuplicateAuthorizationIDs(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, _ := metadataRecords(identity, testRouteHost)
	if err := WriteSnapshotRecord(root, "authorizations", "a.json", authorization); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotRecord(root, "authorizations", "b.json", authorization); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil || !strings.Contains(err.Error(), "duplicate authorization_id") {
		t.Fatalf("duplicate authorization_id must fail snapshot load, got %v", err)
	}
}

func TestSnapshotDirectoryRejectsCanonicalDuplicateHostRoutes(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	_, route := metadataRecords(identity, testRouteHost)
	upper := route
	upper.AssignmentID = "assign-runtime-002"
	upper.EndpointID = "endpoint-runtime-002"
	upper.PublicHostname = strings.ToUpper(route.PublicHostname)
	if err := WriteSnapshotRecord(root, "routes", "a.json", route); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotRecord(root, "routes", "b.json", upper); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshotDirectory(root); err == nil || !strings.Contains(err.Error(), "duplicate public_hostname") {
		t.Fatalf("canonical duplicate public_hostname must fail snapshot load, got %v", err)
	}
}

func TestSnapshotMetadataRejectsMalformedAndDuplicateJSONMembers(t *testing.T) {
	identity := newTestIdentity(t)
	authorization, _ := metadataRecords(identity, testRouteHost)
	payload, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	needle := fmt.Sprintf(`"authorization_id":"%s"`, authorization.AuthorizationID)
	duplicate := strings.Replace(string(payload), needle, needle+","+needle, 1)

	source := NewSnapshotMetadata()
	if err := source.addAuthorizationJSON([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member name") {
		t.Fatalf("duplicate JSON member must be rejected, got %v", err)
	}
	if err := source.Ready(); err == nil {
		t.Fatal("snapshot with rejected malformed content must be not ready")
	}

	unknown := strings.TrimSuffix(string(payload), "}") + `,"unexpected":true}`
	other := NewSnapshotMetadata()
	if err := other.addAuthorizationJSON([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown metadata field must be rejected, got %v", err)
	}
}

func TestSnapshotMetadataParsesStaticRecordsButEvaluatesTimeAtUse(t *testing.T) {
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	authorization.IssuedAt = now.Add(-3 * time.Hour).Format(time.RFC3339)
	authorization.NotBefore = now.Add(-2 * time.Hour).Format(time.RFC3339)
	authorization.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
	route.NotBefore = now.Add(time.Hour).Format(time.RFC3339)
	route.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339)

	source := NewSnapshotMetadata()
	addJSONRecord(t, source.addAuthorizationJSON, authorization)
	addJSONRecord(t, source.addRouteJSON, route)
	if err := source.Ready(); err != nil {
		t.Fatalf("structurally valid inactive records must not make snapshot unusable: %v", err)
	}
	if _, err := source.Authorization(context.Background(), authorization.AuthorizationID, authorization.DeviceID, authorization.TokenID, now); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expired authorization must fail at use time, got %v", err)
	}
	if _, err := source.RouteByHostname(context.Background(), route.PublicHostname, now); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("future route must fail at use time, got %v", err)
	}
	if _, err := source.Authorization(context.Background(), authorization.AuthorizationID, authorization.DeviceID, authorization.TokenID, now.Add(-90*time.Minute)); err != nil {
		t.Fatalf("authorization should be valid inside cached time window: %v", err)
	}
	if _, err := source.RouteByHostname(context.Background(), route.PublicHostname, now.Add(90*time.Minute)); err != nil {
		t.Fatalf("route should be valid inside cached time window: %v", err)
	}
}

func TestSnapshotMetadataRevocationIndexEvaluatesEffectiveTimeAtUse(t *testing.T) {
	identity := newTestIdentity(t)
	authorization, _ := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	source := NewSnapshotMetadata()
	addJSONRecord(t, source.addAuthorizationJSON, authorization)
	addJSONRecord(t, source.addRevocationJSON, contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-r7-future",
		SubjectKind:     "device_session_authorization",
		SubjectID:       authorization.AuthorizationID,
		EffectiveAt:     now.Add(time.Minute).Format(time.RFC3339),
		ReasonCode:      "credential_revoked",
	})
	if _, err := source.Authorization(context.Background(), authorization.AuthorizationID, authorization.DeviceID, authorization.TokenID, now); err != nil {
		t.Fatalf("future revocation must not apply early: %v", err)
	}
	if _, err := source.Authorization(context.Background(), authorization.AuthorizationID, authorization.DeviceID, authorization.TokenID, now.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("effective revocation must fail closed at use time, got %v", err)
	}
}

func TestSnapshotMetadataRevocationIndexCollapsesEventsPerSubject(t *testing.T) {
	source := NewSnapshotMetadata()
	now := time.Now().UTC()
	for i := 0; i < 1000; i++ {
		addJSONRecord(t, source.addRevocationJSON, contractv1.RevocationSignal{
			ContractVersion: contractv1.ProtocolVersion,
			EventID:         fmt.Sprintf("revoke-r7-%04d", i),
			SubjectKind:     "device",
			SubjectID:       "device-r7-indexed",
			EffectiveAt:     now.Add(time.Duration(1000-i) * time.Second).Format(time.RFC3339),
			ReasonCode:      "security_hold",
		})
	}
	if got := len(source.revocations); got != 1 {
		t.Fatalf("revocation index entries=%d want=1 unique subject", got)
	}
	if revoked, err := source.Revoked(context.Background(), "device", "device-r7-indexed", now.Add(2*time.Second)); err != nil || !revoked {
		t.Fatalf("earliest effective revocation must be retained: revoked=%v err=%v", revoked, err)
	}
}

func TestGatewayReadinessFailsClosedForUnusableSnapshot(t *testing.T) {
	identity := newTestIdentity(t)
	authorization, _ := metadataRecords(identity, testRouteHost)
	source := NewSnapshotMetadata()
	addJSONRecord(t, source.addAuthorizationJSON, authorization)
	payload, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.addAuthorizationJSON(payload); err == nil {
		t.Fatal("duplicate authorization unexpectedly accepted")
	}

	gateway, err := New(source, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"status":"not_ready"}` {
		t.Fatalf("unusable metadata readiness status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func BenchmarkSnapshotMetadataLargeLookup(b *testing.B) {
	now := time.Now().UTC()
	source := NewSnapshotMetadata()
	source.authorizations["auth-r7-target"] = authorizationSnapshot{
		record: contractv1.DeviceSessionAuthorization{
			AuthorizationID: "auth-r7-target",
			DeviceID:        "device-r7-target",
			TokenID:         "token-r7-target",
		},
		notBefore: now.Add(-time.Hour),
		expiresAt: now.Add(time.Hour),
	}
	const subjects = 100000
	for i := 0; i < subjects; i++ {
		source.revocations[revocationSubject{kind: "device", id: fmt.Sprintf("device-r7-%06d", i)}] = now.Add(-time.Hour)
	}
	b.ReportMetric(subjects, "revocation_subjects")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := source.Authorization(context.Background(), "auth-r7-target", "device-r7-target", "token-r7-target", now); err != nil {
			b.Fatal(err)
		}
	}
}

func addJSONRecord(t *testing.T, add func([]byte) error, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := add(payload); err != nil {
		t.Fatal(err)
	}
}
