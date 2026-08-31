package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestLiveMetadataPollingActivatesCompleteGenerationAtomically(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)

	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: 20 * time.Millisecond, MaxSnapshotAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.Ready(); err != nil {
		t.Fatalf("initial generation not ready: %v", err)
	}

	nextRoute := route
	nextRoute.AssignmentID = "assign-runtime-002"
	nextRoute.EndpointID = "endpoint-runtime-002"
	nextRoute.PublicHostname = "next.hooshix.test"
	publishLiveGeneration(t, root, 2, "generation-2", time.Now().UTC(), time.Now().UTC().Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{nextRoute}, nil)

	waitFor(t, time.Second, func() bool {
		loaded, err := source.RouteByHostname(context.Background(), nextRoute.PublicHostname, time.Now().UTC())
		return err == nil && loaded.AssignmentID == nextRoute.AssignmentID
	})
	if _, err := source.RouteByHostname(context.Background(), route.PublicHostname, time.Now().UTC()); !errors.Is(err, ErrMetadataNotFound) {
		t.Fatalf("old route survived complete generation swap: %v", err)
	}
	stats := source.MetadataStats(time.Now().UTC())
	if stats.ActiveRevision != 2 || !stats.Fresh {
		t.Fatalf("stats after activation=%+v", stats)
	}
	gateway, err := New(source, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	for _, name := range []string{"hooshix_gateway_metadata_fresh", "hooshix_gateway_metadata_snapshot_age_seconds", "hooshix_gateway_metadata_refresh_successes_total", "hooshix_gateway_metadata_refresh_failures_total"} {
		if !strings.Contains(metrics.Body.String(), name) {
			t.Fatalf("live metadata metric %q missing", name)
		}
	}
	if strings.Contains(metrics.Body.String(), "{") {
		t.Fatal("live metadata metrics unexpectedly contain labels")
	}
}

func TestLiveMetadataRejectsMalformedReplayAndSameRevisionMutation(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	nextRoute := route
	nextRoute.AssignmentID = "assign-runtime-002"
	nextRoute.EndpointID = "endpoint-runtime-002"
	nextRoute.PublicHostname = "next.hooshix.test"
	publishLiveGeneration(t, root, 2, "generation-2", now.Add(time.Second), now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{nextRoute}, nil)
	if err := source.RefreshNow(); err != nil {
		t.Fatalf("activate revision 2: %v", err)
	}
	activeDigest := source.active.Load().digest

	// A malformed higher revision never partially replaces the active generation.
	badRoot := filepath.Join(root, "generations", "generation-3")
	if err := os.MkdirAll(filepath.Join(badRoot, "authorizations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(badRoot, "revocations"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeLiveManifest(t, root, MetadataGenerationManifest{ContractVersion: contractv1.ProtocolVersion, Revision: 3, Generation: "generation-3", PublishedAt: time.Now().UTC().Format(time.RFC3339Nano), ValidUntil: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)})
	if err := source.RefreshNow(); err == nil {
		t.Fatal("incomplete generation unexpectedly activated")
	}
	assertLiveRoute(t, source, nextRoute.PublicHostname, nextRoute.AssignmentID)

	// Lower revisions are replay/rollback and cannot replace the active authority.
	writeLiveManifest(t, root, MetadataGenerationManifest{ContractVersion: contractv1.ProtocolVersion, Revision: 1, Generation: "generation-1", PublishedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(time.Hour).Format(time.RFC3339Nano)})
	if err := source.RefreshNow(); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("rollback revision accepted: %v", err)
	}
	assertLiveRoute(t, source, nextRoute.PublicHostname, nextRoute.AssignmentID)

	// Reusing the accepted revision after mutating immutable generation content is rejected.
	mutated := nextRoute
	mutated.LocalEndpointID = "local-mutated"
	writeJSONFile(t, filepath.Join(root, "generations", "generation-2", "routes", "route-000000.json"), mutated)
	writeLiveManifest(t, root, MetadataGenerationManifest{ContractVersion: contractv1.ProtocolVersion, Revision: 2, Generation: "generation-2", PublishedAt: now.Add(time.Second).Format(time.RFC3339Nano), ValidUntil: now.Add(time.Hour).Format(time.RFC3339Nano)})
	if err := source.RefreshNow(); err == nil || !strings.Contains(err.Error(), "different manifest or content") {
		t.Fatalf("same-revision mutation accepted: %v", err)
	}
	if got := source.active.Load().digest; got != activeDigest {
		t.Fatalf("rejected candidate changed active digest")
	}
	assertLiveRoute(t, source, nextRoute.PublicHostname, nextRoute.AssignmentID)
}

func TestLiveMetadataStaleFailsClosedAndNewGenerationRecoversReadiness(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: 50 * time.Millisecond, MaxSnapshotAge: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	gateway, err := New(source, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool { return source.Ready() != nil })
	if _, err := source.Authorization(context.Background(), identity.authorizationID, identity.deviceID, identity.tokenID, time.Now().UTC()); !errors.Is(err, ErrMetadataStale) {
		t.Fatalf("stale authorization did not fail closed: %v", err)
	}
	if _, err := source.RouteByHostname(context.Background(), route.PublicHostname, time.Now().UTC()); !errors.Is(err, ErrMetadataStale) {
		t.Fatalf("stale route did not fail closed: %v", err)
	}
	ready := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "https://gateway.test/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale readiness status=%d want=%d", ready.Code, http.StatusServiceUnavailable)
	}

	publishLiveGeneration(t, root, 2, "generation-2", time.Now().UTC(), time.Now().UTC().Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	waitFor(t, time.Second, func() bool {
		return source.Ready() == nil && source.MetadataStats(time.Now().UTC()).ActiveRevision == 2
	})
	ready = httptest.NewRecorder()
	gateway.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "https://gateway.test/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("recovered readiness status=%d want=%d", ready.Code, http.StatusOK)
	}
}

func TestLiveMetadataRevocationTerminatesExistingSessionWithinBound(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: 25 * time.Millisecond, MaxSnapshotAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	limits := DefaultLimits()
	limits.HeartbeatInterval = 5 * time.Second
	limits.IdleTimeout = 15 * time.Second
	gateway, err := New(source, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	agent := connectMockAgent(t, context.Background(), server.URL, server.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	revocation := contractv1.RevocationSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "revoke-live-runtime-001",
		SubjectKind:     "device_session_authorization",
		SubjectID:       identity.authorizationID,
		EffectiveAt:     time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano),
		ReasonCode:      "credential_revoked",
	}
	publishLiveGeneration(t, root, 2, "generation-2", time.Now().UTC(), time.Now().UTC().Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, []contractv1.RevocationSignal{revocation})
	waitFor(t, time.Second, func() bool { return source.MetadataStats(time.Now().UTC()).ActiveRevision == 2 })
	waitFor(t, 7*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) == nil })
}

type midHandshakeAuthorizationMetadata struct {
	MetadataSource
	calls      atomic.Int32
	initial    contractv1.DeviceSessionAuthorization
	updated    contractv1.DeviceSessionAuthorization
	updatedErr error
}

func (source *midHandshakeAuthorizationMetadata) Authorization(context.Context, string, string, string, time.Time) (contractv1.DeviceSessionAuthorization, error) {
	if source.calls.Add(1) == 1 {
		return source.initial, nil
	}
	return source.updated, source.updatedErr
}

func TestHandshakeRevalidatesLiveAuthorizationBeforeSessionRegistration(t *testing.T) {
	identity := newTestIdentity(t)
	initial, _ := metadataRecords(identity, testRouteHost)
	updated := initial
	updated.Disabled = true
	source := &midHandshakeAuthorizationMetadata{
		MetadataSource: testMetadata(t, identity, testRouteHost),
		initial:        initial,
		updated:        updated,
		updatedErr:     errors.New("authorization is disabled"),
	}
	gateway, err := New(source, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()
	conn := dialRawAgent(t, server.Client(), server.URL)
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hello := clientHello(identity)
	if err := sendHello(ctx, conn, hello, 1); err != nil {
		t.Fatal(err)
	}
	challengeFrame := readFrameForTest(t, ctx, conn)
	var challenge contractv1.ServerChallenge
	if err := json.Unmarshal(challengeFrame.Payload, &challenge); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(identity.privateKey, contractv1.AuthTranscript(hello, challenge))
	auth := contractv1.ClientAuth{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "client_auth",
		SessionID:       challenge.SessionID,
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
	}
	if err := writeControlFrame(ctx, conn, 2, 0, auth); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(ctx, conn); err == nil {
		t.Fatal("authorization disabled during challenge still received session_ready")
	}
	if source.calls.Load() < 2 {
		t.Fatalf("authorization was not revalidated after challenge: calls=%d", source.calls.Load())
	}
	if gateway.sessionForDevice(identity.deviceID) != nil {
		t.Fatal("authorization disabled during challenge became routable")
	}
}

func TestLiveMetadataColdStartFailClosedThenRecovers(t *testing.T) {
	root := t.TempDir()
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: 20 * time.Millisecond, MaxSnapshotAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if !errors.Is(source.Ready(), ErrMetadataUnavailable) {
		t.Fatalf("cold start without current.json must be unavailable, got %v", source.Ready())
	}

	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	publishLiveGeneration(t, root, 1, "generation-1", time.Now().UTC(), time.Now().UTC().Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	waitFor(t, time.Second, func() bool { return source.Ready() == nil })
}

func TestLiveMetadataAuthorizationUpdateBecomesActiveWithoutRestart(t *testing.T) {
	root := t.TempDir()
	identity := newTestIdentity(t)
	authorization, route := metadataRecords(identity, testRouteHost)
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), []contractv1.DeviceSessionAuthorization{authorization}, []contractv1.EndpointRouteAssignment{route}, nil)
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	disabled := authorization
	disabled.Disabled = true
	publishLiveGeneration(t, root, 2, "generation-2", time.Now().UTC(), time.Now().UTC().Add(time.Hour), []contractv1.DeviceSessionAuthorization{disabled}, []contractv1.EndpointRouteAssignment{route}, nil)
	if err := source.RefreshNow(); err != nil {
		t.Fatal(err)
	}
	record, err := source.Authorization(context.Background(), identity.authorizationID, identity.deviceID, identity.tokenID, time.Now().UTC())
	if err == nil || !record.Disabled {
		t.Fatalf("live disabled authorization not enforced: record=%+v err=%v", record, err)
	}
}

func publishLiveGeneration(t *testing.T, root string, revision uint64, generation string, publishedAt, validUntil time.Time, authorizations []contractv1.DeviceSessionAuthorization, routes []contractv1.EndpointRouteAssignment, revocations []contractv1.RevocationSignal) {
	t.Helper()
	generationRoot := filepath.Join(root, "generations", generation)
	for _, category := range []string{"authorizations", "routes", "revocations"} {
		if err := os.MkdirAll(filepath.Join(generationRoot, category), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for i, record := range authorizations {
		writeJSONFile(t, filepath.Join(generationRoot, "authorizations", formatMetadataTestName("authorization", i)), record)
	}
	for i, record := range routes {
		writeJSONFile(t, filepath.Join(generationRoot, "routes", formatMetadataTestName("route", i)), record)
	}
	for i, record := range revocations {
		writeJSONFile(t, filepath.Join(generationRoot, "revocations", formatMetadataTestName("revocation", i)), record)
	}
	writeLiveManifest(t, root, MetadataGenerationManifest{
		ContractVersion: contractv1.ProtocolVersion,
		Revision:        revision,
		Generation:      generation,
		PublishedAt:     publishedAt.Format(time.RFC3339Nano),
		ValidUntil:      validUntil.Format(time.RFC3339Nano),
	})
}

func writeLiveManifest(t *testing.T, root string, manifest MetadataGenerationManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "current.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(root, "current.json")); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func formatMetadataTestName(prefix string, index int) string {
	return fmt.Sprintf("%s-%06d.json", prefix, index)
}

func assertLiveRoute(t *testing.T, source *LiveMetadata, hostname, assignmentID string) {
	t.Helper()
	route, err := source.RouteByHostname(context.Background(), hostname, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if route.AssignmentID != assignmentID {
		t.Fatalf("assignment=%q want=%q", route.AssignmentID, assignmentID)
	}
}
