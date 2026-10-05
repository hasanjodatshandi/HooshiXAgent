package gateway

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

type shortWriteConn struct{ bytes.Buffer }

func (conn *shortWriteConn) Write(data []byte) (int, error) {
	if len(data) > 2 {
		data = data[:2]
	}
	return conn.Buffer.Write(data)
}

func (conn *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (conn *shortWriteConn) Read([]byte) (int, error)         { return 0, nil }
func (conn *shortWriteConn) Close() error                     { return nil }
func (conn *shortWriteConn) LocalAddr() net.Addr              { return nil }
func (conn *shortWriteConn) RemoteAddr() net.Addr             { return nil }
func (conn *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (conn *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }

func TestPublicTCPWritesAllBytesAfterShortWrites(t *testing.T) {
	stream := newStream(context.Background(), 1, 2, 1024, newByteBudget(1024), newByteBudget(1024), nil)
	if err := stream.enqueue([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	stream.finish(nil)
	defer stream.discardRetained()
	manager := &PublicTCPManager{gateway: &Gateway{limits: DefaultLimits()}}
	conn := &shortWriteConn{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	phase := newResponsePhase(time.Second, cancel)
	defer phase.stop()
	if err := manager.writePublicTCP(ctx, conn, stream, phase); err != nil {
		t.Fatal(err)
	}
	if got := conn.String(); got != "abcdef" {
		t.Fatalf("forwarded %q, want abcdef", got)
	}
}

func TestPublicTCPListenerClosesWhenEndpointDisabled(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	source := NewSnapshotMetadata()
	record := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-public-1", OwnerDeviceID: "device-1",
		Protocol: contractv2.ProtocolTCP, ApplicationProtocol: contractv2.ApplicationGeneric, LocalEndpointID: "local-1",
		PublicPort: port, AllowedSourceCIDRs: []string{"127.0.0.0/8"}, Exposure: contractv2.ExposurePublic,
		Enabled: true, CreatedAt: "2026-09-28T08:00:00Z", Revision: 1,
	}
	source.serviceEndpoints[record.EndpointID] = record
	source.publicPorts[port] = record.EndpointID
	limits := DefaultLimits()
	gateway, err := New(source, nil, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPublicTCPManager(gateway, source, PublicTCPConfig{BindHost: "127.0.0.1", PortMin: port, PortMax: port, ReconcileInterval: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("enabled listener: %v", err)
	}
	_ = conn.Close()
	record.Enabled = false
	record.Revision++
	source.serviceEndpoints[record.EndpointID] = record
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("disabled endpoint still accepts TCP")
	}
}

func TestPublicTCPSourceCIDRPolicy(t *testing.T) {
	if !sourceAllowed(net.ParseIP("127.0.0.1"), []string{"127.0.0.0/8"}) {
		t.Fatal("allowed source was rejected")
	}
	if sourceAllowed(net.ParseIP("127.0.0.1"), []string{"192.0.2.0/24"}) {
		t.Fatal("source outside the allowlist was accepted")
	}
}

func TestPublicUDPListenerClosesWhenEndpointDisabled(t *testing.T) {
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	_ = reservation.Close()
	source := NewSnapshotMetadata()
	record := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-udp-public", OwnerDeviceID: "device-1",
		Protocol: contractv2.ProtocolUDP, LocalEndpointID: "local-udp", PublicPort: port,
		AllowedSourceCIDRs: []string{"127.0.0.0/8"}, Exposure: contractv2.ExposurePublic,
		Enabled: true, CreatedAt: "2026-09-28T08:00:00Z", Revision: 1,
	}
	source.serviceEndpoints[record.EndpointID] = record
	source.publicPorts[port] = record.EndpointID
	serverGateway, err := New(source, nil, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPublicUDPManager(serverGateway, source, PublicUDPConfig{BindHost: "127.0.0.1", PortMin: port, PortMax: port, ReconcileInterval: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if listener, err := net.ListenPacket("udp4", reservation.LocalAddr().String()); err == nil {
		_ = listener.Close()
		t.Fatal("enabled UDP port was not bound")
	}
	record.Enabled = false
	record.Revision++
	source.serviceEndpoints[record.EndpointID] = record
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", reservation.LocalAddr().String())
	if err != nil {
		t.Fatalf("disabled UDP port not released: %v", err)
	}
	_ = listener.Close()
}

func TestPublicUDPLiveMetadataRemovalReleasesListener(t *testing.T) {
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.LocalAddr().String()
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	_ = reservation.Close()
	root := t.TempDir()
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), nil, nil, nil)
	record := contractv2.ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: 2, EndpointID: "endpoint-live-udp", OwnerDeviceID: "device-1",
		Protocol: contractv2.ProtocolUDP, LocalEndpointID: "local-udp", PublicPort: port,
		AllowedSourceCIDRs: []string{"127.0.0.0/8"}, Exposure: contractv2.ExposurePublic,
		Enabled: true, CreatedAt: now.Truncate(time.Second).Format(time.RFC3339), Revision: 1,
	}
	if err := WriteSnapshotRecord(filepath.Join(root, "generations", "generation-1"), "service_endpoints", "endpoint.json", record); err != nil {
		t.Fatal(err)
	}
	metadata, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	serverGateway, err := New(metadata, nil, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPublicUDPManager(serverGateway, metadata, PublicUDPConfig{BindHost: "127.0.0.1", PortMin: port, PortMax: port, ReconcileInterval: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if listener, err := net.ListenPacket("udp4", address); err == nil {
		_ = listener.Close()
		t.Fatal("live UDP endpoint did not bind its port")
	}
	publishLiveGeneration(t, root, 2, "generation-2", now.Add(time.Second), now.Add(time.Hour), nil, nil, nil)
	if err := metadata.RefreshNow(); err != nil {
		t.Fatal(err)
	}
	if err := manager.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("removed live UDP endpoint retained its listener: %v", err)
	}
	_ = listener.Close()
}

func TestLiveMetadataLoadsOptionalServiceEndpointsAtomically(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), nil, nil, nil)
	record := contractv2.ServiceEndpoint{
		Kind:            "service_endpoint",
		ContractVersion: contractv2.ProtocolVersion,
		EndpointID:      "endpoint-1",
		OwnerDeviceID:   "device-1",
		Protocol:        contractv2.ProtocolHTTP,
		LocalEndpointID: "web-1",
		Exposure:        contractv2.ExposurePublic,
		Enabled:         true,
		CreatedAt:       "2026-09-27T08:00:00Z",
		Revision:        1,
	}
	if err := WriteSnapshotRecord(filepath.Join(root, "generations", "generation-1"), "service_endpoints", record.EndpointID+".json", record); err != nil {
		t.Fatal(err)
	}

	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	got, err := source.ServiceEndpoint(context.Background(), record.EndpointID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, record) {
		t.Fatalf("service endpoint mismatch: got %+v want %+v", got, record)
	}
}

func TestLiveMetadataRejectsInvalidServiceEndpointWithoutReplacingActiveGeneration(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), nil, nil, nil)
	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	publishLiveGeneration(t, root, 2, "generation-2", now.Add(time.Second), now.Add(time.Hour), nil, nil, nil)
	if err := WriteSnapshotRecord(filepath.Join(root, "generations", "generation-2"), "service_endpoints", "bad.json", map[string]any{
		"kind":              "service_endpoint",
		"contract_version":  2,
		"endpoint_id":       "endpoint-2",
		"owner_device_id":   "device-1",
		"protocol":          "rdp",
		"local_endpoint_id": "rdp-1",
		"exposure":          "private",
		"enabled":           true,
		"created_at":        "2026-09-27T08:00:00Z",
		"revision":          1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.RefreshNow(); err == nil {
		t.Fatal("invalid service endpoint generation was activated")
	}
	if stats := source.MetadataStats(now); stats.ActiveRevision != 1 {
		t.Fatalf("active revision changed after rejected generation: %+v", stats)
	}
}

func TestLiveMetadataLoadsAndExpiresConnectorGrant(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	publishLiveGeneration(t, root, 1, "generation-1", now, now.Add(time.Hour), nil, nil, nil)
	grant := contractv2.ConnectorGrant{
		Kind: "connector_grant", ContractVersion: contractv2.ProtocolVersion,
		GrantID: "grant-1", EndpointID: "endpoint-1", TokenID: "token-1",
		TokenSHA256: "abababababababababababababababababababababababababababababababab",
		NotBefore:   now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:   now.Add(time.Minute).Format(time.RFC3339), MaxConnections: 1,
	}
	if err := WriteSnapshotRecord(filepath.Join(root, "generations", "generation-1"), "connector_grants", grant.GrantID+".json", grant); err != nil {
		t.Fatal(err)
	}

	source, err := NewLiveMetadata(root, LiveMetadataOptions{RefreshInterval: time.Hour, MaxSnapshotAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	got, err := source.ConnectorGrant(context.Background(), grant.GrantID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != grant {
		t.Fatalf("connector grant mismatch: got %+v want %+v", got, grant)
	}
	if _, err := source.ConnectorGrant(context.Background(), grant.GrantID, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired connector grant was accepted")
	}
}
