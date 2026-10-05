package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

var ErrMetadataNotFound = errors.New("external metadata not found")

type MetadataSource interface {
	Authorization(ctx context.Context, authorizationID, deviceID, tokenID string, at time.Time) (contractv1.DeviceSessionAuthorization, error)
	RouteByHostname(ctx context.Context, hostname string, at time.Time) (contractv1.EndpointRouteAssignment, error)
	Revoked(ctx context.Context, subjectKind, subjectID string, at time.Time) (bool, error)
}

// PrivateEndpointMetadata is the v2 authority required by Connector ingress.
// It stays separate so existing v1 metadata adapters remain source-compatible.
type PrivateEndpointMetadata interface {
	ServiceEndpoint(ctx context.Context, endpointID string, at time.Time) (contractv2.ServiceEndpoint, error)
	ConnectorGrant(ctx context.Context, grantID string, at time.Time) (contractv2.ConnectorGrant, error)
}

// PublicTCPMetadata is the authority used to reconcile public TCP listeners.
type PublicTCPMetadata interface {
	ServiceEndpoint(ctx context.Context, endpointID string, at time.Time) (contractv2.ServiceEndpoint, error)
	PublicTCPEndpoints(ctx context.Context, at time.Time) ([]contractv2.ServiceEndpoint, error)
}

type PublicUDPMetadata interface {
	PublicUDPEndpoints(ctx context.Context, at time.Time) ([]contractv2.ServiceEndpoint, error)
}

type StatusSink interface {
	Emit(ctx context.Context, signal contractv1.GatewayStatusSignal) error
}

type NopStatusSink struct{}

func (NopStatusSink) Emit(context.Context, contractv1.GatewayStatusSignal) error { return nil }

type JSONLineStatusSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLineStatusSink(w io.Writer) *JSONLineStatusSink {
	return &JSONLineStatusSink{w: w}
}

func (sink *JSONLineStatusSink) Emit(_ context.Context, signal contractv1.GatewayStatusSignal) error {
	if sink == nil || sink.w == nil {
		return nil
	}
	payload, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	_, err = fmt.Fprintf(sink.w, "%s\n", payload)
	return err
}

type authorizationSnapshot struct {
	record    contractv1.DeviceSessionAuthorization
	notBefore time.Time
	expiresAt time.Time
}

type routeSnapshot struct {
	record    contractv1.EndpointRouteAssignment
	notBefore time.Time
	expiresAt time.Time
}

type revocationSubject struct {
	kind string
	id   string
}

type SnapshotMetadata struct {
	authorizations    map[string]authorizationSnapshot
	routes            map[string]routeSnapshot
	revocations       map[revocationSubject]time.Time
	revocationReasons map[revocationSubject]string
	serviceEndpoints  map[string]contractv2.ServiceEndpoint
	publicPorts       map[int]string
	connectorGrants   map[string]contractv2.ConnectorGrant
	readyErr          error
}

func NewSnapshotMetadata() *SnapshotMetadata {
	return &SnapshotMetadata{
		authorizations:    make(map[string]authorizationSnapshot),
		routes:            make(map[string]routeSnapshot),
		revocations:       make(map[revocationSubject]time.Time),
		revocationReasons: make(map[revocationSubject]string),
		serviceEndpoints:  make(map[string]contractv2.ServiceEndpoint),
		publicPorts:       make(map[int]string),
		connectorGrants:   make(map[string]contractv2.ConnectorGrant),
	}
}

func LoadSnapshotDirectory(root string) (*SnapshotMetadata, error) {
	if err := validateTrustedMetadataDirectory(root, false); err != nil {
		return nil, fmt.Errorf("validate metadata root: %w", err)
	}
	source := NewSnapshotMetadata()
	for _, spec := range []struct {
		dir string
		fn  func([]byte) error
	}{
		{dir: "authorizations", fn: source.addAuthorizationJSON},
		{dir: "routes", fn: source.addRouteJSON},
		{dir: "revocations", fn: source.addRevocationJSON},
		{dir: "service_endpoints", fn: source.addServiceEndpointJSON},
		{dir: "connector_grants", fn: source.addConnectorGrantJSON},
	} {
		dir := filepath.Join(root, spec.dir)
		if err := validateTrustedMetadataDirectory(dir, true); err != nil {
			return nil, fmt.Errorf("validate metadata directory %s: %w", dir, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read metadata directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				continue
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("metadata JSON entry %s must be a regular non-symlink file", entry.Name())
			}
			data, err := readTrustedMetadataFile(filepath.Join(dir, entry.Name()), maxMetadataRecordBytes)
			if err != nil {
				return nil, fmt.Errorf("read metadata file %s: %w", entry.Name(), err)
			}
			if err := spec.fn(data); err != nil {
				return nil, fmt.Errorf("load metadata file %s: %w", entry.Name(), err)
			}
		}
	}
	return source, nil
}

func (source *SnapshotMetadata) Ready() error {
	if source == nil {
		return errors.New("external metadata snapshot is unavailable")
	}
	if source.readyErr != nil {
		return fmt.Errorf("external metadata snapshot is unusable: %w", source.readyErr)
	}
	return nil
}

func (source *SnapshotMetadata) invalidate(err error) error {
	if source.readyErr == nil {
		source.readyErr = err
	}
	return err
}

func (source *SnapshotMetadata) addAuthorizationJSON(data []byte) error {
	record, err := contractv1.ParseDeviceSessionAuthorizationRecord(data)
	if err != nil {
		return source.invalidate(err)
	}
	notBefore, err := time.Parse(time.RFC3339, record.NotBefore)
	if err != nil {
		return source.invalidate(fmt.Errorf("parse authorization not_before: %w", err))
	}
	expiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return source.invalidate(fmt.Errorf("parse authorization expires_at: %w", err))
	}
	if _, exists := source.authorizations[record.AuthorizationID]; exists {
		return source.invalidate(fmt.Errorf("duplicate authorization_id %q", record.AuthorizationID))
	}
	source.authorizations[record.AuthorizationID] = authorizationSnapshot{
		record:    record,
		notBefore: notBefore,
		expiresAt: expiresAt,
	}
	return nil
}

func (source *SnapshotMetadata) addRouteJSON(data []byte) error {
	record, err := contractv1.ParseEndpointRouteAssignmentRecord(data)
	if err != nil {
		return source.invalidate(err)
	}
	host := canonicalHostname(record.PublicHostname)
	if host == "" {
		return source.invalidate(errors.New("public_hostname is required"))
	}
	notBefore, err := time.Parse(time.RFC3339, record.NotBefore)
	if err != nil {
		return source.invalidate(fmt.Errorf("parse route not_before: %w", err))
	}
	expiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return source.invalidate(fmt.Errorf("parse route expires_at: %w", err))
	}
	if _, exists := source.routes[host]; exists {
		return source.invalidate(fmt.Errorf("duplicate public_hostname %q", host))
	}
	source.routes[host] = routeSnapshot{
		record:    record,
		notBefore: notBefore,
		expiresAt: expiresAt,
	}
	return nil
}

func (source *SnapshotMetadata) addRevocationJSON(data []byte) error {
	signal, err := contractv1.ParseRevocationSignal(data)
	if err != nil {
		return source.invalidate(err)
	}
	effectiveAt, err := time.Parse(time.RFC3339, signal.EffectiveAt)
	if err != nil {
		return source.invalidate(fmt.Errorf("parse revocation effective_at: %w", err))
	}
	subject := revocationSubject{kind: signal.SubjectKind, id: signal.SubjectID}
	if current, exists := source.revocations[subject]; !exists || effectiveAt.Before(current) {
		source.revocations[subject] = effectiveAt
		source.revocationReasons[subject] = signal.ReasonCode
	}
	return nil
}

func (source *SnapshotMetadata) addServiceEndpointJSON(data []byte) error {
	record, err := contractv2.ParseServiceEndpoint(data)
	if err != nil {
		return source.invalidate(err)
	}
	if _, exists := source.serviceEndpoints[record.EndpointID]; exists {
		return source.invalidate(fmt.Errorf("duplicate service endpoint %q", record.EndpointID))
	}
	if record.PublicPort != 0 {
		if endpointID, exists := source.publicPorts[record.PublicPort]; exists {
			return source.invalidate(fmt.Errorf("public port %d is assigned to both %q and %q", record.PublicPort, endpointID, record.EndpointID))
		}
		source.publicPorts[record.PublicPort] = record.EndpointID
	}
	source.serviceEndpoints[record.EndpointID] = record
	return nil
}

func (source *SnapshotMetadata) PublicTCPEndpoints(ctx context.Context, at time.Time) ([]contractv2.ServiceEndpoint, error) {
	return source.publicEndpoints(ctx, at, contractv2.ProtocolTCP), nil
}

func (source *SnapshotMetadata) PublicUDPEndpoints(ctx context.Context, at time.Time) ([]contractv2.ServiceEndpoint, error) {
	return source.publicEndpoints(ctx, at, contractv2.ProtocolUDP), nil
}

func (source *SnapshotMetadata) publicEndpoints(ctx context.Context, at time.Time, protocol contractv2.Protocol) []contractv2.ServiceEndpoint {
	records := make([]contractv2.ServiceEndpoint, 0, len(source.publicPorts))
	for _, endpointID := range source.publicPorts {
		record, err := source.ServiceEndpoint(ctx, endpointID, at)
		if err != nil || record.Protocol != protocol {
			continue
		}
		records = append(records, record)
	}
	return records
}

func (source *SnapshotMetadata) ServiceEndpoint(_ context.Context, endpointID string, at time.Time) (contractv2.ServiceEndpoint, error) {
	record, ok := source.serviceEndpoints[endpointID]
	if !ok {
		return contractv2.ServiceEndpoint{}, ErrMetadataNotFound
	}
	if !record.Enabled {
		return record, errors.New("service endpoint is disabled")
	}
	if source.revokedAt(revocationSubject{kind: "device", id: record.OwnerDeviceID}, at) {
		return record, errors.New("service endpoint owner is revoked")
	}
	return record, nil
}

func (source *SnapshotMetadata) addConnectorGrantJSON(data []byte) error {
	record, err := contractv2.ParseConnectorGrant(data)
	if err != nil {
		return source.invalidate(err)
	}
	if _, exists := source.connectorGrants[record.GrantID]; exists {
		return source.invalidate(fmt.Errorf("duplicate connector grant %q", record.GrantID))
	}
	source.connectorGrants[record.GrantID] = record
	return nil
}

func (source *SnapshotMetadata) ConnectorGrant(_ context.Context, grantID string, at time.Time) (contractv2.ConnectorGrant, error) {
	record, ok := source.connectorGrants[grantID]
	if !ok {
		return contractv2.ConnectorGrant{}, ErrMetadataNotFound
	}
	if record.Disabled {
		return record, errors.New("connector grant is disabled")
	}
	notBefore, err := time.Parse(time.RFC3339Nano, record.NotBefore)
	if err != nil {
		return record, errors.New("connector grant not_before is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil {
		return record, errors.New("connector grant expires_at is invalid")
	}
	if at.Before(notBefore) || !at.Before(expiresAt) {
		return record, errors.New("connector grant is not active at evaluation time")
	}
	return record, nil
}

func (source *SnapshotMetadata) Authorization(_ context.Context, authorizationID, deviceID, tokenID string, at time.Time) (contractv1.DeviceSessionAuthorization, error) {
	entry, ok := source.authorizations[authorizationID]
	if !ok {
		return contractv1.DeviceSessionAuthorization{}, ErrMetadataNotFound
	}
	record := entry.record
	if record.Disabled {
		return record, errors.New("authorization is disabled")
	}
	if at.Before(entry.notBefore) || !at.Before(entry.expiresAt) {
		return record, errors.New("authorization is not active at evaluation time")
	}
	if record.DeviceID != deviceID || record.TokenID != tokenID {
		return record, errors.New("authorization subject mismatch")
	}
	for _, subject := range []revocationSubject{
		{kind: "device_session_authorization", id: record.AuthorizationID},
		{kind: "device", id: record.DeviceID},
	} {
		if source.revokedAt(subject, at) {
			return record, errors.New("authorization subject is revoked")
		}
	}
	return record, nil
}

func (source *SnapshotMetadata) RouteByHostname(_ context.Context, hostname string, at time.Time) (contractv1.EndpointRouteAssignment, error) {
	entry, ok := source.routes[canonicalHostname(hostname)]
	if !ok {
		return contractv1.EndpointRouteAssignment{}, ErrMetadataNotFound
	}
	record := entry.record
	if !record.Enabled {
		return record, errors.New("route assignment is disabled")
	}
	if at.Before(entry.notBefore) || !at.Before(entry.expiresAt) {
		return record, errors.New("route assignment is not active at evaluation time")
	}
	for _, subject := range []revocationSubject{
		{kind: "endpoint_route_assignment", id: record.AssignmentID},
		{kind: "device", id: record.DeviceID},
	} {
		if source.revokedAt(subject, at) {
			return record, errors.New("route subject is revoked")
		}
	}
	return record, nil
}

func (source *SnapshotMetadata) Revoked(_ context.Context, subjectKind, subjectID string, at time.Time) (bool, error) {
	return source.revokedAt(revocationSubject{kind: subjectKind, id: subjectID}, at), nil
}

func (source *SnapshotMetadata) RevocationReason(_ context.Context, subjectKind, subjectID string, at time.Time) (string, bool, error) {
	subject := revocationSubject{kind: subjectKind, id: subjectID}
	if !source.revokedAt(subject, at) {
		return "", false, nil
	}
	reason := source.revocationReasons[subject]
	if reason == "" {
		reason = "credential_revoked"
	}
	return reason, true, nil
}

func (source *SnapshotMetadata) revokedAt(subject revocationSubject, at time.Time) bool {
	effectiveAt, ok := source.revocations[subject]
	return ok && !effectiveAt.After(at)
}

func WriteSnapshotRecord(root, category, name string, value any) error {
	dir := filepath.Join(root, category)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return writer.Flush()
}

func canonicalHostname(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if index := strings.IndexByte(value, ':'); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSuffix(value, ".")
}
