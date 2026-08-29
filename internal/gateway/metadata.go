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
)

var ErrMetadataNotFound = errors.New("external metadata not found")

type MetadataSource interface {
	Authorization(ctx context.Context, authorizationID, deviceID, tokenID string, at time.Time) (contractv1.DeviceSessionAuthorization, error)
	RouteByHostname(ctx context.Context, hostname string, at time.Time) (contractv1.EndpointRouteAssignment, error)
	Revoked(ctx context.Context, subjectKind, subjectID string, at time.Time) (bool, error)
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

type SnapshotMetadata struct {
	authorizations map[string][]byte
	routes         map[string][]byte
	revocations    []contractv1.RevocationSignal
}

func NewSnapshotMetadata() *SnapshotMetadata {
	return &SnapshotMetadata{
		authorizations: make(map[string][]byte),
		routes:         make(map[string][]byte),
	}
}

func LoadSnapshotDirectory(root string) (*SnapshotMetadata, error) {
	source := NewSnapshotMetadata()
	for _, spec := range []struct {
		dir string
		fn  func([]byte) error
	}{
		{dir: "authorizations", fn: source.addAuthorizationJSON},
		{dir: "routes", fn: source.addRouteJSON},
		{dir: "revocations", fn: source.addRevocationJSON},
	} {
		dir := filepath.Join(root, spec.dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read metadata directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
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

func (source *SnapshotMetadata) addAuthorizationJSON(data []byte) error {
	var envelope struct {
		AuthorizationID string `json:"authorization_id"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.AuthorizationID == "" {
		return errors.New("authorization_id is required")
	}
	source.authorizations[envelope.AuthorizationID] = append([]byte(nil), data...)
	return nil
}

func (source *SnapshotMetadata) addRouteJSON(data []byte) error {
	var envelope struct {
		PublicHostname string `json:"public_hostname"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	host := canonicalHostname(envelope.PublicHostname)
	if host == "" {
		return errors.New("public_hostname is required")
	}
	source.routes[host] = append([]byte(nil), data...)
	return nil
}

func (source *SnapshotMetadata) addRevocationJSON(data []byte) error {
	signal, err := contractv1.ParseRevocationSignal(data)
	if err != nil {
		return err
	}
	source.revocations = append(source.revocations, signal)
	return nil
}

func (source *SnapshotMetadata) Authorization(_ context.Context, authorizationID, deviceID, tokenID string, at time.Time) (contractv1.DeviceSessionAuthorization, error) {
	data, ok := source.authorizations[authorizationID]
	if !ok {
		return contractv1.DeviceSessionAuthorization{}, ErrMetadataNotFound
	}
	record, err := contractv1.ParseDeviceSessionAuthorization(data, at)
	if err != nil {
		return record, err
	}
	if record.DeviceID != deviceID || record.TokenID != tokenID {
		return record, errors.New("authorization subject mismatch")
	}
	for _, subject := range []struct{ kind, id string }{{"device_session_authorization", record.AuthorizationID}, {"device", record.DeviceID}} {
		revoked, err := source.Revoked(context.Background(), subject.kind, subject.id, at)
		if err != nil {
			return record, err
		}
		if revoked {
			return record, errors.New("authorization subject is revoked")
		}
	}
	return record, nil
}

func (source *SnapshotMetadata) RouteByHostname(_ context.Context, hostname string, at time.Time) (contractv1.EndpointRouteAssignment, error) {
	data, ok := source.routes[canonicalHostname(hostname)]
	if !ok {
		return contractv1.EndpointRouteAssignment{}, ErrMetadataNotFound
	}
	record, err := contractv1.ParseEndpointRouteAssignment(data, at)
	if err != nil {
		return record, err
	}
	for _, subject := range []struct{ kind, id string }{{"endpoint_route_assignment", record.AssignmentID}, {"device", record.DeviceID}} {
		revoked, err := source.Revoked(context.Background(), subject.kind, subject.id, at)
		if err != nil {
			return record, err
		}
		if revoked {
			return record, errors.New("route subject is revoked")
		}
	}
	return record, nil
}

func (source *SnapshotMetadata) Revoked(_ context.Context, subjectKind, subjectID string, at time.Time) (bool, error) {
	for _, signal := range source.revocations {
		if signal.SubjectKind != subjectKind || signal.SubjectID != subjectID {
			continue
		}
		effectiveAt, err := time.Parse(time.RFC3339, signal.EffectiveAt)
		if err != nil {
			return false, err
		}
		if !effectiveAt.After(at) {
			return true, nil
		}
	}
	return false, nil
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
