package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const (
	DefaultMetadataRefreshInterval = time.Second
	DefaultMetadataMaxSnapshotAge  = 30 * time.Second
	maxMetadataManifestBytes       = 16 << 10
	maxMetadataRecordBytes         = 1 << 20
	maxLiveMetadataRecords         = 100_000
	maxLiveGenerationBytes         = 64 << 20
	maxMetadataFutureSkew          = 30 * time.Second
)

var (
	ErrMetadataUnavailable = errors.New("live external metadata is unavailable")
	ErrMetadataStale       = errors.New("live external metadata is stale")
)

type MetadataGenerationManifest struct {
	ContractVersion int    `json:"contract_version"`
	Revision        uint64 `json:"revision"`
	Generation      string `json:"generation"`
	PublishedAt     string `json:"published_at"`
	ValidUntil      string `json:"valid_until"`
}

type LiveMetadataOptions struct {
	RefreshInterval time.Duration
	MaxSnapshotAge  time.Duration
	Logger          *slog.Logger
}

type LiveMetadataStats struct {
	ActiveRevision   uint64
	Fresh            bool
	SnapshotAge      time.Duration
	RefreshSuccesses uint64
	RefreshFailures  uint64
}

type liveMetadataGeneration struct {
	snapshot    *SnapshotMetadata
	revision    uint64
	generation  string
	publishedAt time.Time
	validUntil  time.Time
	deadline    time.Time
	digest      [sha256.Size]byte
}

type LiveMetadata struct {
	root            string
	refreshInterval time.Duration
	maxSnapshotAge  time.Duration
	logger          *slog.Logger

	active atomic.Pointer[liveMetadataGeneration]

	refreshMu      sync.Mutex
	lastErrorText  string
	lastErrorLogAt time.Time

	refreshSuccesses atomic.Uint64
	refreshFailures  atomic.Uint64

	cancel context.CancelFunc
	done   chan struct{}
}

func NewLiveMetadata(root string, options LiveMetadataOptions) (*LiveMetadata, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("live metadata root is required")
	}
	if err := validateTrustedMetadataDirectory(root, false); err != nil {
		return nil, fmt.Errorf("validate live metadata root: %w", err)
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = DefaultMetadataRefreshInterval
	}
	if options.MaxSnapshotAge <= 0 {
		options.MaxSnapshotAge = DefaultMetadataMaxSnapshotAge
	}
	if options.RefreshInterval > options.MaxSnapshotAge {
		return nil, errors.New("metadata refresh interval must not exceed maximum snapshot age")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ctx, cancel := context.WithCancel(context.Background())
	source := &LiveMetadata{
		root:            filepath.Clean(root),
		refreshInterval: options.RefreshInterval,
		maxSnapshotAge:  options.MaxSnapshotAge,
		logger:          options.Logger,
		cancel:          cancel,
		done:            make(chan struct{}),
	}
	_ = source.refreshAt(time.Now().UTC())
	go source.refreshLoop(ctx)
	return source, nil
}

func (source *LiveMetadata) Close() error {
	if source == nil || source.cancel == nil {
		return nil
	}
	source.cancel()
	<-source.done
	return nil
}

func (source *LiveMetadata) RefreshNow() error {
	if source == nil {
		return ErrMetadataUnavailable
	}
	return source.refreshAt(time.Now().UTC())
}

func (source *LiveMetadata) Ready() error {
	_, err := source.activeSnapshot(time.Now().UTC())
	return err
}

func (source *LiveMetadata) MetadataStats(at time.Time) LiveMetadataStats {
	stats := LiveMetadataStats{
		RefreshSuccesses: source.refreshSuccesses.Load(),
		RefreshFailures:  source.refreshFailures.Load(),
	}
	active := source.active.Load()
	if active == nil {
		return stats
	}
	stats.ActiveRevision = active.revision
	stats.Fresh = at.Before(active.deadline)
	if at.After(active.publishedAt) {
		stats.SnapshotAge = at.Sub(active.publishedAt)
	}
	return stats
}

func (source *LiveMetadata) Authorization(ctx context.Context, authorizationID, deviceID, tokenID string, at time.Time) (contractv1.DeviceSessionAuthorization, error) {
	active, err := source.activeSnapshot(at)
	if err != nil {
		return contractv1.DeviceSessionAuthorization{}, err
	}
	return active.Authorization(ctx, authorizationID, deviceID, tokenID, at)
}

func (source *LiveMetadata) RouteByHostname(ctx context.Context, hostname string, at time.Time) (contractv1.EndpointRouteAssignment, error) {
	active, err := source.activeSnapshot(at)
	if err != nil {
		return contractv1.EndpointRouteAssignment{}, err
	}
	return active.RouteByHostname(ctx, hostname, at)
}

func (source *LiveMetadata) Revoked(ctx context.Context, subjectKind, subjectID string, at time.Time) (bool, error) {
	active, err := source.activeSnapshot(at)
	if err != nil {
		return false, err
	}
	return active.Revoked(ctx, subjectKind, subjectID, at)
}

func (source *LiveMetadata) RevocationReason(ctx context.Context, subjectKind, subjectID string, at time.Time) (string, bool, error) {
	active, err := source.activeSnapshot(at)
	if err != nil {
		return "", false, err
	}
	return active.RevocationReason(ctx, subjectKind, subjectID, at)
}

func (source *LiveMetadata) activeSnapshot(at time.Time) (*SnapshotMetadata, error) {
	if source == nil {
		return nil, ErrMetadataUnavailable
	}
	active := source.active.Load()
	if active == nil {
		return nil, ErrMetadataUnavailable
	}
	if !at.Before(active.deadline) {
		return nil, fmt.Errorf("%w: revision %d expired at %s", ErrMetadataStale, active.revision, active.deadline.Format(time.RFC3339Nano))
	}
	if err := active.snapshot.Ready(); err != nil {
		return nil, err
	}
	return active.snapshot, nil
}

func (source *LiveMetadata) refreshLoop(ctx context.Context) {
	defer close(source.done)
	ticker := time.NewTicker(source.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_ = source.refreshAt(now.UTC())
		}
	}
}

func (source *LiveMetadata) refreshAt(now time.Time) error {
	source.refreshMu.Lock()
	defer source.refreshMu.Unlock()

	if err := validateTrustedMetadataDirectory(source.root, false); err != nil {
		return source.recordRefreshFailure(fmt.Errorf("validate live metadata root: %w", err))
	}
	manifest, err := loadMetadataManifest(filepath.Join(source.root, "current.json"), now, source.maxSnapshotAge)
	if err != nil {
		return source.recordRefreshFailure(err)
	}
	active := source.active.Load()
	if active != nil && manifest.revision < active.revision {
		return source.recordRefreshFailure(fmt.Errorf("metadata revision rollback rejected: candidate=%d active=%d", manifest.revision, active.revision))
	}

	snapshot, digest, err := loadLiveGeneration(filepath.Join(source.root, "generations", manifest.generation))
	if err != nil {
		return source.recordRefreshFailure(fmt.Errorf("load metadata generation %q: %w", manifest.generation, err))
	}
	if active != nil && manifest.revision == active.revision {
		if active.generation != manifest.generation || !active.publishedAt.Equal(manifest.publishedAt) || !active.validUntil.Equal(manifest.validUntil) || active.digest != digest {
			return source.recordRefreshFailure(fmt.Errorf("metadata revision %d was republished with different manifest or content", manifest.revision))
		}
		source.recordRefreshSuccess()
		return nil
	}

	candidate := &liveMetadataGeneration{
		snapshot:    snapshot,
		revision:    manifest.revision,
		generation:  manifest.generation,
		publishedAt: manifest.publishedAt,
		validUntil:  manifest.validUntil,
		deadline:    manifest.deadline,
		digest:      digest,
	}
	source.active.Store(candidate)
	source.recordRefreshSuccess()
	source.logger.Info("live metadata generation activated", "revision", candidate.revision, "published_at", candidate.publishedAt, "deadline", candidate.deadline)
	return nil
}

type parsedMetadataManifest struct {
	revision    uint64
	generation  string
	publishedAt time.Time
	validUntil  time.Time
	deadline    time.Time
}

func loadMetadataManifest(path string, now time.Time, maxSnapshotAge time.Duration) (parsedMetadataManifest, error) {
	var parsed parsedMetadataManifest
	data, err := readRegularFileBounded(path, maxMetadataManifestBytes)
	if err != nil {
		return parsed, fmt.Errorf("read current metadata manifest: %w", err)
	}
	var manifest MetadataGenerationManifest
	if err := decodeStrictJSONObject(data, &manifest); err != nil {
		return parsed, fmt.Errorf("parse current metadata manifest: %w", err)
	}
	if manifest.ContractVersion != contractv1.ProtocolVersion {
		return parsed, fmt.Errorf("unsupported metadata manifest contract_version %d", manifest.ContractVersion)
	}
	if manifest.Revision == 0 {
		return parsed, errors.New("metadata manifest revision must be greater than zero")
	}
	if !validGenerationName(manifest.Generation) {
		return parsed, errors.New("metadata manifest generation is invalid")
	}
	publishedAt, err := time.Parse(time.RFC3339, manifest.PublishedAt)
	if err != nil {
		return parsed, fmt.Errorf("parse metadata published_at: %w", err)
	}
	validUntil, err := time.Parse(time.RFC3339, manifest.ValidUntil)
	if err != nil {
		return parsed, fmt.Errorf("parse metadata valid_until: %w", err)
	}
	if !publishedAt.Before(validUntil) {
		return parsed, errors.New("metadata valid_until must be after published_at")
	}
	if publishedAt.After(now.Add(maxMetadataFutureSkew)) {
		return parsed, errors.New("metadata published_at is too far in the future")
	}
	localDeadline := publishedAt.Add(maxSnapshotAge)
	acceptedDeadline := now.Add(maxSnapshotAge)
	deadline := validUntil
	if localDeadline.Before(deadline) {
		deadline = localDeadline
	}
	if acceptedDeadline.Before(deadline) {
		deadline = acceptedDeadline
	}
	if !now.Before(deadline) {
		return parsed, fmt.Errorf("metadata candidate is already stale at %s", deadline.Format(time.RFC3339Nano))
	}
	return parsedMetadataManifest{
		revision:    manifest.Revision,
		generation:  manifest.Generation,
		publishedAt: publishedAt,
		validUntil:  validUntil,
		deadline:    deadline,
	}, nil
}

func loadLiveGeneration(root string) (*SnapshotMetadata, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateTrustedMetadataDirectory(root, false); err != nil {
		return nil, zero, fmt.Errorf("validate generation path: %w", err)
	}

	source := NewSnapshotMetadata()
	hasher := sha256.New()
	recordCount := 0
	var generationBytes int64
	for _, spec := range []struct {
		category string
		add      func([]byte) error
	}{
		{category: "authorizations", add: source.addAuthorizationJSON},
		{category: "routes", add: source.addRouteJSON},
		{category: "revocations", add: source.addRevocationJSON},
	} {
		dir := filepath.Join(root, spec.category)
		if err := validateTrustedMetadataDirectory(dir, false); err != nil {
			return nil, zero, fmt.Errorf("validate metadata category %s: %w", spec.category, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, zero, fmt.Errorf("read metadata category %s: %w", spec.category, err)
		}
		for _, entry := range entries {
			recordCount++
			if recordCount > maxLiveMetadataRecords {
				return nil, zero, fmt.Errorf("metadata generation exceeds %d records", maxLiveMetadataRecords)
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				return nil, zero, fmt.Errorf("unexpected metadata generation entry %s/%s", spec.category, entry.Name())
			}
			data, err := readRegularFileBounded(filepath.Join(dir, entry.Name()), maxMetadataRecordBytes)
			if err != nil {
				return nil, zero, fmt.Errorf("read metadata record %s/%s: %w", spec.category, entry.Name(), err)
			}
			generationBytes += int64(len(data))
			if generationBytes > maxLiveGenerationBytes {
				return nil, zero, fmt.Errorf("metadata generation exceeds %d bytes", maxLiveGenerationBytes)
			}
			_, _ = io.WriteString(hasher, spec.category)
			_, _ = hasher.Write([]byte{0})
			_, _ = io.WriteString(hasher, entry.Name())
			_, _ = hasher.Write([]byte{0})
			_, _ = hasher.Write(data)
			_, _ = hasher.Write([]byte{0})
			if err := spec.add(data); err != nil {
				return nil, zero, fmt.Errorf("validate metadata record %s/%s: %w", spec.category, entry.Name(), err)
			}
		}
	}
	if err := source.Ready(); err != nil {
		return nil, zero, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return source, digest, nil
}

func readRegularFileBounded(path string, maxBytes int64) ([]byte, error) {
	return readTrustedMetadataFile(path, maxBytes)
}

func validGenerationName(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func decodeStrictJSONObject(data []byte, target any) error {
	if err := validateStrictJSONObject(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("strict JSON decode failed: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON decode failed: %w", err)
	}
	return nil
}

func validateStrictJSONObject(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON payload is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("JSON payload must be one object")
	}
	if err := consumeStrictJSONObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON is invalid: %w", err)
	}
	return nil
}

func consumeStrictJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON object key: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("JSON object member name must be a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON object member name: %q", key)
		}
		seen[key] = struct{}{}
		valueToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON value for %q: %w", key, err)
		}
		if err := consumeStrictJSONValue(decoder, valueToken); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON object close: %w", err)
	}
	if delim, ok := closing.(json.Delim); !ok || delim != '}' {
		return errors.New("invalid JSON object close")
	}
	return nil
}

func consumeStrictJSONValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeStrictJSONObject(decoder)
	case '[':
		for decoder.More() {
			item, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeStrictJSONValue(decoder, item); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if arrayClose, ok := closing.(json.Delim); !ok || arrayClose != ']' {
			return errors.New("invalid JSON array close")
		}
		return nil
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func (source *LiveMetadata) recordRefreshFailure(err error) error {
	source.refreshFailures.Add(1)
	now := time.Now().UTC()
	text := err.Error()
	if text != source.lastErrorText || source.lastErrorLogAt.IsZero() || now.Sub(source.lastErrorLogAt) >= 30*time.Second {
		source.logger.Warn("live metadata refresh rejected; last validated authority remains bounded by its original freshness deadline", "error", err)
		source.lastErrorText = text
		source.lastErrorLogAt = now
	}
	return err
}

func (source *LiveMetadata) recordRefreshSuccess() {
	source.refreshSuccesses.Add(1)
	if source.lastErrorText != "" {
		source.logger.Info("live metadata refresh recovered")
		source.lastErrorText = ""
		source.lastErrorLogAt = time.Time{}
	}
}
