package contractv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxTrafficDeltaBytes = 1024 * 1024 * 1024

// Health-report contract bounds. A health_report must stay small and strictly
// bounded so a misbehaving Agent cannot use it as a resource-exhaustion
// channel.
const (
	MaxStreamsPerSessionBound = 4096
	MaxQueuedFramesBound      = 65536
	MaxHealthReconnectCount   = 1<<31 - 1
)

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
	// utcTimestampPattern bounds every component to its calendar range and the
	// fractional second to 9 digits (nanosecond precision). It matches the
	// `timestamp` definition in contracts/v1 and the schema `maxLength` of 30.
	utcTimestampPattern = regexp.MustCompile(`^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$`)
)

type DeviceSessionAuthorization struct {
	ContractVersion int    `json:"contract_version"`
	AuthorizationID string `json:"authorization_id"`
	DeviceID        string `json:"device_id"`
	DevicePublicKey string `json:"device_public_key"`
	TokenID         string `json:"token_id"`
	TokenSHA256     string `json:"token_sha256"`
	IssuedAt        string `json:"issued_at"`
	NotBefore       string `json:"not_before"`
	ExpiresAt       string `json:"expires_at"`
	Disabled        bool   `json:"disabled"`
}

type EndpointRouteAssignment struct {
	ContractVersion int    `json:"contract_version"`
	AssignmentID    string `json:"assignment_id"`
	EndpointID      string `json:"endpoint_id"`
	PublicHostname  string `json:"public_hostname"`
	DeviceID        string `json:"device_id"`
	LocalEndpointID string `json:"local_endpoint_id"`
	Enabled         bool   `json:"enabled"`
	NotBefore       string `json:"not_before"`
	ExpiresAt       string `json:"expires_at"`
}

type RevocationSignal struct {
	ContractVersion int    `json:"contract_version"`
	EventID         string `json:"event_id"`
	SubjectKind     string `json:"subject_kind"`
	SubjectID       string `json:"subject_id"`
	EffectiveAt     string `json:"effective_at"`
	ReasonCode      string `json:"reason_code"`
}

type GatewayStatusSignal struct {
	ContractVersion int    `json:"contract_version"`
	EventID         string `json:"event_id"`
	ObservedAt      string `json:"observed_at"`
	Kind            string `json:"kind"`
	DeviceID        string `json:"device_id"`
	SessionID       string `json:"session_id,omitempty"`
	EndpointID      string `json:"endpoint_id,omitempty"`
	BytesFromPublic *int64 `json:"bytes_from_public,omitempty"`
	BytesToPublic   *int64 `json:"bytes_to_public,omitempty"`
}

func ParseDeviceSessionAuthorizationRecord(data []byte) (DeviceSessionAuthorization, error) {
	var record DeviceSessionAuthorization
	if err := validateStrictJSONObject(data); err != nil {
		return record, err
	}
	if err := rejectNullMembers(data); err != nil {
		return record, err
	}
	// `disabled` is schema-required and its Go zero value (`false`) is a valid
	// contract value, so an absent member would otherwise fail open.
	if err := requirePresent(data, "disabled"); err != nil {
		return record, err
	}
	if err := decodeStrict(data, &record); err != nil {
		return record, err
	}
	if record.ContractVersion != ProtocolVersion {
		return record, fmt.Errorf("unsupported contract version: %d", record.ContractVersion)
	}
	for name, value := range map[string]string{
		"authorization_id": record.AuthorizationID,
		"device_id":        record.DeviceID,
		"token_id":         record.TokenID,
	} {
		if err := validateID(name, value); err != nil {
			return record, err
		}
	}
	// The base64url field is canonical: the encoding must reproduce the
	// transmitted string exactly, so a value with non-zero discarded trailing
	// bits cannot alias a different public key encoding.
	if err := validateRawBase64Length("device_public_key", record.DevicePublicKey, ed25519.PublicKeySize); err != nil {
		return record, err
	}
	digest, err := hex.DecodeString(record.TokenSHA256)
	if err != nil || len(digest) != 32 || record.TokenSHA256 != strings.ToLower(record.TokenSHA256) {
		return record, errors.New("token_sha256 must be 32 bytes encoded as lower-case hex")
	}
	issuedAt, err := parseUTCTime("issued_at", record.IssuedAt)
	if err != nil {
		return record, err
	}
	notBefore, err := parseUTCTime("not_before", record.NotBefore)
	if err != nil {
		return record, err
	}
	expiresAt, err := parseUTCTime("expires_at", record.ExpiresAt)
	if err != nil {
		return record, err
	}
	if issuedAt.After(notBefore) || !notBefore.Before(expiresAt) {
		return record, errors.New("authorization timestamps must satisfy issued_at <= not_before < expires_at")
	}
	return record, nil
}

func ValidateDeviceSessionAuthorizationAt(record DeviceSessionAuthorization, at time.Time) error {
	if record.Disabled {
		return errors.New("authorization is disabled")
	}
	notBefore, err := parseUTCTime("not_before", record.NotBefore)
	if err != nil {
		return err
	}
	expiresAt, err := parseUTCTime("expires_at", record.ExpiresAt)
	if err != nil {
		return err
	}
	if at.Before(notBefore) || !at.Before(expiresAt) {
		return errors.New("authorization is not active at evaluation time")
	}
	return nil
}

func ParseDeviceSessionAuthorization(data []byte, at time.Time) (DeviceSessionAuthorization, error) {
	record, err := ParseDeviceSessionAuthorizationRecord(data)
	if err != nil {
		return record, err
	}
	if err := ValidateDeviceSessionAuthorizationAt(record, at); err != nil {
		return record, err
	}
	return record, nil
}

func ParseEndpointRouteAssignmentRecord(data []byte) (EndpointRouteAssignment, error) {
	var record EndpointRouteAssignment
	if err := validateStrictJSONObject(data); err != nil {
		return record, err
	}
	if err := rejectNullMembers(data); err != nil {
		return record, err
	}
	// `enabled` is schema-required and its Go zero value (`false`) is a valid
	// contract value, so an absent member would otherwise fail open.
	if err := requirePresent(data, "enabled"); err != nil {
		return record, err
	}
	if err := decodeStrict(data, &record); err != nil {
		return record, err
	}
	if record.ContractVersion != ProtocolVersion {
		return record, fmt.Errorf("unsupported contract version: %d", record.ContractVersion)
	}
	for name, value := range map[string]string{
		"assignment_id":     record.AssignmentID,
		"endpoint_id":       record.EndpointID,
		"device_id":         record.DeviceID,
		"local_endpoint_id": record.LocalEndpointID,
	} {
		if err := validateID(name, value); err != nil {
			return record, err
		}
	}
	if err := validateHostname(record.PublicHostname); err != nil {
		return record, err
	}
	notBefore, err := parseUTCTime("not_before", record.NotBefore)
	if err != nil {
		return record, err
	}
	expiresAt, err := parseUTCTime("expires_at", record.ExpiresAt)
	if err != nil {
		return record, err
	}
	if !notBefore.Before(expiresAt) {
		return record, errors.New("route timestamps must satisfy not_before < expires_at")
	}
	return record, nil
}

func ValidateEndpointRouteAssignmentAt(record EndpointRouteAssignment, at time.Time) error {
	if !record.Enabled {
		return errors.New("route assignment is disabled")
	}
	notBefore, err := parseUTCTime("not_before", record.NotBefore)
	if err != nil {
		return err
	}
	expiresAt, err := parseUTCTime("expires_at", record.ExpiresAt)
	if err != nil {
		return err
	}
	if at.Before(notBefore) || !at.Before(expiresAt) {
		return errors.New("route assignment is not active at evaluation time")
	}
	return nil
}

func ParseEndpointRouteAssignment(data []byte, at time.Time) (EndpointRouteAssignment, error) {
	record, err := ParseEndpointRouteAssignmentRecord(data)
	if err != nil {
		return record, err
	}
	if err := ValidateEndpointRouteAssignmentAt(record, at); err != nil {
		return record, err
	}
	return record, nil
}

func ParseRevocationSignal(data []byte) (RevocationSignal, error) {
	var signal RevocationSignal
	if err := validateStrictJSONObject(data); err != nil {
		return signal, err
	}
	if err := rejectNullMembers(data); err != nil {
		return signal, err
	}
	if err := decodeStrict(data, &signal); err != nil {
		return signal, err
	}
	if signal.ContractVersion != ProtocolVersion {
		return signal, fmt.Errorf("unsupported contract version: %d", signal.ContractVersion)
	}
	if err := validateID("event_id", signal.EventID); err != nil {
		return signal, err
	}
	if err := validateID("subject_id", signal.SubjectID); err != nil {
		return signal, err
	}
	if !oneOfStrings(signal.SubjectKind, "device_session_authorization", "endpoint_route_assignment", "device") {
		return signal, errors.New("invalid revocation subject_kind")
	}
	if !oneOfStrings(signal.ReasonCode, "disabled", "credential_revoked", "assignment_revoked", "security_hold", "expired") {
		return signal, errors.New("invalid revocation reason_code")
	}
	if _, err := parseUTCTime("effective_at", signal.EffectiveAt); err != nil {
		return signal, err
	}
	return signal, nil
}

func ParseGatewayStatusSignal(data []byte) (GatewayStatusSignal, error) {
	var signal GatewayStatusSignal
	if err := validateStrictJSONObject(data); err != nil {
		return signal, err
	}
	if err := rejectNullMembers(data); err != nil {
		return signal, err
	}
	if err := decodeStrict(data, &signal); err != nil {
		return signal, err
	}
	if signal.ContractVersion != ProtocolVersion {
		return signal, fmt.Errorf("unsupported contract version: %d", signal.ContractVersion)
	}
	if err := validateID("event_id", signal.EventID); err != nil {
		return signal, err
	}
	if err := validateID("device_id", signal.DeviceID); err != nil {
		return signal, err
	}
	if signal.SessionID != "" {
		if err := validateID("session_id", signal.SessionID); err != nil {
			return signal, err
		}
	}
	if signal.EndpointID != "" {
		if err := validateID("endpoint_id", signal.EndpointID); err != nil {
			return signal, err
		}
	}
	// Both identifiers are optional but the schema pattern has a minimum
	// length of 1, so an explicit empty string is malformed rather than absent.
	if err := rejectEmptyMembers(data, "session_id", "endpoint_id"); err != nil {
		return signal, err
	}
	if _, err := parseUTCTime("observed_at", signal.ObservedAt); err != nil {
		return signal, err
	}
	if !oneOfStrings(signal.Kind, "session_connected", "session_disconnected", "route_opened", "route_closed", "traffic_delta") {
		return signal, errors.New("invalid gateway status kind")
	}
	if err := validateTrafficCounter("bytes_from_public", signal.BytesFromPublic); err != nil {
		return signal, err
	}
	if err := validateTrafficCounter("bytes_to_public", signal.BytesToPublic); err != nil {
		return signal, err
	}
	if signal.Kind == "traffic_delta" {
		if signal.EndpointID == "" || (signal.BytesFromPublic == nil && signal.BytesToPublic == nil) {
			return signal, errors.New("traffic_delta requires endpoint_id and at least one byte counter")
		}
	}
	return signal, nil
}

type ClientHello struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	DeviceID        string `json:"device_id"`
	AuthorizationID string `json:"authorization_id"`
	TokenID         string `json:"token_id"`
	SessionToken    string `json:"session_token"`
	ClientNonce     string `json:"client_nonce"`
}

type ServerChallenge struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	ServerNonce     string `json:"server_nonce"`
	ExpiresAt       string `json:"expires_at"`
}

type ClientAuth struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	Signature       string `json:"signature"`
}

type SessionReady struct {
	ContractVersion          int    `json:"contract_version"`
	MessageType              string `json:"message_type"`
	SessionID                string `json:"session_id"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	IdleTimeoutSeconds       int    `json:"idle_timeout_seconds"`
	// ResumeChallenge is the Gateway-issued per-transport proof the Agent
	// must bind into its next resume_session transcript. It is rotated on
	// every accepted resume (see SessionResumed).
	ResumeChallenge string `json:"resume_challenge,omitempty"`
}

type Heartbeat struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	PingID          string `json:"ping_id"`
	SentAt          string `json:"sent_at,omitempty"`
	ReceivedAt      string `json:"received_at,omitempty"`
}

// HealthReport is the Agent→Gateway periodic health observation required by
// the tunnel implementation plan. It carries only bounded runtime counters;
// it never carries authorization, routing authority, secrets, or identifiers
// beyond the opaque report correlation.
type HealthReport struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	ReportID        string `json:"report_id"`
	GeneratedAt     string `json:"generated_at"`
	ActiveStreams   int    `json:"active_streams"`
	QueuedFrames    int    `json:"queued_frames"`
	ReconnectCount  int64  `json:"reconnect_count"`
	LastReconnectAt string `json:"last_reconnect_at,omitempty"`
	AgentVersion    string `json:"agent_version,omitempty"`
}

type StreamOpen struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	EndpointID      string `json:"endpoint_id"`
	AssignmentID    string `json:"assignment_id"`
	LocalEndpointID string `json:"local_endpoint_id"`
	RequestID       string `json:"request_id"`
}

type StreamClose struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	ReasonCode      string `json:"reason_code"`
}

type StreamError struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	Code            string `json:"code"`
	Message         string `json:"message"`
	Retryable       bool   `json:"retryable"`
}

type SessionRevoked struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	AuthorizationID string `json:"authorization_id"`
	ReasonCode      string `json:"reason_code"`
}

// ResumeSession is the Agent→Gateway request to resume a previously
// authenticated session after a transport interruption. The Agent proves
// continued ownership of the device identity by signing the resume
// transcript; the Gateway accepts only while the original session is still
// live, the authorization is still valid, the Gateway-issued resume challenge
// bound into the transcript matches, the proof is inside its acceptance
// window, and no revocation applies.
type ResumeSession struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	DeviceID        string `json:"device_id"`
	AuthorizationID string `json:"authorization_id"`
	TokenID         string `json:"token_id"`
	SessionID       string `json:"session_id"`
	ResumeNonce     string `json:"resume_nonce"`
	// ResumeChallenge is the per-transport challenge the Gateway issued to
	// this device over the transport being replaced (session_ready or
	// session_resumed) and rotated on every accepted resume.
	ResumeChallenge string `json:"resume_challenge"`
	// IssuedAt is the Agent's RFC3339 UTC proof-generation time, which the
	// Gateway compares against its own clock to enforce a short acceptance
	// window.
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

// SessionResumed is the Gateway→Agent confirmation that the previously
// authenticated session resumed without a full challenge handshake. The
// outbound sequence continues from the pre-interruption value, and
// resume_challenge carries the fresh per-transport proof for the next resume.
type SessionResumed struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	NextSequence    uint64 `json:"next_sequence"`
	ResumedAt       string `json:"resumed_at"`
	ResumeChallenge string `json:"resume_challenge"`
}

func ValidateControlPayload(data []byte, streamID uint32, at time.Time) error {
	if err := validateStrictJSONObject(data); err != nil {
		return err
	}
	// Fail closed before dispatch: no v1 control member is nullable, and
	// encoding/json silently maps an explicit null to the Go zero value.
	if err := rejectNullMembers(data); err != nil {
		return err
	}
	var envelope struct {
		ContractVersion int    `json:"contract_version"`
		MessageType     string `json:"message_type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("invalid control JSON: %w", err)
	}
	if envelope.ContractVersion != ProtocolVersion {
		return fmt.Errorf("unsupported contract version: %d", envelope.ContractVersion)
	}

	sessionScope := func() error {
		if streamID != 0 {
			return errors.New("session control message requires stream ID 0")
		}
		return nil
	}
	streamScope := func() error {
		if streamID == 0 {
			return errors.New("stream control message requires non-zero stream ID")
		}
		return nil
	}

	switch envelope.MessageType {
	case "client_hello":
		if err := sessionScope(); err != nil {
			return err
		}
		_, err := DecodeClientHello(data)
		return err
	case "server_challenge":
		if err := sessionScope(); err != nil {
			return err
		}
		challenge, err := DecodeServerChallenge(data)
		if err != nil {
			return err
		}
		expiresAt, err := parseUTCTime("expires_at", challenge.ExpiresAt)
		if err != nil {
			return err
		}
		if !at.Before(expiresAt) {
			return errors.New("server challenge is expired")
		}
		return nil
	case "client_auth":
		if err := sessionScope(); err != nil {
			return err
		}
		_, err := DecodeClientAuth(data)
		return err
	case "session_ready":
		if err := sessionScope(); err != nil {
			return err
		}
		if err := requirePresent(data, "heartbeat_interval_seconds", "idle_timeout_seconds"); err != nil {
			return err
		}
		var ready SessionReady
		if err := decodeControlStrict(data, &ready); err != nil {
			return err
		}
		if ready.MessageType != "session_ready" || ready.ContractVersion != ProtocolVersion {
			return errors.New("invalid session_ready envelope")
		}
		if err := validateID("session_id", ready.SessionID); err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		if _, present := fields["resume_challenge"]; present {
			if err := validateRawBase64Length("resume_challenge", ready.ResumeChallenge, 32); err != nil {
				return err
			}
		}
		if ready.HeartbeatIntervalSeconds < 5 || ready.HeartbeatIntervalSeconds > 60 {
			return errors.New("heartbeat_interval_seconds outside 5..60")
		}
		if ready.IdleTimeoutSeconds < 15 || ready.IdleTimeoutSeconds > 300 || ready.IdleTimeoutSeconds < 2*ready.HeartbeatIntervalSeconds {
			return errors.New("idle_timeout_seconds outside contract bounds")
		}
		return nil
	case "ping", "pong":
		if err := sessionScope(); err != nil {
			return err
		}
		var heartbeat Heartbeat
		if err := decodeControlStrict(data, &heartbeat); err != nil {
			return err
		}
		if heartbeat.MessageType != envelope.MessageType || heartbeat.ContractVersion != ProtocolVersion {
			return errors.New("invalid heartbeat envelope")
		}
		if err := validateID("ping_id", heartbeat.PingID); err != nil {
			return err
		}
		if envelope.MessageType == "ping" {
			if heartbeat.SentAt == "" || heartbeat.ReceivedAt != "" {
				return errors.New("ping requires sent_at only")
			}
			_, err := parseUTCTime("sent_at", heartbeat.SentAt)
			return err
		}
		if heartbeat.ReceivedAt == "" || heartbeat.SentAt != "" {
			return errors.New("pong requires received_at only")
		}
		_, err := parseUTCTime("received_at", heartbeat.ReceivedAt)
		return err
	case "health_report":
		if err := sessionScope(); err != nil {
			return err
		}
		if err := requirePresent(data, "active_streams", "queued_frames", "reconnect_count"); err != nil {
			return err
		}
		var report HealthReport
		if err := decodeControlStrict(data, &report); err != nil {
			return err
		}
		if report.MessageType != "health_report" || report.ContractVersion != ProtocolVersion {
			return errors.New("invalid health_report envelope")
		}
		if err := validateID("report_id", report.ReportID); err != nil {
			return err
		}
		if _, err := parseUTCTime("generated_at", report.GeneratedAt); err != nil {
			return err
		}
		if report.ActiveStreams < 0 || report.ActiveStreams > MaxStreamsPerSessionBound {
			return errors.New("health_report active_streams outside contract bounds")
		}
		if report.QueuedFrames < 0 || report.QueuedFrames > MaxQueuedFramesBound {
			return errors.New("health_report queued_frames outside contract bounds")
		}
		if report.ReconnectCount < 0 || report.ReconnectCount > MaxHealthReconnectCount {
			return errors.New("health_report reconnect_count outside contract bounds")
		}
		// `last_reconnect_at` is optional but the schema requires a timestamp
		// when it is present, so an explicit empty string is not a valid way to
		// say "absent".
		if err := rejectEmptyMembers(data, "last_reconnect_at"); err != nil {
			return err
		}
		if report.LastReconnectAt != "" {
			if _, err := parseUTCTime("last_reconnect_at", report.LastReconnectAt); err != nil {
				return err
			}
		}
		if utf8.RuneCountInString(report.AgentVersion) > 64 {
			return errors.New("health_report agent_version outside contract length")
		}
		return nil
	case "stream_open":
		if err := streamScope(); err != nil {
			return err
		}
		var message StreamOpen
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "stream_open" {
			return errors.New("invalid stream_open envelope")
		}
		for name, value := range map[string]string{"endpoint_id": message.EndpointID, "assignment_id": message.AssignmentID, "local_endpoint_id": message.LocalEndpointID, "request_id": message.RequestID} {
			if err := validateID(name, value); err != nil {
				return err
			}
		}
		return nil
	case "stream_close":
		if err := streamScope(); err != nil {
			return err
		}
		var message StreamClose
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "stream_close" {
			return errors.New("invalid stream_close envelope")
		}
		if !oneOfStrings(message.ReasonCode, "completed", "peer_closed", "cancelled") {
			return errors.New("invalid stream_close reason_code")
		}
		return nil
	case "stream_error":
		if err := streamScope(); err != nil {
			return err
		}
		if err := requirePresent(data, "retryable"); err != nil {
			return err
		}
		var message StreamError
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "stream_error" {
			return errors.New("invalid stream_error envelope")
		}
		if !oneOfStrings(message.Code, "local_target_unavailable", "route_revoked", "protocol_error", "resource_limit", "internal_error") {
			return errors.New("invalid stream_error code")
		}
		// The schema maxLength counts code points, not UTF-8 bytes.
		if runes := utf8.RuneCountInString(message.Message); runes == 0 || runes > 256 {
			return errors.New("stream_error message outside contract length")
		}
		return nil
	case "session_revoked":
		if err := sessionScope(); err != nil {
			return err
		}
		var message SessionRevoked
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "session_revoked" {
			return errors.New("invalid session_revoked envelope")
		}
		if err := validateID("authorization_id", message.AuthorizationID); err != nil {
			return err
		}
		if !oneOfStrings(message.ReasonCode, "disabled", "credential_revoked", "security_hold", "expired") {
			return errors.New("invalid session_revoked reason_code")
		}
		return nil
	case "resume_session":
		if err := sessionScope(); err != nil {
			return err
		}
		var message ResumeSession
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "resume_session" {
			return errors.New("invalid resume_session envelope")
		}
		for name, value := range map[string]string{
			"device_id":        message.DeviceID,
			"authorization_id": message.AuthorizationID,
			"token_id":         message.TokenID,
			"session_id":       message.SessionID,
		} {
			if err := validateID(name, value); err != nil {
				return err
			}
		}
		if err := validateRawBase64Length("resume_nonce", message.ResumeNonce, 32); err != nil {
			return err
		}
		if err := validateRawBase64Length("resume_challenge", message.ResumeChallenge, 32); err != nil {
			return err
		}
		if _, err := parseUTCTime("issued_at", message.IssuedAt); err != nil {
			return err
		}
		if err := validateRawBase64Length("signature", message.Signature, ed25519.SignatureSize); err != nil {
			return err
		}
		return nil
	case "session_resumed":
		if err := sessionScope(); err != nil {
			return err
		}
		if err := requirePresent(data, "next_sequence", "resume_challenge"); err != nil {
			return err
		}
		var message SessionResumed
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if message.ContractVersion != ProtocolVersion || message.MessageType != "session_resumed" {
			return errors.New("invalid session_resumed envelope")
		}
		if err := validateID("session_id", message.SessionID); err != nil {
			return err
		}
		if message.NextSequence == 0 {
			return errors.New("session_resumed next_sequence must be positive")
		}
		if _, err := parseUTCTime("resumed_at", message.ResumedAt); err != nil {
			return err
		}
		if err := validateRawBase64Length("resume_challenge", message.ResumeChallenge, 32); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown control message_type: %q", envelope.MessageType)
	}
}

// transcriptFor joins the prefix and the components with the NUL delimiter.
// Every component is re-checked against its contract pattern first: identifier
// and nonce patterns prohibit NUL, so a validated component can never contain
// the delimiter and the encoding is unambiguous without the caller having run
// the decoder first. Inputs that violate their pattern yield a nil transcript,
// which differs from every valid transcript and can never be mistaken for one.
func transcriptFor(prefix string, components []string, validate func() error) ([]byte, error) {
	if err := validate(); err != nil {
		return nil, err
	}
	return []byte(strings.Join(append([]string{prefix}, components...), "\x00")), nil
}

// ResumeTranscript is the exact signed byte sequence for resume_session. The
// Gateway-issued per-transport resume challenge and the proof timestamp are
// part of the transcript, so a proof is bound both to the Gateway's challenge
// for that transport and to the moment the Agent produced it.
func ResumeTranscript(resume ResumeSession) []byte {
	transcript, err := transcriptFor("HXT1-RESUME",
		[]string{resume.DeviceID, resume.AuthorizationID, resume.TokenID, resume.SessionID, resume.ResumeNonce, resume.ResumeChallenge, resume.IssuedAt},
		func() error {
			for _, check := range []struct {
				name  string
				value string
			}{
				{"device_id", resume.DeviceID},
				{"authorization_id", resume.AuthorizationID},
				{"token_id", resume.TokenID},
				{"session_id", resume.SessionID},
			} {
				if err := validateID(check.name, check.value); err != nil {
					return err
				}
			}
			if err := validateRawBase64Length("resume_nonce", resume.ResumeNonce, 32); err != nil {
				return err
			}
			if err := validateRawBase64Length("resume_challenge", resume.ResumeChallenge, 32); err != nil {
				return err
			}
			_, err := parseUTCTime("issued_at", resume.IssuedAt)
			return err
		})
	if err != nil {
		return nil
	}
	return transcript
}

// ResumeIssuedAt parses the Agent's proof-generation timestamp. It is a
// contract-validated RFC3339 UTC instant.
func ResumeIssuedAt(resume ResumeSession) (time.Time, error) {
	return parseUTCTime("issued_at", resume.IssuedAt)
}

// MatchResumeChallenge compares the resume challenge the Gateway issued for a
// session identity with the one a resume proof presents, in constant time.
// A challenge is never empty for a live session, so an empty expected value
// can never match.
func MatchResumeChallenge(expected, presented string) bool {
	if expected == "" || len(expected) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// VerifyResumeSignature verifies the resume_session signature against the
// externally registered device public key.
func VerifyResumeSignature(publicKeyBase64 string, resume ResumeSession) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(resume.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	transcript := ResumeTranscript(resume)
	if len(transcript) == 0 {
		return errors.New("resume transcript requires contract-valid inputs")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), transcript, signature) {
		return errors.New("resume signature verification failed")
	}
	return nil
}

func DecodeClientHello(data []byte) (ClientHello, error) {
	var message ClientHello
	if err := decodeControlStrict(data, &message); err != nil {
		return message, err
	}
	if message.ContractVersion != ProtocolVersion || message.MessageType != "client_hello" {
		return message, errors.New("invalid client_hello envelope")
	}
	for name, value := range map[string]string{"device_id": message.DeviceID, "authorization_id": message.AuthorizationID, "token_id": message.TokenID} {
		if err := validateID(name, value); err != nil {
			return message, err
		}
	}
	if !tokenPattern.MatchString(message.SessionToken) {
		return message, errors.New("session_token must be 32..512 base64url-safe characters")
	}
	if err := validateRawBase64Length("client_nonce", message.ClientNonce, 32); err != nil {
		return message, err
	}
	return message, nil
}

func DecodeServerChallenge(data []byte) (ServerChallenge, error) {
	var message ServerChallenge
	if err := decodeControlStrict(data, &message); err != nil {
		return message, err
	}
	if message.ContractVersion != ProtocolVersion || message.MessageType != "server_challenge" {
		return message, errors.New("invalid server_challenge envelope")
	}
	if err := validateID("session_id", message.SessionID); err != nil {
		return message, err
	}
	if err := validateRawBase64Length("server_nonce", message.ServerNonce, 32); err != nil {
		return message, err
	}
	if _, err := parseUTCTime("expires_at", message.ExpiresAt); err != nil {
		return message, err
	}
	return message, nil
}

func DecodeClientAuth(data []byte) (ClientAuth, error) {
	var message ClientAuth
	if err := decodeControlStrict(data, &message); err != nil {
		return message, err
	}
	if message.ContractVersion != ProtocolVersion || message.MessageType != "client_auth" {
		return message, errors.New("invalid client_auth envelope")
	}
	if err := validateID("session_id", message.SessionID); err != nil {
		return message, err
	}
	if err := validateRawBase64Length("signature", message.Signature, ed25519.SignatureSize); err != nil {
		return message, err
	}
	return message, nil
}

func VerifyClientAuthSignature(publicKeyBase64 string, hello ClientHello, challenge ServerChallenge, auth ClientAuth) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(auth.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	if auth.SessionID != challenge.SessionID {
		return errors.New("client_auth session_id does not match challenge")
	}
	transcript := AuthTranscript(hello, challenge)
	if len(transcript) == 0 {
		return errors.New("authentication transcript requires contract-valid inputs")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), transcript, signature) {
		return errors.New("Ed25519 authentication signature verification failed")
	}
	return nil
}

// AuthTranscript is the exact signed byte sequence for client_auth. See
// transcriptFor for the NUL-delimiter safety argument.
func AuthTranscript(hello ClientHello, challenge ServerChallenge) []byte {
	transcript, err := transcriptFor("HXT1-AUTH",
		[]string{challenge.SessionID, hello.DeviceID, hello.AuthorizationID, hello.TokenID, hello.ClientNonce, challenge.ServerNonce},
		func() error {
			for _, check := range []struct {
				name  string
				value string
			}{
				{"session_id", challenge.SessionID},
				{"device_id", hello.DeviceID},
				{"authorization_id", hello.AuthorizationID},
				{"token_id", hello.TokenID},
			} {
				if err := validateID(check.name, check.value); err != nil {
					return err
				}
			}
			if err := validateRawBase64Length("client_nonce", hello.ClientNonce, 32); err != nil {
				return err
			}
			return validateRawBase64Length("server_nonce", challenge.ServerNonce, 32)
		})
	if err != nil {
		return nil
	}
	return transcript
}

func MatchSessionToken(record DeviceSessionAuthorization, token string) bool {
	expected, err := hex.DecodeString(record.TokenSHA256)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], expected) == 1
}

func decodeControlStrict(data []byte, target any) error {
	if err := validateStrictJSONObject(data); err != nil {
		return err
	}
	return decodeStrict(data, target)
}

func decodeStrict(data []byte, target any) error {
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

func validateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid contract identifier", name)
	}
	return nil
}

func validateRawBase64Length(name, value string, size int) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size {
		return fmt.Errorf("%s must encode exactly %d bytes as base64url without padding", name, size)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("%s is not canonical base64url without padding", name)
	}
	return nil
}

func parseUTCTime(name, value string) (time.Time, error) {
	if !utcTimestampPattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC with Z suffix and optional dot-fraction", name)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC: %w", name, err)
	}
	return parsed, nil
}

func validateHostname(value string) error {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return errors.New("public_hostname is invalid")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return errors.New("public_hostname must contain at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("public_hostname contains invalid label")
		}
		for _, r := range label {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') || r > unicode.MaxASCII {
				return errors.New("public_hostname must contain ASCII letters, digits, and hyphens only")
			}
		}
	}
	// The schema requires a top-level label of [A-Za-z]{2,63}; a single-letter
	// TLD is not accepted by this contract.
	top := labels[len(labels)-1]
	if len(top) < 2 || len(top) > 63 {
		return errors.New("public_hostname top-level label must be 2..63 ASCII letters")
	}
	for _, r := range top {
		if !unicode.IsLetter(r) || r > unicode.MaxASCII {
			return errors.New("public_hostname top-level label must contain letters only")
		}
	}
	return nil
}

func validateTrafficCounter(name string, value *int64) error {
	if value == nil {
		return nil
	}
	if *value < 0 || *value > MaxTrafficDeltaBytes {
		return fmt.Errorf("%s outside 0..%d", name, MaxTrafficDeltaBytes)
	}
	return nil
}

func oneOfStrings(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
