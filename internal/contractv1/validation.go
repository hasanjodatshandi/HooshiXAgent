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
)

const MaxTrafficDeltaBytes = 1024 * 1024 * 1024

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
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
	publicKey, err := base64.RawURLEncoding.DecodeString(record.DevicePublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return record, errors.New("device_public_key must be 32 raw Ed25519 bytes encoded base64url without padding")
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
	if !oneOf(signal.SubjectKind, "device_session_authorization", "endpoint_route_assignment", "device") {
		return signal, errors.New("invalid revocation subject_kind")
	}
	if !oneOf(signal.ReasonCode, "disabled", "credential_revoked", "assignment_revoked", "security_hold", "expired") {
		return signal, errors.New("invalid revocation reason_code")
	}
	if _, err := parseUTCTime("effective_at", signal.EffectiveAt); err != nil {
		return signal, err
	}
	return signal, nil
}

func ParseGatewayStatusSignal(data []byte) (GatewayStatusSignal, error) {
	var signal GatewayStatusSignal
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
	if _, err := parseUTCTime("observed_at", signal.ObservedAt); err != nil {
		return signal, err
	}
	if !oneOf(signal.Kind, "session_connected", "session_disconnected", "route_opened", "route_closed", "traffic_delta") {
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
}

type Heartbeat struct {
	ContractVersion int    `json:"contract_version"`
	MessageType     string `json:"message_type"`
	PingID          string `json:"ping_id"`
	SentAt          string `json:"sent_at,omitempty"`
	ReceivedAt      string `json:"received_at,omitempty"`
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

func ValidateControlPayload(data []byte, streamID uint32, at time.Time) error {
	if err := validateStrictJSONObject(data); err != nil {
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
	case "stream_open":
		if err := streamScope(); err != nil {
			return err
		}
		var message StreamOpen
		if err := decodeControlStrict(data, &message); err != nil {
			return err
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
		if !oneOf(message.ReasonCode, "completed", "peer_closed", "cancelled") {
			return errors.New("invalid stream_close reason_code")
		}
		return nil
	case "stream_error":
		if err := streamScope(); err != nil {
			return err
		}
		var message StreamError
		if err := decodeControlStrict(data, &message); err != nil {
			return err
		}
		if !oneOf(message.Code, "local_target_unavailable", "route_revoked", "protocol_error", "resource_limit", "internal_error") {
			return errors.New("invalid stream_error code")
		}
		if len(message.Message) == 0 || len(message.Message) > 256 {
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
		if err := validateID("authorization_id", message.AuthorizationID); err != nil {
			return err
		}
		if !oneOf(message.ReasonCode, "disabled", "credential_revoked", "security_hold", "expired") {
			return errors.New("invalid session_revoked reason_code")
		}
		return nil
	default:
		return fmt.Errorf("unknown control message_type: %q", envelope.MessageType)
	}
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
	if !ed25519.Verify(ed25519.PublicKey(publicKey), AuthTranscript(hello, challenge), signature) {
		return errors.New("Ed25519 authentication signature verification failed")
	}
	return nil
}

func AuthTranscript(hello ClientHello, challenge ServerChallenge) []byte {
	parts := []string{
		"HXT1-AUTH",
		challenge.SessionID,
		hello.DeviceID,
		hello.AuthorizationID,
		hello.TokenID,
		hello.ClientNonce,
		challenge.ServerNonce,
	}
	return []byte(strings.Join(parts, "\x00"))
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
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC with Z suffix", name)
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
	for _, r := range labels[len(labels)-1] {
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

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
