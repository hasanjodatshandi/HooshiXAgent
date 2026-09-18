package contractv1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// This file is the cross-validator agreement matrix: every payload is judged by
// both implementations of the same contract — the Go reference validator and
// the published JSON Schema — and the two verdicts must match. A rule that
// only one side implements shows up here as a failing case instead of as a
// production interop failure.

// challengeFixture / issuedAtFixture are the Gateway-issued resume challenge
// and proof timestamp used by the resume_session agreement cases.
const (
	challengeFixture = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	issuedAtFixture  = "2026-08-29T12:00:00Z"
)

const (
	tunnelSchemaName = "tunnel-control.schema.json"
	authSchemaName   = "external/device-session-authorization.schema.json"
	routeSchemaName  = "external/endpoint-route-assignment.schema.json"
	revokeSchemaName = "external/revocation-signal.schema.json"
	statusSchemaName = "external/gateway-status-signal.schema.json"
)

type agreementCase struct {
	name       string
	schemaName string
	payload    string
	// verify runs the Go reference implementation and returns nil when the
	// payload is contract-valid.
	verify func([]byte) error
	wantGo bool
	// wantSchema is equal to wantGo unless JSON Schema cannot express the rule.
	// In that case reason must state why and a normative document must record
	// the rule, so the asymmetry is declared rather than accidental.
	wantSchema bool
	reason     string
}

// agreementBoth builds a case where both validators must return valid.
func agreementBoth(name, schemaName, payload string, verify func([]byte) error, valid bool) agreementCase {
	return agreementCase{name: name, schemaName: schemaName, payload: payload, verify: verify, wantGo: valid, wantSchema: valid}
}

// agreementGoOnly builds a case where the rule is normative but cannot be
// expressed in JSON Schema. reason is the documented justification.
func agreementGoOnly(name, schemaName, reason, payload string, verify func([]byte) error) agreementCase {
	return agreementCase{name: name, schemaName: schemaName, payload: payload, verify: verify, wantGo: false, wantSchema: true, reason: reason}
}

func TestGoAndJSONSchemaAgreementMatrix(t *testing.T) {
	corpus := agreementCorpus(t)
	schemas := make(map[string]*jsonschema.Schema)
	var failures []string
	asymmetries := 0
	for _, test := range corpus {
		if test.wantGo != test.wantSchema && test.reason == "" {
			t.Fatalf("%s: validators disagree without a documented reason", test.name)
		}
		if test.wantGo != test.wantSchema {
			asymmetries++
		}
		gotGo := test.verify([]byte(test.payload)) == nil
		if gotGo != test.wantGo {
			failures = append(failures, fmt.Sprintf("%s: Go validator=%v want %v", test.name, gotGo, test.wantGo))
		}
		gotSchema := schemaAccepts(t, schemas, test.schemaName, test.payload)
		if gotSchema != test.wantSchema {
			failures = append(failures, fmt.Sprintf("%s: JSON Schema=%v want %v", test.name, gotSchema, test.wantSchema))
		}
		if test.wantGo == test.wantSchema && gotGo != gotSchema {
			failures = append(failures, fmt.Sprintf("%s: Go=%v but JSON Schema=%v", test.name, gotGo, gotSchema))
		}
	}
	t.Logf("agreement matrix: %d payloads, %d validators, %d documented JSON-Schema-inexpressible asymmetries",
		len(corpus), 2, asymmetries)
	for _, failure := range failures {
		t.Error(failure)
	}
}

// TestAgreementMatrixCoversEveryRequiredMember proves the generated corpus is
// not vacuously small: every required member of every message and record is
// covered by both an absence and a null case.
func TestAgreementMatrixCoversEveryRequiredMember(t *testing.T) {
	corpus := agreementCorpus(t)
	covered := make(map[string]bool)
	for _, test := range corpus {
		covered[test.name] = true
	}
	for _, target := range agreementTargets(t) {
		for _, member := range schemaRequiredMembers(t, target.schemaName, target.defName) {
			for _, kind := range []string{"absent", "null"} {
				name := fmt.Sprintf("%s/%s/%s", target.label, kind, member)
				if !covered[name] {
					t.Errorf("agreement corpus is missing case %q", name)
				}
			}
		}
	}
}

// TestSessionReadyCrossFieldRuleIsExact compares both validators with the
// contract rule across every heartbeat_interval_seconds value in and around the
// declared range, at the cross-field boundary (2*hb) and at both independent
// bounds. The only hb-dependent constraint is idle_timeout_seconds >= 2*hb, so
// probing +/-2 around 2*hb for every hb is what proves the schema enumeration
// has no gap: a bracketed approximation would pass a spot sample but fail here.
func TestSessionReadyCrossFieldRuleIsExact(t *testing.T) {
	schema := compileSchema(t, tunnelSchemaName)
	mismatches := 0
	evaluations := 0
	for hb := 1; hb <= 90; hb++ {
		for _, it := range []int{14, 15, 16, 299, 300, 301, 2*hb - 2, 2*hb - 1, 2 * hb, 2*hb + 1, 2*hb + 2} {
			if it < 1 {
				continue
			}
			evaluations++
			want := hb >= 5 && hb <= 60 && it >= 15 && it <= 300 && it >= 2*hb
			payload := fmt.Sprintf(`{"contract_version":1,"message_type":"session_ready","session_id":"session-001","heartbeat_interval_seconds":%d,"idle_timeout_seconds":%d,"resume_challenge":"%s"}`, hb, it, challengeFixture)
			gotGo := ValidateControlPayload([]byte(payload), 0, fixtureTime) == nil
			gotSchema := validateSchemaValue(schema, []byte(payload)) == nil
			if gotGo != want || gotSchema != want {
				mismatches++
				if mismatches <= 20 {
					t.Errorf("hb=%d it=%d: go=%v schema=%v want %v", hb, it, gotGo, gotSchema, want)
				}
			}
		}
	}
	if mismatches > 20 {
		t.Errorf("... and %d further mismatches", mismatches-20)
	}
	t.Logf("session_ready cross-field grid: %d evaluations over hb 1..90", evaluations)
}

func schemaAccepts(t *testing.T, schemas map[string]*jsonschema.Schema, schemaName, payload string) bool {
	t.Helper()
	schema, ok := schemas[schemaName]
	if !ok {
		schema = compileSchema(t, schemaName)
		schemas[schemaName] = schema
	}
	// validateSchemaValue shares the Go side's JSON strictness (UseNumber,
	// trailing-value rejection), so an undecodable payload is simply not
	// accepted by this side.
	return validateSchemaValue(schema, []byte(payload)) == nil
}

// agreementTarget pairs a schema and one of its message/record definitions with
// the valid payload used to generate absence and null cases.
type agreementTarget struct {
	label      string
	schemaName string
	defName    string
	payload    string
	streamID   uint32
	record     bool
}

func agreementTargets(t *testing.T) []agreementTarget {
	t.Helper()
	targets := controlTargets()
	for _, name := range []string{authSchemaName, routeSchemaName, revokeSchemaName, statusSchemaName} {
		targets = append(targets, agreementTarget{
			label:      strings.TrimSuffix(filepath.Base(name), ".schema.json"),
			schemaName: name,
			payload:    compactFixture(t, filepath.Join("external", strings.TrimSuffix(filepath.Base(name), ".schema.json")+".valid.json")),
			record:     true,
		})
	}
	return targets
}

func controlTargets() []agreementTarget {
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	return []agreementTarget{
		{label: "client_hello", schemaName: tunnelSchemaName, defName: "client_hello", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"client_hello","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_token":"test_session_token_0123456789ABCDEF","client_nonce":"%s"}`, nonce)},
		{label: "server_challenge", schemaName: tunnelSchemaName, defName: "server_challenge", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"server_challenge","session_id":"session-001","server_nonce":"%s","expires_at":"2026-08-29T12:10:00Z"}`, nonce)},
		{label: "client_auth", schemaName: tunnelSchemaName, defName: "client_auth", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"client_auth","session_id":"session-001","signature":"%s"}`, signature)},
		{label: "session_ready", schemaName: tunnelSchemaName, defName: "session_ready", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"session_ready","session_id":"session-001","heartbeat_interval_seconds":15,"idle_timeout_seconds":45,"resume_challenge":"%s"}`, challengeFixture)},
		{label: "ping", schemaName: tunnelSchemaName, defName: "ping", payload: `{"contract_version":1,"message_type":"ping","ping_id":"ping-001","sent_at":"2026-08-29T12:00:00Z"}`},
		{label: "pong", schemaName: tunnelSchemaName, defName: "pong", payload: `{"contract_version":1,"message_type":"pong","ping_id":"ping-001","received_at":"2026-08-29T12:00:00Z"}`},
		{label: "health_report", schemaName: tunnelSchemaName, defName: "health_report", payload: `{"contract_version":1,"message_type":"health_report","report_id":"report-001","generated_at":"2026-08-29T12:00:00Z","active_streams":3,"queued_frames":5,"reconnect_count":2,"last_reconnect_at":"2026-08-29T12:05:00Z","agent_version":"v1.2.3"}`},
		{label: "stream_open", schemaName: tunnelSchemaName, defName: "stream_open", streamID: 7, payload: `{"contract_version":1,"message_type":"stream_open","endpoint_id":"endpoint-001","assignment_id":"assign-001","local_endpoint_id":"local-http-001","request_id":"request-001"}`},
		{label: "stream_close", schemaName: tunnelSchemaName, defName: "stream_close", streamID: 7, payload: `{"contract_version":1,"message_type":"stream_close","reason_code":"completed"}`},
		{label: "stream_error", schemaName: tunnelSchemaName, defName: "stream_error", streamID: 7, payload: `{"contract_version":1,"message_type":"stream_error","code":"internal_error","message":"stream failed","retryable":false}`},
		{label: "session_revoked", schemaName: tunnelSchemaName, defName: "session_revoked", payload: `{"contract_version":1,"message_type":"session_revoked","authorization_id":"auth-001","reason_code":"disabled"}`},
		{label: "resume_session", schemaName: tunnelSchemaName, defName: "resume_session", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"%s","resume_challenge":"%s","issued_at":"%s","signature":"%s"}`, nonce, challengeFixture, issuedAtFixture, signature)},
		{label: "session_resumed", schemaName: tunnelSchemaName, defName: "session_resumed", payload: fmt.Sprintf(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":5,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"%s"}`, challengeFixture)},
	}
}

func agreementCorpus(t *testing.T) []agreementCase {
	t.Helper()
	var corpus []agreementCase

	for _, target := range agreementTargets(t) {
		verify := target.verifier()
		required := schemaRequiredMembers(t, target.schemaName, target.defName)
		corpus = append(corpus, agreementBoth(target.label+"/baseline", target.schemaName, target.payload, verify, true))
		for _, member := range required {
			section := member
			corpus = append(corpus, agreementBoth(
				fmt.Sprintf("%s/absent/%s", target.label, section), target.schemaName,
				mutatePayload(t, target.payload, func(object map[string]json.RawMessage) { delete(object, member) }), verify, false))
			corpus = append(corpus, agreementBoth(
				fmt.Sprintf("%s/null/%s", target.label, section), target.schemaName,
				mutatePayload(t, target.payload, func(object map[string]json.RawMessage) { object[member] = json.RawMessage("null") }), verify, false))
		}
		if !target.record {
			// Contract-version and unknown-member strictness for every message.
			corpus = append(corpus, agreementBoth(
				target.label+"/wrong-contract-version", target.schemaName,
				mutatePayload(t, target.payload, func(object map[string]json.RawMessage) { object["contract_version"] = json.RawMessage("2") }), verify, false))
			corpus = append(corpus, agreementBoth(
				target.label+"/unknown-member", target.schemaName,
				mutatePayload(t, target.payload, func(object map[string]json.RawMessage) { object["unexpected"] = json.RawMessage(`"x"`) }), verify, false))
		}
	}

	corpus = append(corpus, heartbeatAgreementCases()...)
	corpus = append(corpus, sessionReadyAgreementCases()...)
	corpus = append(corpus, byteCounterAgreementCases(t)...)
	corpus = append(corpus, timestampAgreementCases()...)
	corpus = append(corpus, lengthAgreementCases(t)...)
	corpus = append(corpus, base64AgreementCases(t)...)
	corpus = append(corpus, jsonLayerAgreementCases()...)
	corpus = append(corpus, externalRecordAgreementCases(t)...)
	return corpus
}

// lengthAgreementCases pins the bounded string members against multi-byte
// input, where a byte-length check and the schema's code-point maxLength would
// otherwise disagree.
func lengthAgreementCases(t *testing.T) []agreementCase {
	t.Helper()
	verifyStream := func(data []byte) error { return ValidateControlPayload(data, 7, fixtureTime) }
	verifySession := func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }
	streamError := func(message string) string {
		return mutatePayloadRaw(t, `{"contract_version":1,"message_type":"stream_error","code":"internal_error","message":"","retryable":false}`, "message", mustJSONString(t, message))
	}
	healthReport := func(agentVersion string) string {
		return mutatePayloadRaw(t, `{"contract_version":1,"message_type":"health_report","report_id":"report-001","generated_at":"2026-08-29T12:00:00Z","active_streams":0,"queued_frames":0,"reconnect_count":0}`, "agent_version", mustJSONString(t, agentVersion))
	}
	return []agreementCase{
		agreementBoth("stream_error/message-256-code-points", tunnelSchemaName, streamError(strings.Repeat("é", 256)), verifyStream, true),
		agreementBoth("stream_error/message-257-code-points", tunnelSchemaName, streamError(strings.Repeat("é", 257)), verifyStream, false),
		agreementBoth("stream_error/message-empty", tunnelSchemaName, streamError(""), verifyStream, false),
		agreementBoth("health_report/agent_version-64-code-points", tunnelSchemaName, healthReport(strings.Repeat("é", 64)), verifySession, true),
		agreementBoth("health_report/agent_version-65-code-points", tunnelSchemaName, healthReport(strings.Repeat("é", 65)), verifySession, false),
		agreementBoth("health_report/agent_version-empty", tunnelSchemaName, healthReport(""), verifySession, true),
		agreementBoth("health_report/last_reconnect_at-empty-string", tunnelSchemaName, healthReport("v1"), verifySession, true),
		agreementBoth("health_report/last_reconnect_at-explicit-empty", tunnelSchemaName,
			mutatePayloadRaw(t, healthReport("v1"), "last_reconnect_at", `""`), verifySession, false),
	}
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func (target agreementTarget) verifier() func([]byte) error {
	if target.record {
		return recordVerifier(target.schemaName)
	}
	streamID := target.streamID
	return func(data []byte) error { return ValidateControlPayload(data, streamID, fixtureTime) }
}

func recordVerifier(schemaName string) func([]byte) error {
	switch schemaName {
	case authSchemaName:
		return func(data []byte) error {
			_, err := ParseDeviceSessionAuthorizationRecord(data)
			return err
		}
	case routeSchemaName:
		return func(data []byte) error {
			_, err := ParseEndpointRouteAssignmentRecord(data)
			return err
		}
	case revokeSchemaName:
		return func(data []byte) error {
			_, err := ParseRevocationSignal(data)
			return err
		}
	default:
		return func(data []byte) error {
			_, err := ParseGatewayStatusSignal(data)
			return err
		}
	}
}

// heartbeatAgreementCases covers every presence combination of the ping/pong
// timestamp members.
func heartbeatAgreementCases() []agreementCase {
	const schemaName = tunnelSchemaName
	control := func(streamID uint32) func([]byte) error {
		return func(data []byte) error { return ValidateControlPayload(data, streamID, fixtureTime) }
	}
	base := func(messageType, members string) string {
		return fmt.Sprintf(`{"contract_version":1,"message_type":"%s","ping_id":"ping-001"%s}`, messageType, members)
	}
	tests := []struct {
		name    string
		payload string
		valid   bool
	}{
		{"ping/sent_at-only", base("ping", `,"sent_at":"2026-08-29T12:00:00Z"`), true},
		{"ping/received_at-only", base("ping", `,"received_at":"2026-08-29T12:00:00Z"`), false},
		{"ping/both-timestamps", base("ping", `,"sent_at":"2026-08-29T12:00:00Z","received_at":"2026-08-29T12:00:00Z"`), false},
		{"ping/no-timestamp", base("ping", ""), false},
		{"ping/sent_at-null", base("ping", `,"sent_at":null`), false},
		{"ping/received_at-null", base("ping", `,"received_at":null`), false},
		{"pong/received_at-only", base("pong", `,"received_at":"2026-08-29T12:00:00Z"`), true},
		{"pong/sent_at-only", base("pong", `,"sent_at":"2026-08-29T12:00:00Z"`), false},
		{"pong/both-timestamps", base("pong", `,"sent_at":"2026-08-29T12:00:00Z","received_at":"2026-08-29T12:00:00Z"`), false},
		{"pong/no-timestamp", base("pong", ""), false},
		{"pong/received_at-null", base("pong", `,"received_at":null`), false},
		{"pong/sent_at-null", base("pong", `,"sent_at":null`), false},
	}
	cases := make([]agreementCase, 0, len(tests))
	for _, test := range tests {
		cases = append(cases, agreementBoth(test.name, schemaName, test.payload, control(0), test.valid))
	}
	return cases
}

// sessionReadyAgreementCases sweeps the cross-field rule
// idle_timeout_seconds >= 2 * heartbeat_interval_seconds across the whole
// declared range of both members, including one step either side of every
// boundary. The expectation is stated independently of both implementations.
func sessionReadyAgreementCases() []agreementCase {
	var cases []agreementCase
	verify := func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }
	for hb := 4; hb <= 61; hb++ {
		for _, it := range []int{14, 15, 16, 2*hb - 2, 2*hb - 1, 2 * hb, 2*hb + 1, 300, 301} {
			valid := hb >= 5 && hb <= 60 && it >= 15 && it <= 300 && it >= 2*hb
			payload := fmt.Sprintf(`{"contract_version":1,"message_type":"session_ready","session_id":"session-001","heartbeat_interval_seconds":%d,"idle_timeout_seconds":%d,"resume_challenge":"%s"}`, hb, it, challengeFixture)
			cases = append(cases, agreementBoth(fmt.Sprintf("session_ready/sweep/hb=%d,it=%d", hb, it), tunnelSchemaName, payload, verify, valid))
		}
	}
	return cases
}

func byteCounterAgreementCases(t *testing.T) []agreementCase {
	t.Helper()
	newCases := func(name, payload string, valid bool) agreementCase {
		return agreementBoth(name, statusSchemaName, payload, recordVerifier(statusSchemaName), valid)
	}
	status := func(body string) string {
		return fmt.Sprintf(`{"contract_version":1,"event_id":"status-001","observed_at":"2026-08-29T12:05:00Z",%s}`, body)
	}
	traffic := func(members string) string {
		return status(fmt.Sprintf(`"kind":"traffic_delta","device_id":"device-001","endpoint_id":"endpoint-001"%s`, members))
	}
	tests := []struct {
		name    string
		payload string
		valid   bool
	}{
		{"traffic_delta/bytes_from_public=0", traffic(`,"bytes_from_public":0`), true},
		{"traffic_delta/bytes_from_public=1073741824", traffic(`,"bytes_from_public":1073741824`), true},
		{"traffic_delta/bytes_from_public=1073741825", traffic(`,"bytes_from_public":1073741825`), false},
		{"traffic_delta/bytes_from_public=-1", traffic(`,"bytes_from_public":-1`), false},
		{"traffic_delta/bytes_to_public=0", traffic(`,"bytes_to_public":0`), true},
		{"traffic_delta/bytes_to_public=1073741824", traffic(`,"bytes_to_public":1073741824`), true},
		{"traffic_delta/bytes_to_public=1073741825", traffic(`,"bytes_to_public":1073741825`), false},
		{"traffic_delta/bytes_to_public=-1", traffic(`,"bytes_to_public":-1`), false},
		{"traffic_delta/only-one-counter", traffic(`,"bytes_to_public":2048`), true},
		{"traffic_delta/no-counter", traffic(""), false},
		{"traffic_delta/from-public-null", traffic(`,"bytes_from_public":null,"bytes_to_public":5`), false},
		{"traffic_delta/to-public-null", traffic(`,"bytes_from_public":5,"bytes_to_public":null`), false},
		{"traffic_delta/both-counters-null", traffic(`,"bytes_from_public":null,"bytes_to_public":null`), false},
		{"traffic_delta/without-endpoint", status(`"kind":"traffic_delta","device_id":"device-001","bytes_from_public":1`), false},
		{"traffic_delta/without-endpoint-or-counter", status(`"kind":"traffic_delta","device_id":"device-001"`), false},
		{"traffic_delta/empty-endpoint-id", status(`"kind":"traffic_delta","device_id":"device-001","endpoint_id":"","bytes_from_public":1`), false},
		{"session_connected/no-counters", status(`"kind":"session_connected","device_id":"device-001","session_id":"session-001"`), true},
		{"session_connected/zero-counters", status(`"kind":"session_connected","device_id":"device-001","bytes_from_public":0,"bytes_to_public":0`), true},
		{"session_connected/over-bound-counter", status(`"kind":"session_connected","device_id":"device-001","bytes_from_public":1073741825`), false},
		{"session_connected/null-counter", status(`"kind":"session_connected","device_id":"device-001","bytes_from_public":null`), false},
		{"session_connected/empty-session-id", status(`"kind":"session_connected","device_id":"device-001","session_id":""`), false},
		{"session_connected/null-session-id", status(`"kind":"session_connected","device_id":"device-001","session_id":null`), false},
		{"session_connected/empty-endpoint-id", status(`"kind":"session_connected","device_id":"device-001","endpoint_id":""`), false},
		{"session_connected/unknown-kind", status(`"kind":"traffic_total","device_id":"device-001"`), false},
		{"session_connected/unknown-member", status(`"kind":"session_connected","device_id":"device-001","unexpected":1`), false},
	}
	cases := make([]agreementCase, 0, len(tests))
	for _, test := range tests {
		cases = append(cases, newCases(test.name, test.payload, test.valid))
	}
	return cases
}

// timestampAgreementCases pins the timestamp grammar shared by the Go pattern
// plus time.Parse and the schema pattern plus the asserted date-time format.
func timestampAgreementCases() []agreementCase {
	verify := func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }
	pong := func(value string) string {
		return fmt.Sprintf(`{"contract_version":1,"message_type":"pong","ping_id":"ping-001","received_at":"%s"}`, value)
	}
	tests := []struct {
		value string
		valid bool
	}{
		{"2026-08-29T12:00:00Z", true},
		{"2026-08-29T12:00:00.1Z", true},
		{"2026-08-29T12:00:00.123456789Z", true},
		{"2026-08-29T12:00:00.000000000Z", true},
		{"2026-08-29T12:00:00.1234567890Z", false},
		{"2026-08-29T12:00:00.123456789012345Z", false},
		{"2026-02-30T12:00:00Z", false},
		{"2026-04-31T12:00:00Z", false},
		{"2026-06-31T12:00:00Z", false},
		{"2025-02-29T12:00:00Z", false},
		{"2024-02-29T12:00:00Z", true},
		{"2026-13-01T12:00:00Z", false},
		{"2026-00-01T12:00:00Z", false},
		{"2026-08-00T12:00:00Z", false},
		{"2026-08-29T24:00:00Z", false},
		{"2026-08-29T12:60:00Z", false},
		{"2026-08-29T12:00:60Z", false},
		{"2026-08-29T12:00:00,5Z", false},
		{"2026-08-29t12:00:00z", false},
		{"2026-08-29T12:00:00+00:00", false},
		{"2026-08-29T12:00:00", false},
		{"2026-08-29T12:00:00.Z", false},
		{"0000-01-01T00:00:00Z", true},
		{"9999-12-31T23:59:59Z", true},
	}
	cases := make([]agreementCase, 0, len(tests))
	for _, test := range tests {
		cases = append(cases, agreementBoth("timestamp/"+test.value, tunnelSchemaName, pong(test.value), verify, test.valid))
	}
	return cases
}

// nonCanonicalBase64 returns a string of the right length and alphabet that
// decodes to the same bytes as the canonical encoding but is not that
// encoding: the discarded trailing bits are non-zero.
func nonCanonicalBase64(size int) string {
	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, size))
	return canonical[:len(canonical)-1] + "B"
}

func base64AgreementCases(t *testing.T) []agreementCase {
	t.Helper()
	const reason = "base64url canonicality is a byte-level rule that JSON Schema cannot express (tunnel-protocol.md section 5)"
	control := func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	return []agreementCase{
		agreementGoOnly("client_nonce/non-canonical", tunnelSchemaName, reason,
			fmt.Sprintf(`{"contract_version":1,"message_type":"client_hello","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_token":"test_session_token_0123456789ABCDEF","client_nonce":"%s"}`, nonCanonicalBase64(32)), control),
		agreementGoOnly("client_auth/signature-non-canonical", tunnelSchemaName, reason,
			fmt.Sprintf(`{"contract_version":1,"message_type":"client_auth","session_id":"session-001","signature":"%s"}`, nonCanonicalBase64(64)), control),
		agreementGoOnly("resume_session/resume_nonce-non-canonical", tunnelSchemaName, reason,
			fmt.Sprintf(`{"contract_version":1,"message_type":"resume_session","device_id":"device-001","authorization_id":"auth-001","token_id":"token-001","session_id":"session-001","resume_nonce":"%s","resume_challenge":"%s","issued_at":"%s","signature":"%s"}`, nonCanonicalBase64(32), challengeFixture, issuedAtFixture, signature), control),
		agreementGoOnly("device_public_key/non-canonical", authSchemaName, reason,
			mutatePayloadRaw(t, compactFixture(t, filepath.Join("external", "device-session-authorization.valid.json")), "device_public_key", `"`+nonCanonicalBase64(32)+`"`), recordVerifier(authSchemaName)),
		agreementBoth("device_public_key/wrong-length", authSchemaName,
			mutatePayloadRaw(t, compactFixture(t, filepath.Join("external", "device-session-authorization.valid.json")), "device_public_key", `"AAAA"`), recordVerifier(authSchemaName), false),
		agreementBoth("token_sha256/upper-case", authSchemaName,
			mutatePayloadRaw(t, compactFixture(t, filepath.Join("external", "device-session-authorization.valid.json")), "token_sha256", `"`+strings.ToUpper(tokenSHA256Fixture)+`"`), recordVerifier(authSchemaName), false),
	}
}

// jsonLayerAgreementCases covers rules that live in the JSON parsing layer,
// which JSON Schema does not model.
func jsonLayerAgreementCases() []agreementCase {
	verifyStream := func(data []byte) error { return ValidateControlPayload(data, 7, fixtureTime) }
	verifySession := func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }
	streamClose := `{"contract_version":1,"message_type":"stream_close","reason_code":"completed"}`

	invalidUTF8 := append([]byte(`{"contract_version":1,"message_type":"stream_error","code":"internal_error","message":"`), byte(0xff))
	invalidUTF8 = append(invalidUTF8, []byte(`","retryable":false}`)...)

	return []agreementCase{
		agreementBoth("json/trailing-value", tunnelSchemaName, streamClose+` {}`, verifyStream, false),
		agreementBoth("json/invalid-utf8-outside-string", tunnelSchemaName, string(append([]byte(streamClose), byte(0xff))), verifyStream, false),
		agreementGoOnly("json/duplicate-member-name", tunnelSchemaName,
			"duplicate JSON member names are rejected at the parsing layer (tunnel-protocol.md section 5); JSON Schema sees only the decoded object",
			`{"contract_version":1,"message_type":"stream_close","reason_code":"cancelled","reason_code":"completed"}`, verifyStream),
		agreementGoOnly("json/invalid-utf8-inside-string", tunnelSchemaName,
			"invalid UTF-8 is rejected byte-wise before JSON semantics (tunnel-protocol.md section 5); encoding/json replaces it with U+FFFD instead of failing",
			string(invalidUTF8), verifyStream),
		agreementGoOnly("scope/stream_open-on-session-stream", tunnelSchemaName,
			"stream scope is a framing property carried in the frame header, not a control payload member (tunnel-protocol.md section 4)",
			`{"contract_version":1,"message_type":"stream_open","endpoint_id":"endpoint-001","assignment_id":"assign-001","local_endpoint_id":"local-http-001","request_id":"request-001"}`, func(data []byte) error { return ValidateControlPayload(data, 0, fixtureTime) }),
		agreementGoOnly("integer-literal/exponent", tunnelSchemaName,
			"integer fields accept only integer literals; JSON Schema cannot distinguish 1e3 from 1000 (tunnel-protocol.md section 5)",
			`{"contract_version":1,"message_type":"health_report","report_id":"report-001","generated_at":"2026-08-29T12:00:00Z","active_streams":1e3,"queued_frames":0,"reconnect_count":0}`, verifySession),
		agreementGoOnly("integer-literal/fraction", tunnelSchemaName,
			"integer fields accept only integer literals; JSON Schema cannot distinguish 3.0 from 3 (tunnel-protocol.md section 5)",
			fmt.Sprintf(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":3.0,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"%s"}`, challengeFixture), verifySession),
		agreementBoth("integer/uint64-max", tunnelSchemaName,
			fmt.Sprintf(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":18446744073709551615,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"%s"}`, challengeFixture), verifySession, true),
		agreementBoth("integer/uint64-overflow", tunnelSchemaName,
			fmt.Sprintf(`{"contract_version":1,"message_type":"session_resumed","session_id":"session-001","next_sequence":18446744073709551616,"resumed_at":"2026-08-29T12:00:00Z","resume_challenge":"%s"}`, challengeFixture), verifySession, false),
	}
}

const tokenSHA256Fixture = "fceb6a20fda55e114a7a11d0ee3ad98191d517c27f42591f2b16421f57a063f8"

func externalRecordAgreementCases(t *testing.T) []agreementCase {
	t.Helper()
	auth := compactFixture(t, filepath.Join("external", "device-session-authorization.valid.json"))
	route := compactFixture(t, filepath.Join("external", "endpoint-route-assignment.valid.json"))
	revoke := compactFixture(t, filepath.Join("external", "revocation-signal.valid.json"))
	verifyAuth := recordVerifier(authSchemaName)
	verifyRoute := recordVerifier(routeSchemaName)
	verifyRevoke := recordVerifier(revokeSchemaName)

	cases := []agreementCase{
		agreementBoth("auth/disabled-false", authSchemaName, mutatePayloadRaw(t, auth, "disabled", "false"), verifyAuth, true),
		agreementBoth("auth/disabled-string", authSchemaName, mutatePayloadRaw(t, auth, "disabled", `"false"`), verifyAuth, false),
		agreementBoth("auth/impossible-calendar-date", authSchemaName,
			mutatePayloadRaw(t, auth, "expires_at", `"2026-02-30T06:00:00Z"`), verifyAuth, false),
		agreementBoth("auth/offset-timestamp", authSchemaName,
			mutatePayloadRaw(t, auth, "expires_at", `"2026-08-30T06:00:00+00:00"`), verifyAuth, false),
		agreementBoth("route/enabled-true", routeSchemaName, mutatePayloadRaw(t, route, "enabled", "true"), verifyRoute, true),
		agreementBoth("route/enabled-string", routeSchemaName, mutatePayloadRaw(t, route, "enabled", `"true"`), verifyRoute, false),
		agreementBoth("revocation/unknown-subject-kind", revokeSchemaName,
			mutatePayloadRaw(t, revoke, "subject_kind", `"tenant"`), verifyRevoke, false),
		agreementBoth("revocation/unknown-reason-code", revokeSchemaName,
			mutatePayloadRaw(t, revoke, "reason_code", `"billing"`), verifyRevoke, false),
		agreementGoOnly("auth/issued_at-after-not_before", authSchemaName, orderingReason,
			mutatePayloadRaw(t, auth, "issued_at", `"2026-08-29T07:00:00Z"`), verifyAuth),
		agreementGoOnly("auth/not_before-equals-expires_at", authSchemaName, orderingReason,
			mutatePayloadRaw(t, auth, "not_before", `"2026-08-30T06:00:00Z"`), verifyAuth),
		agreementGoOnly("route/not_before-equals-expires_at", routeSchemaName, orderingReason,
			mutatePayloadRaw(t, route, "not_before", `"2026-08-30T06:00:00Z"`), verifyRoute),
	}

	for _, hostname := range hostnameAgreementValues() {
		cases = append(cases, agreementBoth("hostname/"+hostname.value, routeSchemaName,
			mutatePayloadRaw(t, route, "public_hostname", fmt.Sprintf("%q", hostname.value)), verifyRoute, hostname.valid))
	}
	return cases
}

const orderingReason = "timestamp ordering is a cross-field comparison that JSON Schema cannot express (external-control-panel-contract.md sections 2 and 3)"

type hostnameCase struct {
	value string
	valid bool
}

func hostnameAgreementValues() []hostnameCase {
	long253 := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 61)}, ".")
	long254 := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 62)}, ".")
	label64 := strings.Repeat("a", 64) + ".example"
	return []hostnameCase{
		{"demo.hooshix.example", true},
		{"a.example", true},
		{"EXAMPLE.COM", true},
		{"a-b.example", true},
		{"xn--bcher-kva.example", true},
		{long253, true},
		{long254, false},
		{"localhost", false},
		{"a.b", false},
		{"example.c", false},
		{"example.c0m", false},
		{"-bad.example", false},
		{"bad-.example", false},
		{"bad..example", false},
		{".example.com", false},
		{"example.com.", false},
		{"127.0.0.1", false},
		{"münich.example", false},
		{"under_score.example", false},
		{label64, false},
		{"", false},
		{strings.Repeat("a", 64) + ".example.com", false},
	}
}

func mutatePayload(t *testing.T, payload string, mutate func(map[string]json.RawMessage)) string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &object); err != nil {
		t.Fatalf("decode payload for mutation: %v", err)
	}
	mutate(object)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func mutatePayloadRaw(t *testing.T, payload, member, rawValue string) string {
	t.Helper()
	return mutatePayload(t, payload, func(object map[string]json.RawMessage) {
		object[member] = json.RawMessage(rawValue)
	})
}

func compactFixture(t *testing.T, name string) string {
	t.Helper()
	var value any
	data := readFixture(t, name)
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// schemaRequiredMembers reads the `required` array of a schema definition (or
// of the document root when defName is empty) so the corpus is generated from
// the published contract rather than from a duplicated list.
func schemaRequiredMembers(t *testing.T, schemaName, defName string) []string {
	t.Helper()
	raw := readContract(t, schemaName)
	if defName != "" {
		var document struct {
			Defs map[string]json.RawMessage `json:"$defs"`
		}
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode %s: %v", schemaName, err)
		}
		definition, ok := document.Defs[defName]
		if !ok {
			t.Fatalf("%s has no $defs/%s", schemaName, defName)
		}
		raw = definition
	}
	var holder struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &holder); err != nil {
		t.Fatalf("decode required members of %s/%s: %v", schemaName, defName, err)
	}
	if len(holder.Required) == 0 {
		t.Fatalf("%s/%s declares no required members to exercise", schemaName, defName)
	}
	return holder.Required
}
