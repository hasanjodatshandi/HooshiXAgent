package contractv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestLanguageNeutralSchemasValidateFixtures(t *testing.T) {
	t.Parallel()

	external := []struct {
		name    string
		schema  string
		fixture string
	}{
		{
			name:    "device session authorization",
			schema:  filepath.Join("external", "device-session-authorization.schema.json"),
			fixture: filepath.Join("external", "device-session-authorization.valid.json"),
		},
		{
			name:    "endpoint route assignment",
			schema:  filepath.Join("external", "endpoint-route-assignment.schema.json"),
			fixture: filepath.Join("external", "endpoint-route-assignment.valid.json"),
		},
		{
			name:    "revocation signal",
			schema:  filepath.Join("external", "revocation-signal.schema.json"),
			fixture: filepath.Join("external", "revocation-signal.valid.json"),
		},
		{
			name:    "gateway status signal",
			schema:  filepath.Join("external", "gateway-status-signal.schema.json"),
			fixture: filepath.Join("external", "gateway-status-signal.valid.json"),
		},
	}
	for _, test := range external {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			schema := compileSchema(t, test.schema)
			validateSchemaFixture(t, schema, readFixture(t, test.fixture))
		})
	}

	t.Run("tunnel handshake control messages", func(t *testing.T) {
		t.Parallel()
		schema := compileSchema(t, "tunnel-control.schema.json")
		var fixture map[string]json.RawMessage
		decodeFixture(t, filepath.Join("tunnel", "handshake.valid.json"), &fixture)
		for name, message := range fixture {
			if err := validateSchemaValue(schema, message); err != nil {
				t.Fatalf("%s failed tunnel-control schema: %v", name, err)
			}
		}
	})

	t.Run("tunnel health_report and session_ready", func(t *testing.T) {
		t.Parallel()
		schema := compileSchema(t, "tunnel-control.schema.json")
		for _, name := range []string{
			filepath.Join("tunnel", "health-report.valid.json"),
			filepath.Join("tunnel", "session-ready.valid.json"),
		} {
			if err := validateSchemaValue(schema, readFixture(t, name)); err != nil {
				t.Fatalf("%s failed tunnel-control schema: %v", name, err)
			}
		}
		for _, name := range []string{
			filepath.Join("tunnel", "health-report.invalid.json"),
			filepath.Join("tunnel", "session-ready.invalid.json"),
		} {
			if err := validateSchemaValue(schema, readFixture(t, name)); err == nil {
				t.Fatalf("%s must fail the tunnel-control schema", name)
			}
		}
	})
}

// TestStructMarshalledHealthReportSatisfiesPublishedSchema is the binding that
// keeps contractv1.HealthReport and the published schema from drifting apart:
// the payload produced by the real marshal path must satisfy the normative
// schema, and the schema must reject the same payload with a required member
// removed.
func TestStructMarshalledHealthReportSatisfiesPublishedSchema(t *testing.T) {
	t.Parallel()

	schema := compileSchema(t, "tunnel-control.schema.json")
	report := HealthReport{
		ContractVersion: ProtocolVersion,
		MessageType:     "health_report",
		ReportID:        "report-struct-001",
		GeneratedAt:     fixtureTime.Format(time.RFC3339),
		ActiveStreams:   2,
		QueuedFrames:    7,
		ReconnectCount:  4,
		LastReconnectAt: fixtureTime.Add(time.Minute).Format(time.RFC3339),
		AgentVersion:    "v1.2.3",
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal HealthReport: %v", err)
	}
	if err := validateSchemaValue(schema, payload); err != nil {
		t.Fatalf("struct-marshalled health_report fails the published schema: %v", err)
	}

	// The minimal struct form (optional members omitted) is equally valid.
	report.LastReconnectAt = ""
	report.AgentVersion = ""
	payload, err = json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal minimal HealthReport: %v", err)
	}
	if err := validateSchemaValue(schema, payload); err != nil {
		t.Fatalf("minimal struct-marshalled health_report fails the published schema: %v", err)
	}

	// Dropping a member that the schema marks required must fail on both the
	// schema side and the Go side. This is the exact drift that let
	// reconnect_count disappear unnoticed.
	drifted := map[string]any{
		"contract_version": ProtocolVersion,
		"message_type":     "health_report",
		"report_id":        "report-struct-001",
		"generated_at":     fixtureTime.Format(time.RFC3339),
		"active_streams":   2,
		"queued_frames":    7,
	}
	driftedPayload, err := json.Marshal(drifted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSchemaValue(schema, driftedPayload); err == nil {
		t.Fatal("schema accepted a health_report without reconnect_count")
	}
	if err := ValidateControlPayload(driftedPayload, 0, fixtureTime); err == nil {
		t.Fatal("Go validator accepted a health_report without reconnect_count")
	}
}

func TestLanguageNeutralSchemaRejectsRawLocalTarget(t *testing.T) {
	t.Parallel()

	schema := compileSchema(t, filepath.Join("external", "endpoint-route-assignment.schema.json"))
	if err := validateSchemaValue(schema, readFixture(t, filepath.Join("invalid", "endpoint-route-assignment.raw-local-target.json"))); err == nil {
		t.Fatal("expected JSON Schema to reject raw local_target field")
	}
}

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	data := readContract(t, name)
	compiler := jsonschema.NewCompiler()
	// The contract asserts `format: date-time` as a normative rule, not as an
	// annotation. Without AssertFormat the compiler only records the format and
	// impossible calendar timestamps such as 2026-02-30T12:00:00Z pass.
	compiler.AssertFormat = true
	uri := "memory://contract/" + filepath.ToSlash(name)
	if err := compiler.AddResource(uri, bytes.NewReader(data)); err != nil {
		t.Fatalf("add schema resource %s: %v", name, err)
	}
	schema, err := compiler.Compile(uri)
	if err != nil {
		t.Fatalf("compile schema %s: %v", name, err)
	}
	return schema
}

func validateSchemaFixture(t *testing.T, schema *jsonschema.Schema, data []byte) {
	t.Helper()
	if err := validateSchemaValue(schema, data); err != nil {
		t.Fatalf("fixture failed schema validation: %v", err)
	}
}

// validateSchemaValue decodes the payload and validates it against the schema.
//
// Numbers are decoded with json.UseNumber so the schema's big.Rat comparisons
// are exact; a float64 round-trip would make the largest valid uint64
// next_sequence look like it exceeds its own maximum. Trailing JSON values are
// rejected, matching the strict decoder used by the Go implementation.
func validateSchemaValue(schema *jsonschema.Schema, data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON is invalid: %w", err)
	}
	return schema.Validate(value)
}
