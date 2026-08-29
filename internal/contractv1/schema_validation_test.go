package contractv1

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

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

func validateSchemaValue(schema *jsonschema.Schema, data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	return schema.Validate(value)
}
