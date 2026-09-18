package contractv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

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
	if err := consumeJSONObject(decoder); err != nil {
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

func consumeJSONObject(decoder *json.Decoder) error {
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
		if err := consumeJSONValue(decoder, valueToken); err != nil {
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

func consumeJSONValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		// Strings, numbers, booleans, and null carry no nested structure.
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder)
	case '[':
		return consumeJSONArray(decoder)
	default:
		// json.Decoder only yields '{' or '[' as a value token, so this is
		// the defensive branch for a decoder/walker disagreement. It is
		// exercised directly by TestConsumeJSONValueRejectsClosingDelimiter.
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func consumeJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		item, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON array item: %w", err)
		}
		if err := consumeJSONValue(decoder, item); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON array close: %w", err)
	}
	if closeDelim, ok := closing.(json.Delim); !ok || closeDelim != ']' {
		return errors.New("invalid JSON array close")
	}
	return nil
}

// scanTopLevelMembers returns the value token of every top-level member of a
// JSON object, keyed by member name. A nil token means the JSON literal null.
// The payload must already have passed validateStrictJSONObject.
func scanTopLevelMembers(data []byte) (map[string]json.Token, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	members := make(map[string]json.Token)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON object key: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("JSON object member name must be a string")
		}
		valueToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON value for %q: %w", key, err)
		}
		if err := consumeJSONValue(decoder, valueToken); err != nil {
			return nil, err
		}
		members[key] = valueToken
	}
	return members, nil
}

// rejectNullMembers rejects any top-level member explicitly set to JSON null.
// The v1 contract defines no nullable member, so an explicit null is exactly as
// malformed as an absent member. encoding/json leaves both at the Go zero
// value without error, which would make `false`, `0`, and `""`
// indistinguishable from a validated value and let a malformed record fail
// open (see external-control-panel-contract.md section 6).
func rejectNullMembers(data []byte) error {
	members, err := scanTopLevelMembers(data)
	if err != nil {
		return err
	}
	var null []string
	for name, token := range members {
		if token == nil {
			null = append(null, name)
		}
	}
	if len(null) == 0 {
		return nil
	}
	// Report a stable member name so the rejection is deterministic.
	sort.Strings(null)
	return fmt.Errorf("%s must not be null", null[0])
}

// requirePresent rejects a payload that omits, or explicitly nulls, a member
// the schema marks required. It is applied to the required members whose Go
// zero value is itself a valid contract value (`false`, `0`), where an absent
// member would otherwise satisfy every downstream bound check.
func requirePresent(data []byte, names ...string) error {
	members, err := scanTopLevelMembers(data)
	if err != nil {
		return err
	}
	for _, name := range names {
		token, ok := members[name]
		if !ok {
			return fmt.Errorf("%s is required by the contract", name)
		}
		if token == nil {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

// rejectEmptyMembers rejects an explicitly empty string for an optional member
// whose schema forbids the empty value (a `minLength` of 1, or an identifier or
// timestamp pattern). encoding/json cannot distinguish an absent member from an
// empty one, so without this check an empty value would silently mean "absent"
// and fail open.
func rejectEmptyMembers(data []byte, names ...string) error {
	members, err := scanTopLevelMembers(data)
	if err != nil {
		return err
	}
	for _, name := range names {
		if value, ok := members[name].(string); ok && value == "" {
			return fmt.Errorf("%s must not be empty when present", name)
		}
	}
	return nil
}
