package contractv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder)
	case '[':
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
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
