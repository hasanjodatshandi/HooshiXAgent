package contractv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const ProtocolVersion = 2

type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
)

type Exposure string

const (
	ExposurePrivate Exposure = "private"
	ExposurePublic  Exposure = "public"
	ExposureBoth    Exposure = "both"
)

type ApplicationProtocol string

const (
	ApplicationGeneric ApplicationProtocol = "generic"
	ApplicationRDP     ApplicationProtocol = "rdp"
)

type ServiceEndpoint struct {
	Kind                string              `json:"kind"`
	ContractVersion     int                 `json:"contract_version"`
	EndpointID          string              `json:"endpoint_id"`
	OwnerDeviceID       string              `json:"owner_device_id"`
	Protocol            Protocol            `json:"protocol"`
	ApplicationProtocol ApplicationProtocol `json:"application_protocol,omitempty"`
	LocalEndpointID     string              `json:"local_endpoint_id"`
	PublicPort          int                 `json:"public_port,omitempty"`
	AllowedSourceCIDRs  []string            `json:"allowed_source_cidrs,omitempty"`
	Exposure            Exposure            `json:"exposure"`
	Enabled             bool                `json:"enabled"`
	CreatedAt           string              `json:"created_at"`
	Revision            uint64              `json:"revision"`
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

func ParseServiceEndpoint(data []byte) (ServiceEndpoint, error) {
	var record ServiceEndpoint
	if err := validateStrictJSONObject(data); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode service endpoint: %w", err)
	}
	if err := requireMembers(data, "kind", "contract_version", "endpoint_id", "owner_device_id", "protocol", "local_endpoint_id", "exposure", "enabled", "created_at", "revision"); err != nil {
		return record, err
	}
	if err := ValidateServiceEndpoint(record); err != nil {
		return record, err
	}
	return record, nil
}

func ValidateServiceEndpoint(record ServiceEndpoint) error {
	if record.Kind != "service_endpoint" {
		return errors.New("kind must be service_endpoint")
	}
	if record.ContractVersion != ProtocolVersion {
		return fmt.Errorf("contract_version must be %d", ProtocolVersion)
	}
	for name, value := range map[string]string{
		"endpoint_id":       record.EndpointID,
		"owner_device_id":   record.OwnerDeviceID,
		"local_endpoint_id": record.LocalEndpointID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	switch record.Protocol {
	case ProtocolHTTP, ProtocolTCP, ProtocolUDP:
	default:
		return fmt.Errorf("protocol %q is unsupported", record.Protocol)
	}
	switch record.Exposure {
	case ExposurePrivate, ExposurePublic, ExposureBoth:
	default:
		return fmt.Errorf("exposure %q is unsupported", record.Exposure)
	}
	switch record.ApplicationProtocol {
	case "", ApplicationGeneric:
	case ApplicationRDP:
		if record.Protocol != ProtocolTCP || record.Exposure != ExposurePrivate {
			return errors.New("rdp endpoints must use tcp with private exposure")
		}
	default:
		return fmt.Errorf("application_protocol %q is unsupported", record.ApplicationProtocol)
	}
	publicPort := (record.Protocol == ProtocolTCP || record.Protocol == ProtocolUDP) && (record.Exposure == ExposurePublic || record.Exposure == ExposureBoth)
	if publicPort {
		if record.PublicPort < 1024 || record.PublicPort > 65535 {
			return errors.New("public TCP/UDP endpoints require public_port between 1024 and 65535")
		}
		if len(record.AllowedSourceCIDRs) < 1 || len(record.AllowedSourceCIDRs) > 16 {
			return errors.New("public TCP/UDP endpoints require 1..16 allowed_source_cidrs")
		}
		seen := make(map[string]struct{}, len(record.AllowedSourceCIDRs))
		for _, raw := range record.AllowedSourceCIDRs {
			if !canonicalIPv4CIDR(raw) {
				return fmt.Errorf("allowed_source_cidrs entry %q must be a canonical IPv4 network CIDR", raw)
			}
			if _, exists := seen[raw]; exists {
				return fmt.Errorf("allowed_source_cidrs entry %q is duplicated", raw)
			}
			seen[raw] = struct{}{}
		}
	} else if record.PublicPort != 0 || len(record.AllowedSourceCIDRs) != 0 {
		return errors.New("public_port and allowed_source_cidrs are valid only for public TCP/UDP endpoints")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil || createdAt.Format(time.RFC3339Nano) != record.CreatedAt {
		return errors.New("created_at must be a canonical UTC RFC3339 timestamp")
	}
	if record.Revision == 0 || record.Revision > 1<<53-1 {
		return errors.New("revision must be between 1 and 9007199254740991")
	}
	return nil
}

func canonicalIPv4CIDR(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	prefix, err := strconv.Atoi(parts[1])
	if err != nil || prefix < 0 || prefix > 32 || strconv.Itoa(prefix) != parts[1] {
		return false
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return false
	}
	var address uint32
	for _, octet := range octets {
		value, err := strconv.Atoi(octet)
		if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != octet {
			return false
		}
		address = address<<8 | uint32(value)
	}
	if prefix == 0 {
		return address == 0
	}
	mask := ^uint32(0) << (32 - prefix)
	return address&mask == address
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
	if delim, ok := first.(json.Delim); !ok || delim != '{' {
		return errors.New("JSON payload must be one object")
	}
	if _, err := consumeObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func consumeObject(decoder *json.Decoder) (map[string]json.Token, error) {
	members := make(map[string]json.Token)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("JSON object member name must be a string")
		}
		if _, exists := members[key]; exists {
			return nil, fmt.Errorf("duplicate JSON object member name: %q", key)
		}
		value, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if err := consumeValue(decoder, value); err != nil {
			return nil, err
		}
		members[key] = value
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := closing.(json.Delim); !ok || delim != '}' {
		return nil, errors.New("invalid JSON object close")
	}
	return members, nil
}

func consumeValue(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		_, err := consumeObject(decoder)
		return err
	case '[':
		for decoder.More() {
			item, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeValue(decoder, item); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closeDelim, ok := closing.(json.Delim); !ok || closeDelim != ']' {
			return errors.New("invalid JSON array close")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func requireMembers(data []byte, names ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if _, err := decoder.Token(); err != nil {
		return err
	}
	members, err := consumeObject(decoder)
	if err != nil {
		return err
	}
	for _, name := range names {
		value, ok := members[name]
		if !ok {
			return fmt.Errorf("%s is required by the contract", name)
		}
		if value == nil {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}
