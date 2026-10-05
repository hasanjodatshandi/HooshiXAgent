package contractv2

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseServiceEndpoint(t *testing.T) {
	record := validServiceEndpoint()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseServiceEndpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, record) {
		t.Fatalf("parsed endpoint mismatch: got %+v want %+v", parsed, record)
	}
}

func TestPublicTCPServiceEndpointPolicy(t *testing.T) {
	record := ServiceEndpoint{
		Kind: "service_endpoint", ContractVersion: ProtocolVersion,
		EndpointID: "endpoint-public-1", OwnerDeviceID: "device-1",
		Protocol: ProtocolTCP, ApplicationProtocol: ApplicationGeneric,
		LocalEndpointID: "ssh-1", Exposure: ExposurePublic, Enabled: true,
		PublicPort: 22022, AllowedSourceCIDRs: []string{"0.0.0.0/0", "192.0.2.0/24"},
		CreatedAt: "2026-09-28T08:00:00Z", Revision: 1,
	}
	if err := ValidateServiceEndpoint(record); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ServiceEndpoint){
		"missing port":            func(value *ServiceEndpoint) { value.PublicPort = 0 },
		"privileged port":         func(value *ServiceEndpoint) { value.PublicPort = 22 },
		"missing sources":         func(value *ServiceEndpoint) { value.AllowedSourceCIDRs = nil },
		"host instead of network": func(value *ServiceEndpoint) { value.AllowedSourceCIDRs = []string{"192.0.2.1/24"} },
		"rdp public":              func(value *ServiceEndpoint) { value.ApplicationProtocol = ApplicationRDP },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := record
			mutate(&candidate)
			if err := ValidateServiceEndpoint(candidate); err == nil {
				t.Fatal("invalid public TCP endpoint was accepted")
			}
		})
	}
}

func TestUDPServiceEndpointRequiresLeaseForPublicExposure(t *testing.T) {
	record := validServiceEndpoint()
	record.Protocol = ProtocolUDP
	record.Exposure = ExposurePrivate
	if err := ValidateServiceEndpoint(record); err != nil {
		t.Fatalf("private UDP endpoint: %v", err)
	}
	record.Exposure = ExposurePublic
	if err := ValidateServiceEndpoint(record); err == nil {
		t.Fatal("public UDP endpoint without a port lease was accepted")
	}
	record.PublicPort = 22024
	record.AllowedSourceCIDRs = []string{"192.0.2.0/24"}
	if err := ValidateServiceEndpoint(record); err != nil {
		t.Fatalf("public UDP endpoint with source-scoped port lease: %v", err)
	}
}

func TestParseServiceEndpointRejectsMalformedRecords(t *testing.T) {
	tests := map[string]string{
		"missing enabled":  `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","owner_device_id":"device-1","protocol":"http","local_endpoint_id":"web-1","exposure":"public","created_at":"2026-09-27T08:00:00Z","revision":1}`,
		"null enabled":     `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","owner_device_id":"device-1","protocol":"http","local_endpoint_id":"web-1","exposure":"public","enabled":null,"created_at":"2026-09-27T08:00:00Z","revision":1}`,
		"unknown member":   `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","owner_device_id":"device-1","protocol":"http","local_endpoint_id":"web-1","exposure":"public","enabled":true,"created_at":"2026-09-27T08:00:00Z","revision":1,"target":"127.0.0.1:80"}`,
		"duplicate member": `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","endpoint_id":"endpoint-2","owner_device_id":"device-1","protocol":"http","local_endpoint_id":"web-1","exposure":"public","enabled":true,"created_at":"2026-09-27T08:00:00Z","revision":1}`,
		"raw target as id": `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","owner_device_id":"device-1","protocol":"http","local_endpoint_id":"127.0.0.1:80/path","exposure":"public","enabled":true,"created_at":"2026-09-27T08:00:00Z","revision":1}`,
		"bad protocol":     `{"kind":"service_endpoint","contract_version":2,"endpoint_id":"endpoint-1","owner_device_id":"device-1","protocol":"rdp","local_endpoint_id":"rdp-1","exposure":"private","enabled":true,"created_at":"2026-09-27T08:00:00Z","revision":1}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseServiceEndpoint([]byte(payload)); err == nil {
				t.Fatal("malformed service endpoint was accepted")
			}
		})
	}
}

func validServiceEndpoint() ServiceEndpoint {
	return ServiceEndpoint{
		Kind:            "service_endpoint",
		ContractVersion: ProtocolVersion,
		EndpointID:      "endpoint-1",
		OwnerDeviceID:   "device-1",
		Protocol:        ProtocolHTTP,
		LocalEndpointID: "web-1",
		Exposure:        ExposurePublic,
		Enabled:         true,
		CreatedAt:       "2026-09-27T08:00:00Z",
		Revision:        1,
	}
}
