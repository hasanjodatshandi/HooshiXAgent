package contractv1

import "testing"

func FuzzExternalMetadataRecordParsing(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"contract_version":1,"authorization_id":"auth-001","device_id":"device-001","device_public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","token_id":"token-001","token_sha256":"fceb6a20fda55e114a7a11d0ee3ad98191d517c27f42591f2b16421f57a063f8","issued_at":"2026-08-29T06:00:00Z","not_before":"2026-08-29T06:00:00Z","expires_at":"2026-08-30T06:00:00Z","disabled":false}`),
		[]byte(`{"contract_version":1,"assignment_id":"assign-001","endpoint_id":"endpoint-001","public_hostname":"demo.hooshix.example","device_id":"device-001","local_endpoint_id":"local-http-001","enabled":true,"not_before":"2026-08-29T06:00:00Z","expires_at":"2026-08-30T06:00:00Z"}`),
		[]byte(`{"contract_version":1,"event_id":"revoke-001","subject_kind":"device_session_authorization","subject_id":"auth-001","effective_at":"2026-08-29T12:00:00Z","reason_code":"credential_revoked"}`),
		[]byte(`{"contract_version":1,"event_id":"status-001","observed_at":"2026-08-29T12:05:00Z","kind":"traffic_delta","device_id":"device-001","session_id":"session-001","endpoint_id":"endpoint-001","bytes_from_public":1024,"bytes_to_public":2048}`),
		[]byte(`{"contract_version":1,"assignment_id":"a","assignment_id":"b"}`),
		[]byte{0xff, 0xfe, 0xfd},
	}
	for i, seed := range seeds {
		f.Add(seed, uint8(i%4))
	}

	f.Fuzz(func(t *testing.T, data []byte, parser uint8) {
		switch parser % 4 {
		case 0:
			_, _ = ParseDeviceSessionAuthorizationRecord(data)
		case 1:
			_, _ = ParseEndpointRouteAssignmentRecord(data)
		case 2:
			_, _ = ParseRevocationSignal(data)
		case 3:
			_, _ = ParseGatewayStatusSignal(data)
		}
	})
}

func FuzzContractHostnameValidation(f *testing.F) {
	for _, seed := range []string{
		"demo.hooshix.example",
		"a-b.example",
		"localhost",
		"-bad.example",
		"bad-.example",
		"bad..example",
		"EXAMPLE.COM",
		"example.com.",
		"127.0.0.1",
		"münich.example",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, hostname string) {
		first := validateHostname(hostname)
		second := validateHostname(hostname)
		if (first == nil) != (second == nil) {
			t.Fatalf("hostname validation is not deterministic for %q: first=%v second=%v", hostname, first, second)
		}
	})
}
