package contractv1

import (
	"strconv"
	"testing"
	"time"
)

func windowUpdate(streamID uint32, body string) error {
	return ValidateControlPayload([]byte(body), streamID, time.Now())
}

func TestStreamWindowUpdateValidation(t *testing.T) {
	const valid = `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":65536}`
	if err := windowUpdate(7, valid); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
	maxCredit := `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":` + strconv.Itoa(MaxWindowCreditBytes) + `}`
	if err := windowUpdate(7, maxCredit); err != nil {
		t.Fatalf("boundary update rejected: %v", err)
	}

	cases := []struct {
		name     string
		streamID uint32
		body     string
	}{
		{"session scope", 0, valid},
		{"zero credit", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":0}`},
		{"missing credit", 7, `{"contract_version":1,"message_type":"stream_window_update"}`},
		{"null credit", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":null}`},
		{"negative credit", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":-1}`},
		{"fractional credit", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":1.5}`},
		{"oversized credit", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":` + strconv.Itoa(MaxWindowCreditBytes+1) + `}`},
		{"wrong contract", 7, `{"contract_version":2,"message_type":"stream_window_update","credit_bytes":16}`},
		{"wrong type", 7, `{"contract_version":1,"message_type":"stream_half_close","credit_bytes":16}`},
		{"unknown field", 7, `{"contract_version":1,"message_type":"stream_window_update","credit_bytes":16,"stream":7}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := windowUpdate(tc.streamID, tc.body); err == nil {
				t.Fatalf("invalid update accepted: %s", tc.body)
			}
		})
	}
}
