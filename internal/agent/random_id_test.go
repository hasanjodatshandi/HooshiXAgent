package agent

import (
	"strings"
	"testing"
)

// TestRandomIDContractSafe proves the health_report report_id can never start
// with a base64url character rejected by the contract ID grammar. The raw
// randomNonce() output CAN start with '-' or '_' (roughly 1 in 64 samples per
// leading char), which previously killed live sessions with "control violation".
func TestRandomIDContractSafe(t *testing.T) {
	const idPatternPrefix = "report-"
	for i := 0; i < 10000; i++ {
		id, err := randomID("report")
		if err != nil {
			t.Fatalf("randomID: %v", err)
		}
		if !strings.HasPrefix(id, idPatternPrefix) {
			t.Fatalf("id %q lost its safe prefix", id)
		}
		rest := strings.TrimPrefix(id, idPatternPrefix)
		if rest == "" {
			t.Fatalf("id %q has no entropy after prefix", id)
		}
		// First character of the whole ID must be alphanumeric (contract
		// idPattern: ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$).
		first := id[0]
		if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
			t.Fatalf("id %q starts with non-alphanumeric %q", id, string(first))
		}
	}
}

// TestRandomNonceCanStartUnsafeChars documents why randomNonce alone is not a
// valid contract ID: its base64url output can begin with '-' or '_'.
func TestRandomNonceCanStartUnsafeChars(t *testing.T) {
	found := false
	for i := 0; i < 20000 && !found; i++ {
		nonce, err := randomNonce()
		if err != nil {
			t.Fatalf("randomNonce: %v", err)
		}
		if nonce[0] == '-' || nonce[0] == '_' {
			found = true
		}
	}
	if !found {
		t.Log("no unsafe-leading nonce sampled in this run (statistical; expected ~1/32 per sample)")
	}
}
