package contractv1

import (
	"encoding/binary"
	"testing"
)

func TestSequenceTrackerRequiresFirstSequenceOneAndRejectsWrap(t *testing.T) {
	var tracker SequenceTracker
	if err := tracker.Accept(2); err == nil {
		t.Fatal("first sequence other than 1 was accepted")
	}
	if tracker.Last() != 0 {
		t.Fatalf("rejected first sequence changed tracker state: %d", tracker.Last())
	}

	exhausted := SequenceTracker{last: MaxSequence}
	if err := exhausted.Accept(1); err == nil {
		t.Fatal("sequence wrap was accepted")
	}
	if exhausted.Last() != MaxSequence {
		t.Fatal("sequence exhaustion changed tracker state")
	}
	if _, err := NextSequence(MaxSequence); err == nil {
		t.Fatal("outbound sequence wrap was allowed")
	}
}

func TestStrictJSONRejectsNestedAndEscapedDuplicateKeys(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"contract_version":1,"message_type":"stream_close","reason_code":"completed","reason_code":"completed"}`),
		[]byte(`{"contract_version":1,"message_type":"stream_error","code":"internal_error","message":"x","retryable":false,"nested":{"a":1,"a":2}}`),
		[]byte(`{"contract_version":1,"message_type":"stream_close","reason_code":"completed","reason_\u0063ode":"cancelled"}`),
	}
	for _, payload := range tests {
		if err := validateStrictJSONObject(payload); err == nil {
			t.Fatalf("duplicate-key JSON accepted: %s", payload)
		}
	}
}

func FuzzDecodeFrameStrictness(f *testing.F) {
	valid, err := EncodeFrame(Frame{Kind: KindData, StreamID: 1, Sequence: 1, Payload: []byte("seed")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not-a-frame"))
	f.Add(make([]byte, HeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := DecodeFrame(data)
		if err != nil {
			return
		}
		encoded, err := EncodeFrame(frame)
		if err != nil {
			t.Fatalf("decoded frame could not be re-encoded: %v", err)
		}
		if len(encoded) < HeaderSize || binary.BigEndian.Uint64(encoded[16:24]) == 0 {
			t.Fatal("successful frame round-trip violated sequence/header invariant")
		}
	})
}

func FuzzValidateControlPayloadStrictness(f *testing.F) {
	f.Add([]byte(`{"contract_version":1,"message_type":"stream_close","reason_code":"completed"}`), uint32(1))
	f.Add([]byte(`{"contract_version":1,"message_type":"stream_close","reason_code":"completed","reason_code":"cancelled"}`), uint32(1))
	invalidUTF8 := append([]byte(`{"contract_version":1,"message_type":"stream_error","code":"internal_error","message":"`), byte(0xff))
	invalidUTF8 = append(invalidUTF8, []byte(`","retryable":false}`)...)
	f.Add(invalidUTF8, uint32(1))

	f.Fuzz(func(t *testing.T, data []byte, streamID uint32) {
		_ = ValidateControlPayload(data, streamID, fixtureTime)
	})
}
