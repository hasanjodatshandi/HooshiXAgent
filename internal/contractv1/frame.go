// Package contractv1 provides the Go reference implementation of the
// language-neutral AG-3 contract. It contains framing and validation only; it
// does not implement Agent/Gateway networking or Control Panel business logic.
package contractv1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderSize        = 24
	ProtocolVersion   = 1
	MaxControlPayload = 64 * 1024
	MaxDataPayload    = 1024 * 1024
)

var magic = [4]byte{'H', 'X', 'T', '1'}

type Kind uint8

const (
	KindControl Kind = 1
	KindData    Kind = 2
)

type Frame struct {
	Kind     Kind
	StreamID uint32
	Sequence uint64
	Payload  []byte
}

func EncodeFrame(frame Frame) ([]byte, error) {
	if err := validateFrameFields(frame); err != nil {
		return nil, err
	}

	encoded := make([]byte, HeaderSize+len(frame.Payload))
	copy(encoded[0:4], magic[:])
	encoded[4] = ProtocolVersion
	encoded[5] = byte(frame.Kind)
	binary.BigEndian.PutUint16(encoded[6:8], 0)
	binary.BigEndian.PutUint32(encoded[8:12], frame.StreamID)
	binary.BigEndian.PutUint32(encoded[12:16], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint64(encoded[16:24], frame.Sequence)
	copy(encoded[HeaderSize:], frame.Payload)
	return encoded, nil
}

func DecodeFrame(encoded []byte) (Frame, error) {
	if len(encoded) < HeaderSize {
		return Frame{}, fmt.Errorf("frame shorter than %d-byte header", HeaderSize)
	}
	if string(encoded[0:4]) != string(magic[:]) {
		return Frame{}, errors.New("invalid frame magic")
	}
	if encoded[4] != ProtocolVersion {
		return Frame{}, fmt.Errorf("unsupported protocol version: %d", encoded[4])
	}
	kind := Kind(encoded[5])
	if kind != KindControl && kind != KindData {
		return Frame{}, fmt.Errorf("unknown frame kind: %d", encoded[5])
	}
	if flags := binary.BigEndian.Uint16(encoded[6:8]); flags != 0 {
		return Frame{}, fmt.Errorf("reserved flags must be zero: 0x%04x", flags)
	}

	payloadLength := binary.BigEndian.Uint32(encoded[12:16])
	if uint64(payloadLength) != uint64(len(encoded)-HeaderSize) {
		return Frame{}, fmt.Errorf("payload length mismatch: header=%d actual=%d", payloadLength, len(encoded)-HeaderSize)
	}
	if payloadLength > maxPayloadForKind(kind) {
		return Frame{}, fmt.Errorf("payload exceeds %s limit: %d", kind, payloadLength)
	}

	frame := Frame{
		Kind:     kind,
		StreamID: binary.BigEndian.Uint32(encoded[8:12]),
		Sequence: binary.BigEndian.Uint64(encoded[16:24]),
		Payload:  append([]byte(nil), encoded[HeaderSize:]...),
	}
	if err := validateFrameFields(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func validateFrameFields(frame Frame) error {
	if frame.Kind != KindControl && frame.Kind != KindData {
		return fmt.Errorf("unknown frame kind: %d", frame.Kind)
	}
	if frame.Sequence == 0 {
		return errors.New("sequence must start at 1")
	}
	if len(frame.Payload) > int(maxPayloadForKind(frame.Kind)) {
		return fmt.Errorf("payload exceeds %s limit: %d", frame.Kind, len(frame.Payload))
	}
	if frame.Kind == KindData && frame.StreamID == 0 {
		return errors.New("data frame stream ID must be non-zero")
	}
	return nil
}

func maxPayloadForKind(kind Kind) uint32 {
	if kind == KindControl {
		return MaxControlPayload
	}
	return MaxDataPayload
}

func (kind Kind) String() string {
	switch kind {
	case KindControl:
		return "control"
	case KindData:
		return "data"
	default:
		return fmt.Sprintf("kind(%d)", kind)
	}
}

type SequenceTracker struct {
	last uint64
}

func (tracker *SequenceTracker) Accept(sequence uint64) error {
	if sequence == 0 {
		return errors.New("sequence must start at 1")
	}
	if sequence <= tracker.last {
		return fmt.Errorf("replayed or out-of-order sequence: got=%d last=%d", sequence, tracker.last)
	}
	tracker.last = sequence
	return nil
}

func (tracker SequenceTracker) Last() uint64 {
	return tracker.last
}
