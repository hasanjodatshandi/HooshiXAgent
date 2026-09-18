package gateway

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestTerminalTailStaysReservedUntilDeliveredOrDiscarded proves the byte
// budget accounts for bytes the stream still retains: a terminal frame moves
// queued chunks into the terminal buffer without releasing them, the
// reservation is released exactly once on dequeue in Read, and an abandoned
// tail is released when the reader has stopped.
func TestTerminalTailStaysReservedUntilDeliveredOrDiscarded(t *testing.T) {
	global := newByteBudget(1 << 20)
	session := newByteBudget(1 << 20)
	var rejects atomic.Uint64
	stream := newStream(context.Background(), 1, 8, 1<<20/2, session, global, &rejects)

	payload := make([]byte, 512)
	if err := stream.enqueue(payload); err != nil {
		t.Fatal(err)
	}
	if global.Used() != int64(len(payload)) {
		t.Fatalf("queued bytes=%d want %d", global.Used(), len(payload))
	}
	stream.finish(nil)
	if global.Used() != int64(len(payload)) || session.Used() != int64(len(payload)) {
		t.Fatalf("retained tail was released before delivery: global=%d session=%d", global.Used(), session.Used())
	}

	buffer := make([]byte, len(payload))
	if _, err := readFullStream(stream, buffer); err != nil {
		t.Fatalf("read retained tail: %v", err)
	}
	if global.Used() != 0 || session.Used() != 0 {
		t.Fatalf("delivered tail still reserved: global=%d session=%d", global.Used(), session.Used())
	}

	// An abandoned tail (reader stopped before draining) must not leak the
	// reservation either.
	second := newStream(context.Background(), 2, 8, 1<<20/2, session, global, &rejects)
	if err := second.enqueue(payload); err != nil {
		t.Fatal(err)
	}
	second.finish(nil)
	second.discardRetained()
	if global.Used() != 0 || session.Used() != 0 {
		t.Fatalf("abandoned tail leaked reservations: global=%d session=%d", global.Used(), session.Used())
	}
	// Discarding twice is a no-op, never an underflow.
	second.discardRetained()
}

func readFullStream(stream *stream, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := stream.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
