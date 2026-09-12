package gateway

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// TestStreamFinishRacesPreserveQueuedData proves the 502 root cause is fixed:
// when the Agent's terminal stream_close arrives while body chunks are still
// queued (a close race under rapid refresh), every queued chunk must still be
// delivered to the reader before EOF. The old errCh-only implementation let
// select randomization drop the queued chunk ~half the time, truncating the
// tunneled response ("unexpected EOF" -> HTTP 502).
func TestStreamFinishRacesPreserveQueuedData(t *testing.T) {
	for round := 0; round < 50; round++ {
		global := newByteBudget(1 << 20)
		session := newByteBudget(1 << 20)
		var rejects atomic.Uint64
		stream := newStream(1, 8, 1<<20, session, global, &rejects)

		header := bytes.Repeat([]byte{'H'}, 156)
		body := bytes.Repeat([]byte{'B'}, 4448)
		if err := stream.enqueue(header); err != nil {
			t.Fatalf("enqueue header: %v", err)
		}
		if err := stream.enqueue(body); err != nil {
			t.Fatalf("enqueue body: %v", err)
		}

		// Simulate the gateway run-loop processing stream_close while both
		// chunks are still queued (the exact production race).
		stream.finish(nil)

		out := make([]byte, len(header)+len(body))
		if _, err := io.ReadFull(stream, out); err != nil {
			t.Fatalf("round %d: reader lost queued data after finish: %v", round, err)
		}
		if !bytes.Equal(out[:len(header)], header) || !bytes.Equal(out[len(header):], body) {
			t.Fatalf("round %d: corrupted stream data", round)
		}
		if _, err := stream.Read(out[:1]); err != io.EOF {
			t.Fatalf("round %d: want EOF after drain, got %v", round, err)
		}
		if global.Used() != 0 || session.Used() != 0 {
			t.Fatalf("round %d: byte budgets leaked: global=%d session=%d", round, global.Used(), session.Used())
		}
	}
}

// TestStreamFinishDeliversTerminalErrorAfterData ensures the terminal error
// (stream_error path) still surfaces after queued data is drained.
func TestStreamFinishDeliversTerminalErrorAfterData(t *testing.T) {
	global := newByteBudget(1 << 20)
	session := newByteBudget(1 << 20)
	var rejects atomic.Uint64
	stream := newStream(2, 8, 1<<20, session, global, &rejects)

	payload := []byte("partial-response")
	if err := stream.enqueue(payload); err != nil {
		t.Fatal(err)
	}
	stream.finish(io.ErrUnexpectedEOF)

	out := make([]byte, len(payload))
	n, err := io.ReadFull(stream, out)
	if err != nil {
		t.Fatalf("queued data lost: n=%d err=%v", n, err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("corrupted payload: %q", out)
	}
	buf := make([]byte, 8)
	if _, err := stream.Read(buf); err != io.ErrUnexpectedEOF {
		t.Fatalf("want terminal error after drain, got %v", err)
	}
}

// TestStreamReadBlocksUntilTerminal verifies the reader blocks while no data
// and no terminal has arrived, then wakes when the terminal lands.
func TestStreamReadBlocksUntilTerminal(t *testing.T) {
	global := newByteBudget(1 << 20)
	session := newByteBudget(1 << 20)
	var rejects atomic.Uint64
	stream := newStream(3, 8, 1<<20, session, global, &rejects)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := stream.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read returned without data/terminal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	stream.finish(nil)
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("want EOF after terminal, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not wake on terminal")
	}
}
