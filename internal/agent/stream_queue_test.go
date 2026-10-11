package agent

import (
	"bytes"
	"testing"
)

// A stream queue that has fewer slots than its own byte budget holds in
// minimum-size frames stops buffering long before the documented limit, which
// is what made a 7 MiB admitted upload die at one megabyte. These tests pin the
// two numbers together.

func TestStreamInputBudgetMatchesTheAdmissionEnvelope(t *testing.T) {
	limits := DefaultLimits()
	for _, mode := range []string{"", "http"} {
		if got := streamInputBudget(mode, limits); got != limits.MaxSessionQueueBytes {
			t.Fatalf("mode %q budget=%d want session bound %d", mode, got, limits.MaxSessionQueueBytes)
		}
	}
	// Byte streams have no admission ceiling, so they keep the tight window that
	// preserves isolation between concurrent streams on one session.
	for _, mode := range []string{"tcp", "udp"} {
		if got := streamInputBudget(mode, limits); got != limits.MaxStreamQueueBytes {
			t.Fatalf("mode %q budget=%d want stream bound %d", mode, got, limits.MaxStreamQueueBytes)
		}
	}
	// An operator who shrinks the session bound below the stream bound must not
	// end up with a per-stream budget larger than the session can pay for.
	shrunk := Limits{MaxQueueFrames: limits.MaxQueueFrames, MaxStreamQueueBytes: 4 << 20, MaxSessionQueueBytes: 1 << 20}
	if got := streamInputBudget("http", shrunk); got != shrunk.MaxStreamQueueBytes {
		t.Fatalf("session bound below stream bound produced %d want %d", got, shrunk.MaxStreamQueueBytes)
	}
}

func TestStreamQueueSlotsNeverBindBeforeTheByteBudget(t *testing.T) {
	if got, want := streamQueueFrames(DefaultLimits().MaxQueueFrames, 2<<20), (2<<20)/minTunnelFrame; got != want {
		t.Fatalf("2 MiB queue slots=%d want %d frames of %d bytes", got, want, minTunnelFrame)
	}
	if got, want := streamQueueFrames(DefaultLimits().MaxQueueFrames, 8<<20), (8<<20)/minTunnelFrame; got != want {
		t.Fatalf("8 MiB queue slots=%d want %d frames of %d bytes", got, want, minTunnelFrame)
	}
	// A budget smaller than one minimum frame still gets the configured floor.
	if got := streamQueueFrames(16, 1024); got != 16 {
		t.Fatalf("floor not applied: got %d want 16", got)
	}
}

func TestStreamQueuesBufferTheirWholeByteBudgetWithoutAConsumer(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{name: "http-mode holds one admitted body", mode: ""},
		{name: "tcp-mode keeps its tight window", mode: "tcp"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			limits := DefaultLimits()
			budget := streamInputBudget(testCase.mode, limits)
			stream := &agentStream{
				id: 1,
				incoming: make(chan agentQueuedPayload,
					streamQueueFrames(limits.MaxQueueFrames, budget)),
				space:         make(chan struct{}, 1),
				streamBudget:  newAgentByteBudget(budget),
				sessionBudget: newAgentByteBudget(limits.MaxSessionQueueBytes),
				logger:        quietAgentLogger(),
			}
			// The queue is filled with the smallest frames the tunnel produces, so
			// a slot count that binds before the budget fails here rather than in
			// production under a slow local target.
			chunk := bytes.Repeat([]byte("x"), minTunnelFrame)
			frames := int(budget / int64(len(chunk)))
			for index := 0; index < frames; index++ {
				if !stream.enqueue(chunk) {
					t.Fatalf("chunk %d of %d rejected: the queue stopped at %d bytes of a %d byte budget",
						index, frames, int64(index)*int64(len(chunk)), budget)
				}
			}
			if stream.enqueue(chunk) {
				t.Fatalf("a full %d byte budget accepted one more frame", budget)
			}
			if used := stream.streamBudget.Used(); used != budget {
				t.Fatalf("stream budget used=%d want %d", used, budget)
			}
			queued := <-stream.incoming
			stream.releaseQueued(queued.Size)
			if !stream.enqueue(chunk) {
				t.Fatal("a released slot was not reusable")
			}
		})
	}
}
