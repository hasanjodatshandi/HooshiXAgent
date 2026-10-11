package gateway

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
)

// The Agent writes what it reads from a local service, so tunnel data frames
// arrive in 4096-byte flushes rather than the 32 KiB the framing allows. A queue
// sized in slots alone therefore stops buffering at a fraction of its documented
// byte budget; these tests pin slots to the budget on this side too.
func TestStreamQueueSlotsFollowTheByteBudget(t *testing.T) {
	limits := DefaultLimits()
	stream := newStream(context.Background(), 1, limits.MaxStreamQueueFrames, limits.MaxStreamQueueBytes,
		newByteBudget(limits.MaxSessionQueueBytes), newByteBudget(limits.MaxGlobalQueueBytes), &atomic.Uint64{})
	if want := int(limits.MaxStreamQueueBytes / minTunnelFrame); cap(stream.incoming) < want {
		t.Fatalf("queue slots=%d cannot hold the %d byte budget in %d byte frames", cap(stream.incoming), limits.MaxStreamQueueBytes, minTunnelFrame)
	}
	if got := newStream(context.Background(), 2, 16, 1024,
		newByteBudget(limits.MaxSessionQueueBytes), newByteBudget(limits.MaxGlobalQueueBytes), &atomic.Uint64{}); cap(got.incoming) != 16 {
		t.Fatalf("a budget below one frame lost the configured slot floor: got %d want 16", cap(got.incoming))
	}
}

func TestStreamQueueBuffersItsWholeByteBudgetWithoutAReader(t *testing.T) {
	limits := DefaultLimits()
	stream := newStream(context.Background(), 1, limits.MaxStreamQueueFrames, limits.MaxStreamQueueBytes,
		newByteBudget(limits.MaxSessionQueueBytes), newByteBudget(limits.MaxGlobalQueueBytes), &atomic.Uint64{})
	chunk := bytes.Repeat([]byte("r"), minTunnelFrame)
	frames := int(limits.MaxStreamQueueBytes / minTunnelFrame)
	for index := 0; index < frames; index++ {
		if err := stream.enqueue(chunk); err != nil {
			t.Fatalf("frame %d of %d rejected: %v", index, frames, err)
		}
	}
	if err := stream.enqueue(chunk); err == nil {
		t.Fatalf("a full %d byte budget accepted one more frame", limits.MaxStreamQueueBytes)
	}
	if used := stream.streamBudget.Used(); used != limits.MaxStreamQueueBytes {
		t.Fatalf("stream budget used=%d want %d", used, limits.MaxStreamQueueBytes)
	}
	queued := <-stream.incoming
	stream.releaseQueued(queued.size)
	if err := stream.enqueue(chunk); err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	}
}
