package agent

import (
	"bytes"
	"context"
	"testing"
)

func TestAgentQueueBudgetsBoundPerStreamAndSession(t *testing.T) {
	limits := DefaultLimits()
	if !limits.valid() {
		t.Fatal("default Agent limits are invalid")
	}
	if limits.MaxStreamQueueBytes > limits.MaxSessionQueueBytes {
		t.Fatal("Agent stream queue budget exceeds session queue budget")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionBudget := newAgentByteBudget(12)
	first := &agentStream{
		id:            1,
		incoming:      make(chan agentQueuedPayload, 4),
		ctx:           ctx,
		cancel:        cancel,
		streamBudget:  newAgentByteBudget(8),
		sessionBudget: sessionBudget,
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	second := &agentStream{
		id:            2,
		incoming:      make(chan agentQueuedPayload, 4),
		ctx:           secondCtx,
		cancel:        secondCancel,
		streamBudget:  newAgentByteBudget(8),
		sessionBudget: sessionBudget,
	}
	if !first.enqueue(bytes.Repeat([]byte{'a'}, 8)) {
		t.Fatal("initial Agent queue reservation failed")
	}
	if second.enqueue(bytes.Repeat([]byte{'b'}, 5)) {
		t.Fatal("Agent session queue budget allowed overcommit")
	}
	if sessionBudget.used.Load() != 8 {
		t.Fatalf("Agent failed enqueue leaked budget: %d", sessionBudget.used.Load())
	}
	queued := <-first.incoming
	first.releaseQueued(queued.size)
	if sessionBudget.used.Load() != 0 {
		t.Fatal("Agent dequeue did not release session byte budget")
	}
	if !second.enqueue(bytes.Repeat([]byte{'c'}, 5)) {
		t.Fatal("Agent queue did not recover after release")
	}
	second.finishStream()
	if sessionBudget.used.Load() != 0 {
		t.Fatalf("Agent stream cleanup leaked queued bytes: %d", sessionBudget.used.Load())
	}
	first.finishStream()
}

func TestAgentQueueFrameLimitDoesNotLeakBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionBudget := newAgentByteBudget(64)
	stream := &agentStream{
		id:            1,
		incoming:      make(chan agentQueuedPayload, 1),
		ctx:           ctx,
		cancel:        cancel,
		streamBudget:  newAgentByteBudget(64),
		sessionBudget: sessionBudget,
	}
	if !stream.enqueue([]byte("first")) {
		t.Fatal("initial Agent frame enqueue failed")
	}
	if stream.enqueue([]byte("second")) {
		t.Fatal("Agent frame queue over-capacity succeeded")
	}
	if got := sessionBudget.used.Load(); got != int64(len("first")) {
		t.Fatalf("Agent rejected frame leaked reservation: %d", got)
	}
	stream.finishStream()
	if sessionBudget.used.Load() != 0 {
		t.Fatal("Agent frame-limit cleanup leaked reservation")
	}
}
