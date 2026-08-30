package agent

import (
	"bytes"
	"context"
	"testing"
	"time"
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
		space:         make(chan struct{}, 1),
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
		space:         make(chan struct{}, 1),
		ctx:           secondCtx,
		cancel:        secondCancel,
		streamBudget:  newAgentByteBudget(8),
		sessionBudget: sessionBudget,
	}
	if !first.enqueue(context.Background(), bytes.Repeat([]byte{'a'}, 8), time.Millisecond) {
		t.Fatal("initial Agent queue reservation failed")
	}
	if second.enqueue(context.Background(), bytes.Repeat([]byte{'b'}, 5), time.Millisecond) {
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
	if !second.enqueue(context.Background(), bytes.Repeat([]byte{'c'}, 5), time.Millisecond) {
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
		space:         make(chan struct{}, 1),
		ctx:           ctx,
		cancel:        cancel,
		streamBudget:  newAgentByteBudget(64),
		sessionBudget: sessionBudget,
	}
	if !stream.enqueue(context.Background(), []byte("first"), time.Millisecond) {
		t.Fatal("initial Agent frame enqueue failed")
	}
	if stream.enqueue(context.Background(), []byte("second"), time.Millisecond) {
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

func TestAgentQueueBackpressureAllowsBoundedStreaming(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionBudget := newAgentByteBudget(64)
	stream := &agentStream{
		id:            1,
		incoming:      make(chan agentQueuedPayload, 1),
		space:         make(chan struct{}, 1),
		ctx:           ctx,
		cancel:        cancel,
		streamBudget:  newAgentByteBudget(64),
		sessionBudget: sessionBudget,
	}
	if !stream.enqueue(context.Background(), []byte("first"), time.Second) {
		t.Fatal("initial frame enqueue failed")
	}
	result := make(chan bool, 1)
	go func() {
		result <- stream.enqueue(context.Background(), []byte("second"), time.Second)
	}()
	select {
	case <-result:
		t.Fatal("backpressured enqueue completed before queue space was released")
	case <-time.After(25 * time.Millisecond):
	}
	queued := <-stream.incoming
	stream.releaseQueued(queued.size)
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("backpressured enqueue did not resume after queue space release")
		}
	case <-time.After(time.Second):
		t.Fatal("backpressured enqueue remained blocked after queue space release")
	}
	stream.finishStream()
	if sessionBudget.used.Load() != 0 {
		t.Fatalf("backpressure cleanup leaked bytes: %d", sessionBudget.used.Load())
	}
}

func TestAgentPeerTerminalOwnsStreamAndSuppressesLocalTerminal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stream := &agentStream{
		id:            7,
		incoming:      make(chan agentQueuedPayload, 1),
		space:         make(chan struct{}, 1),
		ctx:           ctx,
		cancel:        cancel,
		streamBudget:  newAgentByteBudget(64),
		sessionBudget: newAgentByteBudget(64),
	}
	sess := &agentSession{streams: map[uint32]*agentStream{7: stream}}
	sess.finishStreamFromPeer(7)
	executed := false
	stream.terminal.Do(func() { executed = true })
	if executed {
		t.Fatal("local terminal signal remained available after peer terminal")
	}
	sess.mu.Lock()
	_, present := sess.streams[7]
	sess.mu.Unlock()
	if present {
		t.Fatal("peer-terminal stream remained registered")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("peer terminal did not cancel stream context")
	}
}
