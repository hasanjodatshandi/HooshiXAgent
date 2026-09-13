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
	if !first.enqueue(bytes.Repeat([]byte{'a'}, 8)) {
		t.Fatal("initial Agent queue reservation failed")
	}
	if second.enqueue(bytes.Repeat([]byte{'b'}, 5)) {
		t.Fatal("Agent session queue budget allowed overcommit")
	}
	if sessionBudget.Used() != 8 {
		t.Fatalf("Agent failed enqueue leaked budget: %d", sessionBudget.Used())
	}
	queued := <-first.incoming
	first.releaseQueued(queued.Size)
	if sessionBudget.Used() != 0 {
		t.Fatal("Agent dequeue did not release session byte budget")
	}
	if !second.enqueue(bytes.Repeat([]byte{'c'}, 5)) {
		t.Fatal("Agent queue did not recover after release")
	}
	second.finishStream()
	if sessionBudget.Used() != 0 {
		t.Fatalf("Agent stream cleanup leaked queued bytes: %d", sessionBudget.Used())
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
	if !stream.enqueue([]byte("first")) {
		t.Fatal("initial Agent frame enqueue failed")
	}
	if stream.enqueue([]byte("second")) {
		t.Fatal("Agent frame queue over-capacity succeeded")
	}
	if got := sessionBudget.Used(); got != int64(len("first")) {
		t.Fatalf("Agent rejected frame leaked reservation: %d", got)
	}
	stream.finishStream()
	if sessionBudget.Used() != 0 {
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
	if !stream.enqueue([]byte("first")) {
		t.Fatal("initial frame enqueue failed")
	}
	// A full per-stream queue must reject immediately (non-blocking): the
	// single session reader must never stall behind a slow local target.
	rejected := make(chan bool, 1)
	go func() {
		rejected <- stream.enqueue([]byte("second"))
	}()
	select {
	case ok := <-rejected:
		if ok {
			t.Fatal("full stream queue accepted another frame")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue against a full queue blocked the caller")
	}
	queued := <-stream.incoming
	stream.releaseQueued(queued.Size)
	// After the local reader dequeues and releases the budget, enqueueing
	// resumes without recreating the stream.
	if !stream.enqueue([]byte("second")) {
		t.Fatal("enqueue did not resume after queue space release")
	}
	stream.finishStream()
	if sessionBudget.Used() != 0 {
		t.Fatalf("backpressure cleanup leaked bytes: %d", sessionBudget.Used())
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
