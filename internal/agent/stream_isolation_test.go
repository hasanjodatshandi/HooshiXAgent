package agent

import (
	"context"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestFullStreamDoesNotWaitInsideSessionReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limits := DefaultLimits()
	sess := &agentSession{limits: limits, logger: quietAgentLogger(), streams: make(map[uint32]*agentStream), maxStreamID: 2,
		closed: make(chan struct{}), controlWrites: make(chan agentWriteRequest, 32), dataWrites: make(chan agentWriteRequest, 2),
		writeMessage: func(context.Context, []byte) error { return nil }}
	go sess.writeLoop()
	defer sess.shutdown()
	for _, id := range []uint32{1, 2} {
		streamCtx, streamCancel := context.WithCancel(ctx)
		sess.streams[id] = &agentStream{id: id, ctx: streamCtx, cancel: streamCancel,
			incoming: make(chan agentQueuedPayload, 1), space: make(chan struct{}, 1),
			streamBudget: newAgentByteBudget(100), sessionBudget: newAgentByteBudget(200), logger: quietAgentLogger()}
	}
	if !sess.streams[1].enqueue([]byte("full")) {
		t.Fatal("initial enqueue failed")
	}
	start := time.Now()
	if err := sess.handleData(ctx, contractv1.Frame{StreamID: 1, Payload: []byte("overflow")}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("slow local consumer stalled the session reader")
	}
	if _, exists := sess.streams[1]; exists {
		t.Fatal("overflow stream not isolated")
	}
	if err := sess.handleData(ctx, contractv1.Frame{StreamID: 2, Payload: []byte("healthy")}); err != nil {
		t.Fatal(err)
	}
	if len(sess.streams[2].incoming) != 1 {
		t.Fatal("healthy sibling lost its data")
	}
}
