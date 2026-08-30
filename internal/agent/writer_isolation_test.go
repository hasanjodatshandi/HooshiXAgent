package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestAgentWriterPrioritizesControlAndPreservesSingleWriter(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	var mu sync.Mutex
	written := make([]contractv1.Frame, 0, 3)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32

	sess := &agentSession{
		limits:        DefaultLimits(),
		streams:       make(map[uint32]*agentStream),
		closed:        make(chan struct{}),
		controlWrites: make(chan agentWriteRequest, 32),
		dataWrites:    make(chan agentWriteRequest, 2),
	}
	sess.writeMessage = func(ctx context.Context, encoded []byte) error {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			maximum := maxActive.Load()
			if current <= maximum || maxActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		frame, err := contractv1.DecodeFrame(encoded)
		if err != nil {
			return err
		}
		mu.Lock()
		written = append(written, frame)
		mu.Unlock()
		if calls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	sess.outbound.Store(2)
	go sess.writeLoop()
	defer sess.shutdown()

	errs := make(chan error, 3)
	go func() { errs <- sess.sendFrame(context.Background(), contractv1.KindData, 1, []byte("data-1")) }()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first data write did not start")
	}
	go func() { errs <- sess.sendFrame(context.Background(), contractv1.KindData, 1, []byte("data-2")) }()
	waitAgentWriterCondition(t, time.Second, func() bool { return len(sess.dataWrites) == 1 })
	go func() {
		errs <- sess.sendFrame(context.Background(), contractv1.KindControl, 0, []byte(`{"message_type":"pong"}`))
	}()
	waitAgentWriterCondition(t, time.Second, func() bool { return len(sess.controlWrites) == 1 })
	close(releaseFirst)
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if maxActive.Load() != 1 {
		t.Fatalf("WebSocket writer concurrency=%d want=1", maxActive.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(written) != 3 {
		t.Fatalf("written frame count=%d", len(written))
	}
	if written[0].Kind != contractv1.KindData || written[1].Kind != contractv1.KindControl || written[2].Kind != contractv1.KindData {
		t.Fatalf("writer order=%v,%v,%v want data,control,data", written[0].Kind, written[1].Kind, written[2].Kind)
	}
	for i, frame := range written {
		if want := uint64(i + 3); frame.Sequence != want {
			t.Fatalf("sequence[%d]=%d want=%d", i, frame.Sequence, want)
		}
	}
}

func waitAgentWriterCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
