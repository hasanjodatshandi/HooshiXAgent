package gateway

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
)

func TestUDPDatagramReaderPreservesQueuedFramesAfterClose(t *testing.T) {
	sessionBudget := newByteBudget(1024)
	globalBudget := newByteBudget(1024)
	var rejects atomic.Uint64
	flow := newStream(context.Background(), 1, 4, 1024, sessionBudget, globalBudget, &rejects)
	flow.datagram = true
	for _, packet := range []string{"a", "bc"} {
		if err := flow.enqueue([]byte(packet)); err != nil {
			t.Fatal(err)
		}
	}
	flow.finish(nil)
	for _, want := range []string{"a", "bc"} {
		got, err := flow.ReadDatagram()
		if err != nil || string(got) != want {
			t.Fatalf("datagram %q, %v; want %q", got, err, want)
		}
	}
	if _, err := flow.ReadDatagram(); !errors.Is(err, io.EOF) {
		t.Fatalf("closed UDP flow returned %v, want EOF", err)
	}
	flow.discardRetained()
	if sessionBudget.Used() != 0 || globalBudget.Used() != 0 {
		t.Fatal("UDP flow retained queue budget after drain")
	}
}
