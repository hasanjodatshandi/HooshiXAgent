package tunnelwindow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestWindowWaitsForReceiverCredit(t *testing.T) {
	window := New(1024)
	done := make(chan error, 1)
	go func() { done <- window.Take(context.Background(), 512) }()

	select {
	case err := <-done:
		t.Fatalf("Take returned before any credit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := window.Add(512); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Take after credit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Take did not resume after credit")
	}
	if window.Credit() != 0 {
		t.Fatalf("credit=%d want 0", window.Credit())
	}
}

func TestWindowRejectsOverGrantAndInvalidSizes(t *testing.T) {
	window := New(1024)
	if err := window.Add(1024); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(window.Add(1), ErrOverGrant) {
		t.Fatal("over-grant was accepted")
	}
	for _, size := range []int64{0, -1, 1025} {
		if err := window.Take(context.Background(), size); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Take(%d)=%v want ErrInvalid", size, err)
		}
	}
}

func TestWindowCloseWakesWaitersAndRejectsCredit(t *testing.T) {
	window := New(1024)
	cause := errors.New("stream closed")
	done := make(chan error, 1)
	go func() { done <- window.Take(context.Background(), 64) }()
	window.Close(cause)
	select {
	case err := <-done:
		if !errors.Is(err, cause) {
			t.Fatalf("Take after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Take was not released by Close")
	}
	if !errors.Is(window.Add(1), cause) {
		t.Fatal("Add after close was accepted")
	}
}

func TestWindowTakeHonoursContext(t *testing.T) {
	window := New(1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := window.Take(ctx, 64); !errors.Is(err, context.Canceled) {
		t.Fatalf("Take with cancelled context: %v", err)
	}
}

func TestWindowConcurrentProducerAndConsumers(t *testing.T) {
	const total = 64 * 1024
	const chunk = 64
	window := New(1 << 20)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total/chunk; i++ {
			if err := window.Add(chunk); err != nil {
				t.Errorf("Add: %v", err)
				return
			}
		}
	}()
	ctx := context.Background()
	for consumer := 0; consumer < 4; consumer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < total/chunk/4; i++ {
				if err := window.Take(ctx, chunk); err != nil {
					t.Errorf("Take: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	window.Close(nil)
}

func TestInitialCreditCapsAndFloors(t *testing.T) {
	if got := InitialCredit(0); got != 1 {
		t.Fatalf("InitialCredit(0)=%d want 1", got)
	}
	if got := InitialCredit(1024); got != 1024 {
		t.Fatalf("InitialCredit(1024)=%d", got)
	}
	if got := InitialCredit(1 << 30); got != contractv1.MaxWindowCreditBytes {
		t.Fatalf("InitialCredit(1GiB)=%d want %d", got, contractv1.MaxWindowCreditBytes)
	}
}
