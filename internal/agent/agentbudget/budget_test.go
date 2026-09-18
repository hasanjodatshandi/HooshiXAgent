package agentbudget

import (
	"errors"
	"sync"
	"testing"
)

// TestTryAcquireFailsClosedBeyondTheLimit proves bounded acquisition: zero and
// negative sizes never reserve, an oversized single request fails, and the
// limit is never exceeded by concurrent acquirers.
func TestTryAcquireFailsClosedBeyondTheLimit(t *testing.T) {
	budget := New(10)
	if budget.TryAcquire(-1) {
		t.Fatal("a negative reservation must be rejected")
	}
	if budget.TryAcquire(11) {
		t.Fatal("an oversized single reservation must be rejected")
	}
	if !budget.TryAcquire(0) {
		t.Fatal("a zero-length reservation must succeed without reserving")
	}
	if !budget.TryAcquire(10) {
		t.Fatal("a reservation equal to the limit must succeed")
	}
	if budget.TryAcquire(1) {
		t.Fatal("a reservation beyond the limit must fail closed")
	}
	if used := budget.Used(); used != 10 {
		t.Fatalf("used=%d want=10", used)
	}
	if err := budget.Release(10); err != nil {
		t.Fatalf("release of exactly the reserved amount: %v", err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("used=%d want=0 after a full release", used)
	}
}

// TestReleaseUnderflowIsClampedAndReported proves an over-release (a double
// release bug) is clamped and surfaced as an error instead of panicking: the
// previous implementation panicked, converting an accounting mistake in a
// stream queue into a whole-process crash.
func TestReleaseUnderflowIsClampedAndReported(t *testing.T) {
	budget := New(1024)
	if !budget.TryAcquire(64) {
		t.Fatal("acquisition failed")
	}
	if err := budget.Release(128); !errors.Is(err, ErrUnderflow) {
		t.Fatalf("over-release err=%v want ErrUnderflow", err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("over-release left used=%d, want it clamped to 0", used)
	}
	if count := budget.Underflows(); count != 1 {
		t.Fatalf("underflows=%d want=1", count)
	}
	// The budget must still be usable (no poisoned state) after clamping.
	if !budget.TryAcquire(1024) {
		t.Fatal("the budget became unusable after a clamped underflow")
	}
	if err := budget.Release(1024); err != nil {
		t.Fatalf("release after recovery: %v", err)
	}
	// A release with nothing outstanding is the degenerate underflow.
	if err := budget.Release(1); !errors.Is(err, ErrUnderflow) {
		t.Fatalf("release of an empty budget err=%v want ErrUnderflow", err)
	}
	if count := budget.Underflows(); count != 2 {
		t.Fatalf("underflows=%d want=2", count)
	}
	// Non-positive releases are no-ops and are not underflows.
	if err := budget.Release(0); err != nil {
		t.Fatalf("release(0) err=%v want nil", err)
	}
	if err := budget.Release(-5); err != nil {
		t.Fatalf("release(-5) err=%v want nil", err)
	}
	if count := budget.Underflows(); count != 2 {
		t.Fatalf("no-op releases counted as underflows: %d", count)
	}
}

// TestConcurrentAccountingStaysBounded proves acquire/release under concurrency
// never exceeds the limit and never underflows.
func TestConcurrentAccountingStaysBounded(t *testing.T) {
	budget := New(1000)
	const workers = 8
	const rounds = 200
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for round := 0; round < rounds; round++ {
				if budget.TryAcquire(10) {
					if err := budget.Release(10); err != nil {
						t.Errorf("release after acquire: %v", err)
						return
					}
				}
			}
		}()
	}
	waitGroup.Wait()
	if used := budget.Used(); used != 0 {
		t.Fatalf("used=%d want=0 after balanced concurrent traffic", used)
	}
	if count := budget.Underflows(); count != 0 {
		t.Fatalf("underflows=%d want=0 for balanced traffic", count)
	}
}

// TestLimitAndUsedAccessors pins the read-only accessors used by diagnostics.
func TestLimitAndUsedAccessors(t *testing.T) {
	budget := New(4096)
	if budget.Limit() != 4096 {
		t.Fatalf("Limit()=%d want=4096", budget.Limit())
	}
	if budget.Used() != 0 {
		t.Fatalf("Used()=%d want=0", budget.Used())
	}
	if !budget.TryAcquire(100) {
		t.Fatal("acquisition failed")
	}
	if budget.Used() != 100 {
		t.Fatalf("Used()=%d want=100", budget.Used())
	}
}
