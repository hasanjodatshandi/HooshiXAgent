// Package agentbudget holds the Edge Agent's bounded byte-budget domain
// primitives (ADR-0013): the fail-closed acquisition/release semantics every
// Agent stream and session queue depends on. It is pure domain logic with no
// network, filesystem, or OS dependencies.
package agentbudget

import (
	"errors"
	"sync/atomic"
)

// ErrUnderflow reports a release larger than the outstanding reservation. It is
// always a caller bug (typically a double release), never a runtime condition.
var ErrUnderflow = errors.New("agent byte budget underflow")

// ByteBudget is a bounded byte accounting primitive. Acquiring beyond the
// limit fails closed. Releasing more than was acquired is a caller bug: the
// budget is CLAMPED to zero and ErrUnderflow is returned rather than panicking,
// so one accounting mistake can no longer crash the whole tunnel process (a
// panic here killed the agent, which is a far worse outcome than a clamped
// counter plus a logged anomaly).
type ByteBudget struct {
	limit      int64
	used       atomic.Int64
	underflows atomic.Int64
}

// New returns a budget with the given hard limit.
func New(limit int64) *ByteBudget {
	return &ByteBudget{limit: limit}
}

// TryAcquire reserves size bytes when the remaining capacity allows it. Zero
// and negative sizes never succeed; an oversized request fails closed.
func (budget *ByteBudget) TryAcquire(size int64) bool {
	if size < 0 || size > budget.limit {
		return false
	}
	if size == 0 {
		return true
	}
	for {
		used := budget.used.Load()
		if used > budget.limit-size {
			return false
		}
		if budget.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

// Release returns previously reserved bytes to the budget. An underflow is
// clamped to zero and reported as ErrUnderflow; the returned value is useful
// only for diagnostics.
func (budget *ByteBudget) Release(size int64) error {
	if size <= 0 {
		return nil
	}
	for {
		used := budget.used.Load()
		next := used - size
		if next < 0 {
			if budget.used.CompareAndSwap(used, 0) {
				budget.underflows.Add(1)
				return ErrUnderflow
			}
			continue
		}
		if budget.used.CompareAndSwap(used, next) {
			return nil
		}
	}
}

// Used returns the currently reserved bytes.
func (budget *ByteBudget) Used() int64 { return budget.used.Load() }

// Limit returns the hard reservation limit.
func (budget *ByteBudget) Limit() int64 { return budget.limit }

// Underflows returns how many releases were clamped to zero.
func (budget *ByteBudget) Underflows() int64 { return budget.underflows.Load() }

// QueuedPayload is one bounded frame queued for a local stream.
type QueuedPayload struct {
	Data []byte
	Size int64
}
