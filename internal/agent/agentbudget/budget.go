// Package agentbudget holds the Edge Agent's bounded byte-budget domain
// primitives (ADR-0013): the fail-closed acquisition/release semantics every
// Agent stream and session queue depends on. It is pure domain logic with no
// network, filesystem, or OS dependencies.
package agentbudget

import "sync/atomic"

// ByteBudget is a bounded byte accounting primitive. Acquiring beyond the
// limit fails closed; releasing more than was acquired is a programming error
// and panics, mirroring the fail-closed budget policy used across the runtime.
type ByteBudget struct {
	limit int64
	used  atomic.Int64
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

// Release returns previously reserved bytes to the budget.
func (budget *ByteBudget) Release(size int64) {
	if size <= 0 {
		return
	}
	if used := budget.used.Add(-size); used < 0 {
		panic("agent byte budget underflow")
	}
}

// Used returns the currently reserved bytes.
func (budget *ByteBudget) Used() int64 { return budget.used.Load() }

// Limit returns the hard reservation limit.
func (budget *ByteBudget) Limit() int64 { return budget.limit }

// QueuedPayload is one bounded frame queued for a local stream.
type QueuedPayload struct {
	Data []byte
	Size int64
}
