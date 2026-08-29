package agent

import "sync/atomic"

type agentByteBudget struct {
	limit int64
	used  atomic.Int64
}

func newAgentByteBudget(limit int64) *agentByteBudget {
	return &agentByteBudget{limit: limit}
}

func (budget *agentByteBudget) tryAcquire(size int64) bool {
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

func (budget *agentByteBudget) release(size int64) {
	if size <= 0 {
		return
	}
	if used := budget.used.Add(-size); used < 0 {
		panic("agent byte budget underflow")
	}
}

type agentQueuedPayload struct {
	data []byte
	size int64
}
