package gateway

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var errResourceBudget = errors.New("gateway resource byte budget exhausted")

type byteBudget struct {
	limit    int64
	used     atomic.Int64
	rejected atomic.Uint64
}

func newByteBudget(limit int64) *byteBudget {
	return &byteBudget{limit: limit}
}

func (budget *byteBudget) tryAcquire(size int64) bool {
	if size < 0 || size > budget.limit {
		budget.rejected.Add(1)
		return false
	}
	if size == 0 {
		return true
	}
	for {
		used := budget.used.Load()
		if used > budget.limit-size {
			budget.rejected.Add(1)
			return false
		}
		if budget.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (budget *byteBudget) release(size int64) {
	if size <= 0 {
		return
	}
	if used := budget.used.Add(-size); used < 0 {
		panic("gateway byte budget underflow")
	}
}

func (budget *byteBudget) snapshot() (used, limit int64, rejected uint64) {
	return budget.used.Load(), budget.limit, budget.rejected.Load()
}

type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	last     time.Time
	rejected atomic.Uint64
}

func newTokenBucket(rate, burst int) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

func (bucket *tokenBucket) allow(now time.Time) bool {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	if now.Before(bucket.last) {
		now = bucket.last
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.tokens += elapsed * bucket.rate
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
	bucket.last = now
	if bucket.tokens < 1 {
		bucket.rejected.Add(1)
		return false
	}
	bucket.tokens--
	return true
}

type gatewayResources struct {
	queueBytes       *byteBudget
	ingressBytes     *byteBudget
	ingressSlots     chan struct{}
	handshakeRate    *tokenBucket
	ingressRate      *tokenBucket
	queueRejects     atomic.Uint64
	handshakeRejects atomic.Uint64
	ingressRejects   atomic.Uint64
	sessionRejects   atomic.Uint64
}

func newGatewayResources(limits Limits) gatewayResources {
	return gatewayResources{
		queueBytes:    newByteBudget(limits.MaxGlobalQueueBytes),
		ingressBytes:  newByteBudget(limits.MaxIngressInFlightBytes),
		ingressSlots:  make(chan struct{}, limits.MaxIngressInFlight),
		handshakeRate: newTokenBucket(limits.HandshakeRatePerSecond, limits.HandshakeRateBurst),
		ingressRate:   newTokenBucket(limits.IngressRatePerSecond, limits.IngressRateBurst),
	}
}

type budgetBuffer struct {
	buffer   bytes.Buffer
	budget   *byteBudget
	acquired int64
}

func newBudgetBuffer(budget *byteBudget) *budgetBuffer {
	return &budgetBuffer{budget: budget}
}

func (buffer *budgetBuffer) Write(data []byte) (int, error) {
	if !buffer.budget.tryAcquire(int64(len(data))) {
		return 0, errResourceBudget
	}
	n, err := buffer.buffer.Write(data)
	buffer.acquired += int64(n)
	if n < len(data) {
		buffer.budget.release(int64(len(data) - n))
	}
	return n, err
}

func (buffer *budgetBuffer) Bytes() []byte { return buffer.buffer.Bytes() }
func (buffer *budgetBuffer) Len() int      { return buffer.buffer.Len() }

func (buffer *budgetBuffer) release() {
	if buffer.acquired > 0 {
		buffer.budget.release(buffer.acquired)
		buffer.acquired = 0
	}
	buffer.buffer = bytes.Buffer{}
}
