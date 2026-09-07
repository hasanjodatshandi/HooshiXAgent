// Package gatewayresources holds the Tunnel Gateway's bounded resource
// domain (ADR-0013): byte budgets, token buckets, and keyed adaptive
// admission control. It is pure domain logic with no network, filesystem, or
// OS dependencies so admission and DoS policy is testable without sockets.
package gatewayresources

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrBudgetExhausted is the sentinel returned when a bounded byte budget
// cannot satisfy a request. The Gateway treats it as a fail-closed
// resource-limit signal, never as an auth or routing decision.
var ErrBudgetExhausted = errors.New("gateway resource byte budget exhausted")

// ByteBudget is a bounded byte accounting primitive with rejection counting.
type ByteBudget struct {
	limit    int64
	used     atomic.Int64
	rejected atomic.Uint64
}

// New returns a byte budget with the given hard limit.
func NewByteBudget(limit int64) *ByteBudget {
	return &ByteBudget{limit: limit}
}

// TryAcquire reserves size bytes when capacity allows; rejected requests
// increment the rejection counter.
func (budget *ByteBudget) TryAcquire(size int64) bool {
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

// Release returns previously reserved bytes. Underflow is a programming
// error and panics.
func (budget *ByteBudget) Release(size int64) {
	if size <= 0 {
		return
	}
	if used := budget.used.Add(-size); used < 0 {
		panic("gateway byte budget underflow")
	}
}

// Snapshot returns the current usage, hard limit, and rejection count.
func (budget *ByteBudget) Snapshot() (used, limit int64, rejected uint64) {
	return budget.used.Load(), budget.limit, budget.rejected.Load()
}

// Rejected returns the number of rejected requests.
func (budget *ByteBudget) Rejected() uint64 { return budget.rejected.Load() }

// Used returns the currently reserved bytes.
func (budget *ByteBudget) Used() int64 { return budget.used.Load() }

// TokenBucket is a classic bounded refill-rate limiter.
type TokenBucket struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	last     time.Time
	rejected atomic.Uint64
}

// NewTokenBucket returns a bucket with the given per-second rate and burst.
func NewTokenBucket(rate, burst int) *TokenBucket {
	now := time.Now()
	return &TokenBucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

// Allow consumes one token at the observation time, fail-closed otherwise.
// Out-of-order observations never rewind the bucket clock.
func (bucket *TokenBucket) Allow(now time.Time) bool {
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

// Rejected returns the number of rejected requests.
func (bucket *TokenBucket) Rejected() uint64 { return bucket.rejected.Load() }

// Tokens returns the currently available token allowance.
func (bucket *TokenBucket) Tokens() float64 {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.tokens
}

// States returns the number of keys with admission state.
func (limiter *KeyedAdmissionLimiter) States() int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.states)
}

// RejectReason classifies a keyed admission decision.
type RejectReason uint8

const (
	// Accepted means the request was admitted.
	Accepted RejectReason = iota
	// RejectedRate means the per-key rate allowance was exhausted.
	RejectedRate
	// RejectedConcurrency means the per-key in-flight allowance was exhausted.
	RejectedConcurrency
)

type keyedState struct {
	inFlight int
	tokens   float64
	last     time.Time
}

// KeyedAdmissionLimiter bounds per-key concurrency and rate with adaptive
// fairness: when a contended key recently consumed capacity, other keys get
// a reduced fair share instead of being starved.
type KeyedAdmissionLimiter struct {
	mu               sync.Mutex
	maxInFlight      int
	fairMaxInFlight  int
	rate             float64
	fairRate         float64
	burst            float64
	fairBurst        float64
	contentionWindow time.Duration
	alwaysFair       bool
	states           map[string]*keyedState
	recentKey        string
	recentAt         time.Time
	previousKey      string
	previousAt       time.Time
	rejected         atomic.Uint64
}

// FairnessShare reduces a global allowance to the adaptive fair share used
// under contention (three quarters, strictly below the global allowance).
func FairnessShare(global int) int {
	if global <= 1 {
		return global
	}
	share := (global * 3) / 4
	if share >= global {
		share = global - 1
	}
	if share < 1 {
		share = 1
	}
	return share
}

// NewKeyedAdmissionLimiter returns a contentional fair limiter.
func NewKeyedAdmissionLimiter(maxInFlight, rate, burst int) *KeyedAdmissionLimiter {
	return &KeyedAdmissionLimiter{
		maxInFlight:      maxInFlight,
		fairMaxInFlight:  FairnessShare(maxInFlight),
		rate:             float64(rate),
		fairRate:         float64(FairnessShare(rate)),
		burst:            float64(burst),
		fairBurst:        float64(FairnessShare(burst)),
		contentionWindow: 2 * time.Second,
		states:           make(map[string]*keyedState),
	}
}

// NewHardKeyedAdmissionLimiter returns a limiter that always applies the
// fair share regardless of observed contention.
func NewHardKeyedAdmissionLimiter(maxInFlight, rate, burst int) *KeyedAdmissionLimiter {
	limiter := NewKeyedAdmissionLimiter(maxInFlight, rate, burst)
	limiter.alwaysFair = true
	return limiter
}

// TryAcquire admits the key at the observation time or returns the rejection
// reason. It never blocks.
func (limiter *KeyedAdmissionLimiter) TryAcquire(key string, now time.Time) RejectReason {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	contended := limiter.alwaysFair || limiter.otherKeyRecentlySeen(key, now)
	limiter.observeKey(key, now)
	maxInFlight := limiter.maxInFlight
	rate := limiter.rate
	burst := limiter.burst
	if contended {
		maxInFlight = limiter.fairMaxInFlight
		rate = limiter.fairRate
		burst = limiter.fairBurst
	}

	state := limiter.states[key]
	if state == nil {
		state = &keyedState{tokens: limiter.burst, last: now}
		limiter.states[key] = state
	}
	if state.inFlight >= maxInFlight {
		limiter.rejected.Add(1)
		return RejectedConcurrency
	}
	if now.Before(state.last) {
		now = state.last
	}
	elapsed := now.Sub(state.last).Seconds()
	state.tokens += elapsed * rate
	if state.tokens > burst {
		state.tokens = burst
	}
	state.last = now
	if state.tokens < 1 {
		limiter.rejected.Add(1)
		return RejectedRate
	}
	state.tokens--
	state.inFlight++
	return Accepted
}

func (limiter *KeyedAdmissionLimiter) otherKeyRecentlySeen(key string, now time.Time) bool {
	cutoff := now.Add(-limiter.contentionWindow)
	return (limiter.recentKey != "" && limiter.recentKey != key && !limiter.recentAt.Before(cutoff)) ||
		(limiter.previousKey != "" && limiter.previousKey != key && !limiter.previousAt.Before(cutoff))
}

func (limiter *KeyedAdmissionLimiter) observeKey(key string, now time.Time) {
	if limiter.recentKey == key {
		limiter.recentAt = now
		return
	}
	limiter.previousKey = limiter.recentKey
	limiter.previousAt = limiter.recentAt
	limiter.recentKey = key
	limiter.recentAt = now
}

// Release returns one in-flight slot to the key. Releasing an unheld slot is
// a programming error and panics.
func (limiter *KeyedAdmissionLimiter) Release(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state := limiter.states[key]
	if state == nil || state.inFlight <= 0 {
		panic("gateway keyed admission underflow")
	}
	state.inFlight--
}

// Rejected returns the number of rejected admission attempts.
func (limiter *KeyedAdmissionLimiter) Rejected() uint64 { return limiter.rejected.Load() }

// InFlight returns the key's currently held in-flight slots.
func (limiter *KeyedAdmissionLimiter) InFlight(key string) int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state := limiter.states[key]
	if state == nil {
		return 0
	}
	return state.inFlight
}

// BudgetBuffer is a byte buffer that refuses to retain more than its budget.
type BudgetBuffer struct {
	buffer   bytes.Buffer
	budget   *ByteBudget
	acquired int64
}

// NewBudgetBuffer returns a buffer bound to the given budget.
func NewBudgetBuffer(budget *ByteBudget) *BudgetBuffer {
	return &BudgetBuffer{budget: budget}
}

// Write retains data only while the budget allows it.
func (buffer *BudgetBuffer) Write(data []byte) (int, error) {
	if !buffer.budget.TryAcquire(int64(len(data))) {
		return 0, ErrBudgetExhausted
	}
	n, err := buffer.buffer.Write(data)
	buffer.acquired += int64(n)
	if n < len(data) {
		buffer.budget.Release(int64(len(data) - n))
	}
	return n, err
}

// Bytes exposes the retained content.
func (buffer *BudgetBuffer) Bytes() []byte { return buffer.buffer.Bytes() }

// Len exposes the retained length.
func (buffer *BudgetBuffer) Len() int { return buffer.buffer.Len() }

// Release drops the buffer and returns all retained bytes to the budget.
func (buffer *BudgetBuffer) Release() {
	if buffer.acquired > 0 {
		buffer.budget.Release(buffer.acquired)
		buffer.acquired = 0
	}
	buffer.buffer = bytes.Buffer{}
}
