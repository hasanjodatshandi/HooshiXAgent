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

type admissionRejectReason uint8

const (
	admissionAccepted admissionRejectReason = iota
	admissionRejectedRate
	admissionRejectedConcurrency
)

type keyedAdmissionState struct {
	inFlight int
	tokens   float64
	last     time.Time
}

type keyedAdmissionLimiter struct {
	mu               sync.Mutex
	maxInFlight      int
	fairMaxInFlight  int
	rate             float64
	fairRate         float64
	burst            float64
	fairBurst        float64
	contentionWindow time.Duration
	alwaysFair       bool
	states           map[string]*keyedAdmissionState
	recentKey        string
	recentAt         time.Time
	previousKey      string
	previousAt       time.Time
	rejected         atomic.Uint64
}

func fairnessShare(global int) int {
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

func newKeyedAdmissionLimiter(maxInFlight, rate, burst int) *keyedAdmissionLimiter {
	return &keyedAdmissionLimiter{
		maxInFlight:      maxInFlight,
		fairMaxInFlight:  fairnessShare(maxInFlight),
		rate:             float64(rate),
		fairRate:         float64(fairnessShare(rate)),
		burst:            float64(burst),
		fairBurst:        float64(fairnessShare(burst)),
		contentionWindow: 2 * time.Second,
		states:           make(map[string]*keyedAdmissionState),
	}
}

func newHardKeyedAdmissionLimiter(maxInFlight, rate, burst int) *keyedAdmissionLimiter {
	limiter := newKeyedAdmissionLimiter(maxInFlight, rate, burst)
	limiter.alwaysFair = true
	return limiter
}

func (limiter *keyedAdmissionLimiter) tryAcquire(key string, now time.Time) admissionRejectReason {
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
		state = &keyedAdmissionState{tokens: limiter.burst, last: now}
		limiter.states[key] = state
	}
	if state.inFlight >= maxInFlight {
		limiter.rejected.Add(1)
		return admissionRejectedConcurrency
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
		return admissionRejectedRate
	}
	state.tokens--
	state.inFlight++
	return admissionAccepted
}

func (limiter *keyedAdmissionLimiter) otherKeyRecentlySeen(key string, now time.Time) bool {
	cutoff := now.Add(-limiter.contentionWindow)
	return (limiter.recentKey != "" && limiter.recentKey != key && !limiter.recentAt.Before(cutoff)) ||
		(limiter.previousKey != "" && limiter.previousKey != key && !limiter.previousAt.Before(cutoff))
}

func (limiter *keyedAdmissionLimiter) observeKey(key string, now time.Time) {
	if limiter.recentKey == key {
		limiter.recentAt = now
		return
	}
	limiter.previousKey = limiter.recentKey
	limiter.previousAt = limiter.recentAt
	limiter.recentKey = key
	limiter.recentAt = now
}

func (limiter *keyedAdmissionLimiter) release(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state := limiter.states[key]
	if state == nil || state.inFlight <= 0 {
		panic("gateway keyed admission underflow")
	}
	state.inFlight--
}

type gatewayResources struct {
	queueBytes               *byteBudget
	ingressBytes             *byteBudget
	ingressSlots             chan struct{}
	handshakeRate            *tokenBucket
	ingressRate              *tokenBucket
	ingressRouteAdmission    *keyedAdmissionLimiter
	ingressDeviceAdmission   *keyedAdmissionLimiter
	handshakeDeviceAdmission *keyedAdmissionLimiter
	queueRejects             atomic.Uint64
	handshakeRejects         atomic.Uint64
	ingressRejects           atomic.Uint64
	sessionRejects           atomic.Uint64
}

func newGatewayResources(limits Limits) gatewayResources {
	return gatewayResources{
		queueBytes:               newByteBudget(limits.MaxGlobalQueueBytes),
		ingressBytes:             newByteBudget(limits.MaxIngressInFlightBytes),
		ingressSlots:             make(chan struct{}, limits.MaxIngressInFlight),
		handshakeRate:            newTokenBucket(limits.HandshakeRatePerSecond, limits.HandshakeRateBurst),
		ingressRate:              newTokenBucket(limits.IngressRatePerSecond, limits.IngressRateBurst),
		ingressRouteAdmission:    newKeyedAdmissionLimiter(limits.MaxIngressInFlight, limits.IngressRatePerSecond, limits.IngressRateBurst),
		ingressDeviceAdmission:   newKeyedAdmissionLimiter(limits.MaxIngressInFlight, limits.IngressRatePerSecond, limits.IngressRateBurst),
		handshakeDeviceAdmission: newHardKeyedAdmissionLimiter(limits.MaxPendingHandshakes, limits.HandshakeRatePerSecond, limits.HandshakeRateBurst),
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
