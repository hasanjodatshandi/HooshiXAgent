package gateway

import (
	"sync/atomic"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway/gatewayresources"
)

type atomicUint64 = atomic.Uint64

// Resource-budget primitives live in the pure-domain package
// internal/gateway/gatewayresources (ADR-0013). These aliases keep the
// in-package names used by Gateway session/ingress orchestration.

type byteBudget = gatewayresources.ByteBudget

func newByteBudget(limit int64) *byteBudget { return gatewayresources.NewByteBudget(limit) }

type tokenBucket = gatewayresources.TokenBucket

func newTokenBucket(rate, burst int) *tokenBucket {
	return gatewayresources.NewTokenBucket(rate, burst)
}

type keyedAdmissionLimiter = gatewayresources.KeyedAdmissionLimiter

func newKeyedAdmissionLimiter(maxInFlight, rate, burst int) *keyedAdmissionLimiter {
	return gatewayresources.NewKeyedAdmissionLimiter(maxInFlight, rate, burst)
}

func newHardKeyedAdmissionLimiter(maxInFlight, rate, burst int) *keyedAdmissionLimiter {
	return gatewayresources.NewHardKeyedAdmissionLimiter(maxInFlight, rate, burst)
}

type keyedRateLimiter = gatewayresources.KeyedTokenBuckets

func newKeyedRateLimiter(rate, burst int) *keyedRateLimiter {
	return gatewayresources.NewKeyedTokenBuckets(rate, burst)
}

const (
	admissionAccepted            = gatewayresources.Accepted
	admissionRejectedRate        = gatewayresources.RejectedRate
	admissionRejectedConcurrency = gatewayresources.RejectedConcurrency
)

var errResourceBudget = gatewayresources.ErrBudgetExhausted

// gatewayResources aggregates the bounded runtime resources shared by the
// Gateway data plane, plus the low-cardinality aggregate rejection counters.
type gatewayResources struct {
	queueBytes               *byteBudget
	ingressBytes             *byteBudget
	ingressSlots             chan struct{}
	handshakeRate            *tokenBucket
	ingressRate              *tokenBucket
	ingressRouteAdmission    *keyedAdmissionLimiter
	ingressDeviceAdmission   *keyedAdmissionLimiter
	handshakeDeviceAdmission *keyedAdmissionLimiter
	preAuthRate              *keyedRateLimiter
	queueRejects             atomicUint64
	handshakeRejects         atomicUint64
	ingressRejects           atomicUint64
	sessionRejects           atomicUint64
	healthReports            atomicUint64
	reconnects               atomicUint64
	agentBytes               atomicUint64
	publicBytes              atomicUint64
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
		// Pre-authentication admission is a per-peer connection rate applied
		// before a pending-handshake slot is taken, so a peer that opens
		// sockets and stalls in the unauthenticated preface cannot cycle the
		// global handshake slots at will. It is deliberately separate from
		// handshakeRate/handshakeDeviceAdmission: the authenticated handshake
		// budget is never spent by unauthenticated traffic.
		preAuthRate: newKeyedRateLimiter(limits.PreAuthRatePerSecond, limits.PreAuthRateBurst),
	}
}
