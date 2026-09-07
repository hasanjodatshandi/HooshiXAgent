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

const (
	admissionAccepted            = gatewayresources.Accepted
	admissionRejectedRate        = gatewayresources.RejectedRate
	admissionRejectedConcurrency = gatewayresources.RejectedConcurrency
)

type budgetBuffer = gatewayresources.BudgetBuffer

func newBudgetBuffer(budget *byteBudget) *budgetBuffer {
	return gatewayresources.NewBudgetBuffer(budget)
}

func fairnessShare(global int) int { return gatewayresources.FairnessShare(global) }

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
	queueRejects             atomicUint64
	handshakeRejects         atomicUint64
	ingressRejects           atomicUint64
	sessionRejects           atomicUint64
	healthReports            atomicUint64
	reconnects               atomicUint64
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
