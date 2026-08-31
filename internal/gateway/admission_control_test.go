package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestAdaptiveIngressAdmissionPreservesUncontendedCapacityAndIsolatesNoisyKeys(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxIngressInFlight = 4
	limits.IngressRatePerSecond = 1000
	limits.IngressRateBurst = 1000
	resources := newGatewayResources(limits)
	now := time.Now()

	for _, limiter := range []*keyedAdmissionLimiter{resources.ingressRouteAdmission, resources.ingressDeviceAdmission} {
		for i := 0; i < limits.MaxIngressInFlight; i++ {
			if got := limiter.tryAcquire("noisy", now); got != admissionAccepted {
				t.Fatalf("uncontended admission %d/%d rejected: %v", i+1, limits.MaxIngressInFlight, got)
			}
		}
		if got := limiter.tryAcquire("neighbor", now); got != admissionAccepted {
			t.Fatalf("neighbor observation should pass keyed admission before global ceiling, got %v", got)
		}
		limiter.release("neighbor")
		if got := limiter.tryAcquire("noisy", now); got != admissionRejectedConcurrency {
			t.Fatalf("noisy key reacquired borrowed capacity during contention: got %v", got)
		}
		limiter.release("noisy")
		if got := limiter.tryAcquire("neighbor", now); got != admissionAccepted {
			t.Fatalf("neighbor could not claim capacity released by noisy key: %v", got)
		}
		limiter.release("neighbor")
		for i := 1; i < limits.MaxIngressInFlight; i++ {
			limiter.release("noisy")
		}
	}
}

func TestAdaptiveIngressRateLeavesRefillCapacityForNeighbor(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxIngressInFlight = 32
	limits.IngressRatePerSecond = 4
	limits.IngressRateBurst = 4
	resources := newGatewayResources(limits)
	now := time.Now()

	for i := 0; i < 4; i++ {
		if got := resources.ingressRouteAdmission.tryAcquire("route-a", now); got != admissionAccepted {
			t.Fatalf("initial route-a admission %d rejected: %v", i+1, got)
		}
		resources.ingressRouteAdmission.release("route-a")
		if !resources.ingressRate.allow(now) {
			t.Fatalf("initial global token %d rejected", i+1)
		}
	}

	if got := resources.ingressRouteAdmission.tryAcquire("route-b", now); got != admissionAccepted {
		t.Fatalf("route-b observation rejected by keyed limiter: %v", got)
	}
	resources.ingressRouteAdmission.release("route-b")
	if resources.ingressRate.allow(now) {
		t.Fatal("exhausted global bucket unexpectedly admitted route-b")
	}

	later := now.Add(time.Second)
	for i := 0; i < fairnessShare(limits.IngressRatePerSecond); i++ {
		if got := resources.ingressRouteAdmission.tryAcquire("route-a", later); got != admissionAccepted {
			t.Fatalf("fair route-a refill %d rejected: %v", i+1, got)
		}
		resources.ingressRouteAdmission.release("route-a")
		if !resources.ingressRate.allow(later) {
			t.Fatalf("global refill for route-a %d rejected", i+1)
		}
	}
	if got := resources.ingressRouteAdmission.tryAcquire("route-a", later); got != admissionRejectedRate {
		t.Fatalf("noisy route exceeded contended fair rate: got %v", got)
	}
	if got := resources.ingressRouteAdmission.tryAcquire("route-b", later); got != admissionAccepted {
		t.Fatalf("neighbor route did not retain keyed rate capacity: %v", got)
	}
	resources.ingressRouteAdmission.release("route-b")
	if !resources.ingressRate.allow(later) {
		t.Fatal("neighbor route could not consume global refill left by noisy-route fair cap")
	}
}

func TestUnauthenticatedHandshakeSlotsRecoverWithinPrefaceDeadline(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxPendingHandshakes = 2
	limits.HandshakeTimeout = 800 * time.Millisecond
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()

	held := []*websocket.Conn{
		dialRawAgent(t, server.Client(), server.URL),
		dialRawAgent(t, server.Client(), server.URL),
	}
	defer func() {
		for _, conn := range held {
			conn.CloseNow()
		}
	}()
	waitFor(t, time.Second, func() bool { return len(gateway.handshakeSlots) == limits.MaxPendingHandshakes })
	waitFor(t, 2*time.Second, func() bool { return len(gateway.handshakeSlots) == 0 })

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), server.URL, server.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
}

func TestValidatedHandshakeRateIgnoresInvalidPrefaceButLimitsAuthorizedFlood(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.HandshakeRatePerSecond = 1
	limits.HandshakeRateBurst = 1
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()

	first := dialRawAgent(t, server.Client(), server.URL)
	defer first.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendClientHello(ctx, first, identity, 1); err != nil {
		t.Fatal(err)
	}
	if frame := readFrameForTest(t, ctx, first); frame.Sequence != 1 {
		t.Fatalf("first authorized handshake challenge sequence=%d", frame.Sequence)
	}

	second := dialRawAgent(t, server.Client(), server.URL)
	defer second.CloseNow()
	if err := sendClientHello(ctx, second, identity, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(ctx, second); err == nil {
		t.Fatal("second authorized handshake bypassed global validated-handshake rate limit")
	}
}

func TestValidatedHandshakeDeviceFairnessReservesGlobalCapacity(t *testing.T) {
	identityA := newTestIdentity(t)
	identityB := newTestIdentity(t)
	identityB.deviceID = "device-runtime-002"
	identityB.authorizationID = "auth-runtime-002"
	identityB.tokenID = "token-runtime-002"

	metadata := testMetadata(t, identityA, testRouteHost)
	authB, _ := metadataRecords(identityB, "other.hooshix.test")
	authJSON, err := json.Marshal(authB)
	if err != nil {
		t.Fatal(err)
	}
	if err := metadata.addAuthorizationJSON(authJSON); err != nil {
		t.Fatal(err)
	}

	limits := DefaultLimits()
	limits.MaxPendingHandshakes = 4
	limits.HandshakeRatePerSecond = 1000
	limits.HandshakeRateBurst = 1000
	limits.HandshakeTimeout = 2 * time.Second
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()

	held := make([]*websocket.Conn, 0, fairnessShare(limits.MaxPendingHandshakes))
	defer func() {
		for _, conn := range held {
			conn.CloseNow()
		}
	}()
	for i := 0; i < fairnessShare(limits.MaxPendingHandshakes); i++ {
		conn := dialRawAgent(t, server.Client(), server.URL)
		held = append(held, conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := sendClientHello(ctx, conn, identityA, 1); err != nil {
			cancel()
			t.Fatal(err)
		}
		if frame := readFrameForTest(t, ctx, conn); frame.Sequence != 1 {
			cancel()
			t.Fatalf("device A challenge sequence=%d", frame.Sequence)
		}
		cancel()
	}

	overflow := dialRawAgent(t, server.Client(), server.URL)
	defer overflow.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := sendClientHello(ctx, overflow, identityA, 1); err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := readFrame(ctx, overflow); err == nil {
		cancel()
		t.Fatal("single device occupied the reserved validated-handshake capacity")
	}
	cancel()
	waitFor(t, time.Second, func() bool { return len(gateway.handshakeSlots) == fairnessShare(limits.MaxPendingHandshakes) })

	neighbor := dialRawAgent(t, server.Client(), server.URL)
	defer neighbor.CloseNow()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendClientHello(ctx, neighbor, identityB, 1); err != nil {
		t.Fatal(err)
	}
	if frame := readFrameForTest(t, ctx, neighbor); frame.Sequence != 1 {
		t.Fatalf("neighbor device challenge sequence=%d", frame.Sequence)
	}
}

func TestSuccessfulHandshakeReleasesDeviceAdmissionWhileSessionStaysLive(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(gateway.Handler())
	defer server.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	agent := connectMockAgent(t, context.Background(), server.URL, server.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	gateway.resources.handshakeDeviceAdmission.mu.Lock()
	state := gateway.resources.handshakeDeviceAdmission.states[identity.deviceID]
	inFlight := 0
	if state != nil {
		inFlight = state.inFlight
	}
	gateway.resources.handshakeDeviceAdmission.mu.Unlock()
	if inFlight != 0 {
		t.Fatalf("validated handshake admission leaked into live session lifetime: in_flight=%d", inFlight)
	}
}
