package gateway

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultResourceEnvelopeFitsDeploymentMemoryLimit(t *testing.T) {
	limits := DefaultLimits()
	if !limits.valid() {
		t.Fatal("default limits are invalid")
	}
	if limits.MaxStreamQueueBytes > limits.MaxSessionQueueBytes || limits.MaxSessionQueueBytes > limits.MaxGlobalQueueBytes {
		t.Fatal("queue budgets are not hierarchically bounded")
	}
	const retainedPayloadEnvelope = int64(64 << 20)
	if got := limits.MaxGlobalQueueBytes + limits.MaxIngressInFlightBytes; got > retainedPayloadEnvelope {
		t.Fatalf("retained application payload budgets=%d exceed 64 MiB envelope", got)
	}
	if limits.MaxAgentSessions != 64 || limits.MaxIngressInFlight != 32 {
		t.Fatalf("deployment-safe concurrency defaults sessions=%d ingress=%d", limits.MaxAgentSessions, limits.MaxIngressInFlight)
	}
	compose, err := os.ReadFile("../../deploy/gateway/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	for _, required := range []string{
		"mem_limit: 256m",
		"-max-stream-queue-bytes",
		"2097152",
		"-max-session-queue-bytes",
		"8388608",
		"-max-global-queue-bytes",
		"33554432",
		"-max-ingress-inflight-bytes",
		"-handshake-rate",
		"-ingress-rate",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Compose resource envelope missing %q", required)
		}
	}
}

func TestByteBudgetAndIngressBufferFailClosedAndRelease(t *testing.T) {
	budget := newByteBudget(10)
	if !budget.tryAcquire(6) {
		t.Fatal("initial byte reservation rejected")
	}
	if budget.tryAcquire(5) {
		t.Fatal("byte budget allowed overcommit")
	}
	used, limit, rejected := budget.snapshot()
	if used != 6 || limit != 10 || rejected != 1 {
		t.Fatalf("unexpected budget snapshot used=%d limit=%d rejected=%d", used, limit, rejected)
	}
	budget.release(6)
	if used, _, _ := budget.snapshot(); used != 0 {
		t.Fatalf("budget did not release: %d", used)
	}

	ingress := newByteBudget(10)
	buffer := newBudgetBuffer(ingress)
	if _, err := buffer.Write(bytes.Repeat([]byte{'x'}, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write(bytes.Repeat([]byte{'y'}, 5)); !errors.Is(err, errResourceBudget) {
		t.Fatalf("ingress budget error=%v want=%v", err, errResourceBudget)
	}
	buffer.release()
	if used, _, _ := ingress.snapshot(); used != 0 {
		t.Fatalf("ingress buffer leaked reservation: %d", used)
	}
}

func TestStreamQueueBudgetsBoundPerStreamSessionAndGlobal(t *testing.T) {
	global := newByteBudget(16)
	session := newByteBudget(12)
	var rejects atomic.Uint64
	first := newStream(1, 4, 8, session, global, &rejects)
	second := newStream(2, 4, 8, session, global, &rejects)

	if err := first.enqueue(bytes.Repeat([]byte{'a'}, 8)); err != nil {
		t.Fatal(err)
	}
	if err := second.enqueue(bytes.Repeat([]byte{'b'}, 5)); !errors.Is(err, errResourceBudget) {
		t.Fatalf("session budget error=%v want=%v", err, errResourceBudget)
	}
	if session.used.Load() != 8 || global.used.Load() != 8 {
		t.Fatalf("failed enqueue leaked budget session=%d global=%d", session.used.Load(), global.used.Load())
	}
	out := make([]byte, 8)
	if n, err := first.Read(out); err != nil || n != 8 {
		t.Fatalf("read n=%d err=%v", n, err)
	}
	if session.used.Load() != 0 || global.used.Load() != 0 {
		t.Fatal("dequeue did not release hierarchical budgets")
	}
	if err := second.enqueue(bytes.Repeat([]byte{'c'}, 5)); err != nil {
		t.Fatal(err)
	}
	second.finish(nil)
	if session.used.Load() != 0 || global.used.Load() != 0 {
		t.Fatal("stream cleanup did not release queued byte budgets")
	}

	global = newByteBudget(10)
	sessionA := newByteBudget(10)
	sessionB := newByteBudget(10)
	streamA := newStream(3, 2, 10, sessionA, global, &rejects)
	streamB := newStream(4, 2, 10, sessionB, global, &rejects)
	if err := streamA.enqueue(bytes.Repeat([]byte{'d'}, 6)); err != nil {
		t.Fatal(err)
	}
	if err := streamB.enqueue(bytes.Repeat([]byte{'e'}, 5)); !errors.Is(err, errResourceBudget) {
		t.Fatalf("global budget error=%v want=%v", err, errResourceBudget)
	}
	streamA.finish(nil)
	streamB.finish(nil)
	if global.used.Load() != 0 {
		t.Fatalf("global queue budget leaked: %d", global.used.Load())
	}
	if rejects.Load() < 2 {
		t.Fatalf("resource rejection counter=%d want>=2", rejects.Load())
	}
}

func TestStreamQueueFrameLimitReleasesRejectedReservation(t *testing.T) {
	global := newByteBudget(64)
	session := newByteBudget(64)
	var rejects atomic.Uint64
	stream := newStream(1, 1, 64, session, global, &rejects)
	if err := stream.enqueue([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := stream.enqueue([]byte("second")); err == nil {
		t.Fatal("frame queue over-capacity unexpectedly succeeded")
	}
	if got := global.used.Load(); got != int64(len("first")) {
		t.Fatalf("rejected frame leaked global reservation: %d", got)
	}
	stream.finish(nil)
	if global.used.Load() != 0 || session.used.Load() != 0 {
		t.Fatal("frame-limit cleanup leaked byte reservations")
	}
}

func TestGatewayRateAndConcurrencyLimitsFailClosed(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.IngressRatePerSecond = 1
	limits.IngressRateBurst = 1
	limits.HandshakeRatePerSecond = 1
	limits.HandshakeRateBurst = 1
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://gateway.invalid/missing", nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("invalid ingress attempt %d status=%d want=%d", i+1, recorder.Code, http.StatusNotFound)
		}
	}
	gateway.resources.ingressRate.mu.Lock()
	remainingIngressTokens := gateway.resources.ingressRate.tokens
	gateway.resources.ingressRate.mu.Unlock()
	if remainingIngressTokens != 1 {
		t.Fatalf("invalid routes consumed global ingress rate budget: tokens=%v want=1", remainingIngressTokens)
	}
	if len(gateway.resources.ingressRouteAdmission.states) != 0 || len(gateway.resources.ingressDeviceAdmission.states) != 0 {
		t.Fatal("invalid routes created route/device admission state")
	}

	for len(gateway.resources.ingressSlots) < cap(gateway.resources.ingressSlots) {
		gateway.resources.ingressSlots <- struct{}{}
	}
	blocked := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "https://gateway.invalid/missing", nil))
	if blocked.Code != http.StatusNotFound {
		t.Fatalf("invalid route was blocked by tunnel concurrency before route lookup: status=%d want=%d", blocked.Code, http.StatusNotFound)
	}
	for len(gateway.resources.ingressSlots) > 0 {
		<-gateway.resources.ingressSlots
	}

	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://gateway.invalid"+agentPath, nil))
	}
	gateway.resources.handshakeRate.mu.Lock()
	remainingHandshakeTokens := gateway.resources.handshakeRate.tokens
	gateway.resources.handshakeRate.mu.Unlock()
	if remainingHandshakeTokens != 1 {
		t.Fatalf("non-WebSocket/unauthorized preface traffic consumed validated handshake rate budget: tokens=%v want=1", remainingHandshakeTokens)
	}
}

func TestGatewayResourceMetricsAreAggregateAndLowCardinality(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !gateway.resources.queueBytes.tryAcquire(7) || !gateway.resources.ingressBytes.tryAcquire(9) {
		t.Fatal("metric setup reservation failed")
	}
	defer gateway.resources.queueBytes.release(7)
	defer gateway.resources.ingressBytes.release(9)
	gateway.resources.queueRejects.Add(2)
	gateway.resources.ingressRejects.Add(3)
	gateway.resources.handshakeRejects.Add(4)
	gateway.resources.sessionRejects.Add(5)

	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://gateway.invalid/metrics", nil))
	body := recorder.Body.String()
	for _, metric := range []string{
		"hooshix_gateway_queued_bytes 7",
		"hooshix_gateway_agent_sessions_limit 64",
		"hooshix_gateway_pending_handshakes_limit 64",
		"hooshix_gateway_queued_bytes_limit 33554432",
		"hooshix_gateway_ingress_inflight_limit 32",
		"hooshix_gateway_ingress_inflight_bytes 9",
		"hooshix_gateway_ingress_inflight_bytes_limit 33554432",
		"hooshix_gateway_queue_rejections_total 2",
		"hooshix_gateway_ingress_rejections_total 3",
		"hooshix_gateway_handshake_rejections_total 4",
		"hooshix_gateway_session_capacity_rejections_total 5",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("metrics missing %q\n%s", metric, body)
		}
	}
	if strings.Contains(body, "{") || strings.Contains(body, identity.deviceID) || strings.Contains(body, testRouteHost) {
		t.Fatal("resource metrics contain labels or user-controlled identifiers")
	}
}

func TestResourcePrimitivesStressDoNotGrowGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	budget := newByteBudget(64)
	bucket := newTokenBucket(100000, 64)
	now := time.Now()
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				if budget.tryAcquire(8) {
					budget.release(8)
				}
				_ = bucket.allow(now.Add(time.Duration(worker*10000+i) * time.Microsecond))
			}
		}(worker)
	}
	wg.Wait()
	if used, _, _ := budget.snapshot(); used != 0 {
		t.Fatalf("stress leaked byte reservations: %d", used)
	}
	runtime.Gosched()
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("resource primitive stress grew goroutines: before=%d after=%d", before, after)
	}
}
