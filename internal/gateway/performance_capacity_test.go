package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	r12CapacityRequestTimeout = 30 * time.Second
	r12CapacityP99Limit       = 5 * time.Second
)

type capacitySample struct {
	level          int
	duration       time.Duration
	latencies      []time.Duration
	peakHeapBytes  uint64
	peakGoroutines uint64
	maxLocalActive int32
	maxAgentActive int32
}

func TestGatewayCapacityEnvelope(t *testing.T) {
	requireR12Capacity(t)
	levels := []int{32, 100, 500, 1000}
	for _, level := range levels {
		level := level
		t.Run(fmt.Sprintf("concurrency-%d", level), func(t *testing.T) {
			sample := runCapacitySample(t, level)
			p50 := percentileDuration(sample.latencies, 50)
			p95 := percentileDuration(sample.latencies, 95)
			p99 := percentileDuration(sample.latencies, 99)
			rps := float64(level) / sample.duration.Seconds()
			t.Logf("R12_CAPACITY concurrency=%d requests=%d duration=%s rps=%.2f p50=%s p95=%s p99=%s peak_heap_bytes=%d peak_goroutines=%d max_local_active=%d max_agent_streams=%d",
				level, level, sample.duration.Round(time.Microsecond), rps, p50.Round(time.Microsecond), p95.Round(time.Microsecond), p99.Round(time.Microsecond),
				sample.peakHeapBytes, sample.peakGoroutines, sample.maxLocalActive, sample.maxAgentActive)
			if sample.maxLocalActive != int32(level) {
				t.Fatalf("local concurrency=%d want=%d", sample.maxLocalActive, level)
			}
			if sample.maxAgentActive < int32(level) {
				t.Fatalf("Agent concurrent streams=%d want-at-least=%d", sample.maxAgentActive, level)
			}
			if p99 > r12CapacityP99Limit {
				t.Fatalf("synthetic p99=%s exceeds stable R-12 regression ceiling %s", p99, r12CapacityP99Limit)
			}
		})
	}
}

func TestAuthenticatedSessionReleasesPendingHandshakeSlot(t *testing.T) {
	identities := []testIdentity{newTestIdentity(t), newTestIdentity(t)}
	metadata := NewSnapshotMetadata()
	for index := range identities {
		identities[index].deviceID = fmt.Sprintf("device-handshake-release-%d", index)
		identities[index].authorizationID = fmt.Sprintf("auth-handshake-release-%d", index)
		identities[index].tokenID = fmt.Sprintf("token-handshake-release-%d", index)
		authorization, _ := metadataRecords(identities[index], testRouteHost)
		encoded, err := json.Marshal(authorization)
		if err != nil {
			t.Fatal(err)
		}
		if err := metadata.addAuthorizationJSON(encoded); err != nil {
			t.Fatal(err)
		}
	}
	limits := DefaultLimits()
	limits.MaxPendingHandshakes = 1
	limits.HandshakeRatePerSecond = 100
	limits.HandshakeRateBurst = 100
	gateway, err := New(metadata, NopStatusSink{}, limits, performanceTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	}()
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer local.Close()
	client := performanceHTTPClient(tlsServer, 4)

	first := connectMockAgent(t, context.Background(), tlsServer.URL, client, identities[0], local.URL)
	defer first.close()
	waitFor(t, time.Second, func() bool { return len(gateway.handshakeSlots) == 0 })
	second := connectMockAgent(t, context.Background(), tlsServer.URL, client, identities[1], local.URL)
	defer second.close()
	waitFor(t, time.Second, func() bool {
		gateway.mu.RLock()
		count := len(gateway.sessions)
		gateway.mu.RUnlock()
		return count == 2 && len(gateway.handshakeSlots) == 0
	})
}

func TestGatewayResidentSessionCapacity(t *testing.T) {
	requireR12Capacity(t)
	levels := []int{64, 100, 500, 1000}
	for _, level := range levels {
		level := level
		t.Run(fmt.Sprintf("sessions-%d", level), func(t *testing.T) {
			identities := make([]testIdentity, 0, level)
			metadata := NewSnapshotMetadata()
			for index := 0; index < level; index++ {
				identity := newTestIdentity(t)
				identity.deviceID = fmt.Sprintf("device-capacity-%04d", index)
				identity.authorizationID = fmt.Sprintf("auth-capacity-%04d", index)
				identity.tokenID = fmt.Sprintf("token-capacity-%04d", index)
				authorization, _ := metadataRecords(identity, testRouteHost)
				encoded, err := json.Marshal(authorization)
				if err != nil {
					t.Fatal(err)
				}
				if err := metadata.addAuthorizationJSON(encoded); err != nil {
					t.Fatal(err)
				}
				identities = append(identities, identity)
			}

			limits := DefaultLimits()
			if level > limits.MaxAgentSessions {
				limits.MaxAgentSessions = level
				limits.HandshakeRatePerSecond = 100000
				limits.HandshakeRateBurst = 100000
			}
			gateway, err := New(metadata, NopStatusSink{}, limits, performanceTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := gateway.Close(ctx); err != nil {
					t.Errorf("gateway close: %v", err)
				}
			}()
			tlsServer := httptest.NewTLSServer(gateway.Handler())
			defer tlsServer.Close()
			local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}))
			defer local.Close()
			client := performanceHTTPClient(tlsServer, level)

			runtime.GC()
			var baseline runtime.MemStats
			runtime.ReadMemStats(&baseline)
			peakHeap := atomic.Uint64{}
			peakHeap.Store(baseline.HeapAlloc)
			peakGoroutines := atomic.Uint64{}
			peakGoroutines.Store(uint64(runtime.NumGoroutine()))
			sampleDone := make(chan struct{})
			go sampleRuntimePeaks(sampleDone, &peakHeap, &peakGoroutines)

			agents := make([]*mockAgent, 0, level)
			started := time.Now()
			for _, identity := range identities {
				agent := connectMockAgent(t, context.Background(), tlsServer.URL, client, identity, local.URL)
				agent.suppressResponseClose = true
				agents = append(agents, agent)
			}
			waitFor(t, 5*time.Second, func() bool {
				gateway.mu.RLock()
				resident := len(gateway.sessions)
				gateway.mu.RUnlock()
				return resident == level
			})
			duration := time.Since(started)
			close(sampleDone)
			t.Logf("R12_SESSIONS concurrency=%d connect_duration=%s sessions_per_second=%.2f peak_heap_bytes=%d peak_goroutines=%d",
				level, duration.Round(time.Microsecond), float64(level)/duration.Seconds(), peakHeap.Load(), peakGoroutines.Load())
			for _, agent := range agents {
				agent.close()
			}
			waitFor(t, 10*time.Second, func() bool {
				gateway.mu.RLock()
				count := len(gateway.sessions)
				gateway.mu.RUnlock()
				return count == 0
			})
		})
	}
}

func BenchmarkGatewayPublicRoundTrip(b *testing.B) {
	const parallelismCeiling = 256
	identity := newTestIdentity(b)
	limits := performanceProbeLimits(parallelismCeiling)
	gateway, err := New(testMetadata(b, identity, testRouteHost), NopStatusSink{}, limits, performanceTestLogger())
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	}()
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()
	client := performanceHTTPClient(tlsServer, parallelismCeiling)
	agent := connectMockAgent(b, context.Background(), tlsServer.URL, client, identity, local.URL)
	agent.suppressResponseClose = true
	defer agent.close()
	waitFor(b, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	b.ReportAllocs()
	b.ResetTimer()
	var firstErr error
	var errOnce sync.Once
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, err := http.NewRequest(http.MethodGet, tlsServer.URL+"/benchmark", nil)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			request.Host = testRouteHost
			ctx, cancel := context.WithTimeout(context.Background(), r12CapacityRequestTimeout)
			request = request.WithContext(ctx)
			response, err := client.Do(request)
			if err != nil {
				cancel()
				errOnce.Do(func() { firstErr = err })
				return
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			cancel()
			if response.StatusCode != http.StatusOK {
				errOnce.Do(func() { firstErr = fmt.Errorf("status=%d", response.StatusCode) })
				return
			}
			if readErr != nil {
				errOnce.Do(func() { firstErr = readErr })
				return
			}
			if closeErr != nil {
				errOnce.Do(func() { firstErr = closeErr })
				return
			}
		}
	})
	b.StopTimer()
	if firstErr != nil {
		b.Fatal(firstErr)
	}
}

func runCapacitySample(t *testing.T, level int) capacitySample {
	t.Helper()
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	if level > limits.MaxIngressInFlight {
		limits = performanceProbeLimits(level)
	}
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, performanceTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := gateway.Close(ctx); err != nil {
			t.Errorf("gateway close: %v", err)
		}
	}()
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	allArrived := make(chan struct{})
	release := make(chan struct{})
	var arrived atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	var arrivedOnce sync.Once
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		updateAtomicMax(&maxActive, current)
		defer active.Add(-1)
		if arrived.Add(1) == int32(level) {
			arrivedOnce.Do(func() { close(allArrived) })
		}
		select {
		case <-release:
		case <-request.Context().Done():
			return
		case <-time.After(20 * time.Second):
			http.Error(w, "R-12 capacity barrier timeout", http.StatusGatewayTimeout)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()

	client := performanceHTTPClient(tlsServer, level)
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, client, identity, local.URL)
	agent.suppressResponseClose = true
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	peakHeap := atomic.Uint64{}
	peakHeap.Store(baseline.HeapAlloc)
	peakGoroutines := atomic.Uint64{}
	peakGoroutines.Store(uint64(runtime.NumGoroutine()))
	sampleDone := make(chan struct{})
	go sampleRuntimePeaks(sampleDone, &peakHeap, &peakGoroutines)

	startGate := make(chan struct{})
	latencies := make([]time.Duration, level)
	errorsByRequest := make([]error, level)
	var wg sync.WaitGroup
	wg.Add(level)
	started := time.Now()
	for index := 0; index < level; index++ {
		index := index
		go func() {
			defer wg.Done()
			<-startGate
			request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/capacity/%d", tlsServer.URL, index), nil)
			if err != nil {
				errorsByRequest[index] = err
				return
			}
			request.Host = testRouteHost
			ctx, cancel := context.WithTimeout(context.Background(), r12CapacityRequestTimeout)
			defer cancel()
			request = request.WithContext(ctx)
			requestStarted := time.Now()
			response, err := client.Do(request)
			latencies[index] = time.Since(requestStarted)
			if err != nil {
				errorsByRequest[index] = err
				return
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				errorsByRequest[index] = readErr
				return
			}
			if closeErr != nil {
				errorsByRequest[index] = closeErr
				return
			}
			if response.StatusCode != http.StatusOK || string(body) != "ok" {
				errorsByRequest[index] = fmt.Errorf("status=%d body=%q", response.StatusCode, body)
			}
		}()
	}
	close(startGate)
	select {
	case <-allArrived:
	case <-time.After(20 * time.Second):
		close(release)
		wg.Wait()
		close(sampleDone)
		t.Fatalf("R-12 capacity level %d reached only %d local requests", level, arrived.Load())
	}
	close(release)
	wg.Wait()
	duration := time.Since(started)
	close(sampleDone)

	for index, requestErr := range errorsByRequest {
		if requestErr != nil {
			t.Fatalf("capacity request %d/%d: %v", index, level, requestErr)
		}
	}
	waitFor(t, 3*time.Second, func() bool {
		used, _, _ := gateway.resources.ingressBytes.snapshot()
		return used == 0 && len(gateway.resources.ingressSlots) == 0 && agent.active.Load() == 0
	})

	return capacitySample{
		level:          level,
		duration:       duration,
		latencies:      latencies,
		peakHeapBytes:  peakHeap.Load(),
		peakGoroutines: peakGoroutines.Load(),
		maxLocalActive: maxActive.Load(),
		maxAgentActive: agent.maxConcurrent.Load(),
	}
}

func performanceProbeLimits(concurrency int) Limits {
	limits := DefaultLimits()
	if concurrency < 64 {
		concurrency = 64
	}
	limits.MaxStreamsPerSession = concurrency
	limits.MaxIngressInFlight = concurrency
	limits.IngressRatePerSecond = 100000
	limits.IngressRateBurst = 100000
	limits.ReadTimeout = 30 * time.Second
	limits.WriteTimeout = 30 * time.Second
	return limits
}

func performanceHTTPClient(server *httptest.Server, concurrency int) *http.Client {
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.MaxIdleConns = concurrency * 2
	transport.MaxIdleConnsPerHost = concurrency * 2
	transport.MaxConnsPerHost = concurrency * 2
	transport.IdleConnTimeout = 30 * time.Second
	return &http.Client{Transport: transport, Timeout: r12CapacityRequestTimeout}
}

func requireR12Capacity(t *testing.T) {
	t.Helper()
	if os.Getenv("HOOSHIX_R12_ENABLE") != "1" {
		t.Skip("R-12 capacity probe runs only in scripts/ci/performance-capacity.sh")
	}
}

func performanceTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func sampleRuntimePeaks(done <-chan struct{}, peakHeap, peakGoroutines *atomic.Uint64) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			updateAtomicMaxUint64(peakHeap, stats.HeapAlloc)
			updateAtomicMaxUint64(peakGoroutines, uint64(runtime.NumGoroutine()))
		}
	}
}

func percentileDuration(values []time.Duration, percentile int) time.Duration {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*percentile + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(ordered) {
		index = len(ordered)
	}
	return ordered[index-1]
}

func updateAtomicMax(target *atomic.Int32, candidate int32) {
	for {
		current := target.Load()
		if candidate <= current || target.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func updateAtomicMaxUint64(target *atomic.Uint64, candidate uint64) {
	for {
		current := target.Load()
		if candidate <= current || target.CompareAndSwap(current, candidate) {
			return
		}
	}
}
