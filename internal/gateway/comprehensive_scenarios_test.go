package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayConcurrentBurstWithinConfiguredBounds(t *testing.T) {
	const burst = 8

	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.MaxStreamsPerSession = burst
	limits.MaxIngressInFlight = burst
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	})
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()

	allArrived := make(chan struct{})
	release := make(chan struct{})
	var arrivals atomic.Int32
	var once sync.Once
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if arrivals.Add(1) == burst {
			once.Do(func() { close(allArrived) })
		}
		select {
		case <-release:
		case <-request.Context().Done():
			return
		}
		_, _ = fmt.Fprintf(w, "burst:%s", request.URL.Path)
	}))
	defer local.Close()

	client := tlsServer.Client()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, client, identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	requests := make([]*http.Request, 0, burst)
	for i := 0; i < burst; i++ {
		requests = append(requests, newPublicRequest(t, fmt.Sprintf("%s/burst-%d", tlsServer.URL, i), testRouteHost, nil))
	}

	errCh := make(chan error, burst)
	var wg sync.WaitGroup
	for index, request := range requests {
		index, request := index, request
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := client.Do(request)
			if err != nil {
				errCh <- fmt.Errorf("request %d: %w", index, err)
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				errCh <- fmt.Errorf("request %d read: %w", index, err)
				return
			}
			want := fmt.Sprintf("burst:/burst-%d", index)
			if response.StatusCode != http.StatusOK || string(body) != want {
				errCh <- fmt.Errorf("request %d status=%d body=%q want=%q", index, response.StatusCode, body, want)
			}
		}()
	}

	select {
	case <-allArrived:
	case <-time.After(5 * time.Second):
		close(release)
		wg.Wait()
		t.Fatalf("concurrent burst reached %d/%d local handlers", arrivals.Load(), burst)
	}
	if got := agent.maxConcurrent.Load(); got < burst {
		close(release)
		wg.Wait()
		t.Fatalf("mock Agent concurrent streams=%d want=%d", got, burst)
	}
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, 2*time.Second, func() bool {
		used, _, _ := gateway.resources.ingressBytes.snapshot()
		return used == 0 && len(gateway.resources.ingressSlots) == 0
	})
}
