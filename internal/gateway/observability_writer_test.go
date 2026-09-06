package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

type blockingStatusSink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (sink *blockingStatusSink) Emit(ctx context.Context, _ contractv1.GatewayStatusSignal) error {
	sink.once.Do(func() { close(sink.started) })
	select {
	case <-sink.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type failingStatusSink struct{}

func (failingStatusSink) Emit(context.Context, contractv1.GatewayStatusSignal) error {
	return errors.New("status exporter test failure")
}

type nonCooperativeStatusSink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (sink *nonCooperativeStatusSink) Emit(context.Context, contractv1.GatewayStatusSignal) error {
	sink.calls.Add(1)
	sink.once.Do(func() { close(sink.started) })
	<-sink.release
	return nil
}

func TestStatusExporterBackpressureDoesNotBlockCriticalCaller(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxStatusQueueSignals = 2
	limits.StatusEmitTimeout = 5 * time.Second
	sink := &blockingStatusSink{started: make(chan struct{}), release: make(chan struct{})}
	gateway, err := New(NewSnapshotMetadata(), sink, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(sink.release)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Close(ctx)
	}()

	gateway.emitStatus(context.Background(), testStatusSignal("session_connected"))
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("status worker did not enter blocked sink")
	}

	emitted := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			gateway.emitStatus(context.Background(), testStatusSignal("traffic_delta"))
		}
		close(emitted)
	}()
	select {
	case <-emitted:
	case <-time.After(2 * time.Second):
		t.Fatal("critical caller blocked on telemetry backpressure")
	}
	queued, limit, dropped, failures := gateway.status.snapshot()
	if limit != 2 || queued > limit {
		t.Fatalf("status queue bounds queued=%d limit=%d", queued, limit)
	}
	if dropped == 0 {
		t.Fatal("expected bounded status queue to account dropped signals")
	}
	if failures != 0 {
		t.Fatalf("unexpected status failures while sink is intentionally blocked: %d", failures)
	}
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(recorder.Body.String(), fmt.Sprintf("hooshix_gateway_status_dropped_total %d", dropped)) {
		t.Fatalf("drop accounting not exposed in aggregate metrics: %s", recorder.Body.String())
	}
}

func TestStatusExporterAccountsFailures(t *testing.T) {
	limits := DefaultLimits()
	limits.StatusEmitTimeout = 100 * time.Millisecond
	gateway, err := New(NewSnapshotMetadata(), failingStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.emitStatus(context.Background(), testStatusSignal("traffic_delta"))
	waitFor(t, time.Second, func() bool {
		_, _, _, failures := gateway.status.snapshot()
		return failures == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gateway.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStatusExporterBoundsNonCooperativeSinkAndShutdown(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxStatusQueueSignals = 4
	limits.StatusEmitTimeout = 50 * time.Millisecond
	sink := &nonCooperativeStatusSink{started: make(chan struct{}), release: make(chan struct{})}
	gateway, err := New(NewSnapshotMetadata(), sink, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer close(sink.release)

	gateway.emitStatus(context.Background(), testStatusSignal("session_connected"))
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("non-cooperative sink did not start")
	}
	for i := 0; i < 32; i++ {
		gateway.emitStatus(context.Background(), testStatusSignal("traffic_delta"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := gateway.Close(ctx); err != nil {
		t.Fatalf("Gateway.Close remained blocked by telemetry sink: %v", err)
	}
	if sink.calls.Load() != 1 {
		t.Fatalf("non-cooperative sink calls=%d want=1 bounded call", sink.calls.Load())
	}
	_, _, dropped, failures := gateway.status.snapshot()
	if failures != 1 {
		t.Fatalf("status timeout failures=%d want=1", failures)
	}
	if dropped == 0 {
		t.Fatal("queued telemetry was not accounted as dropped during bounded shutdown")
	}
}

func TestStatusMetricsRemainAggregateLowCardinality(t *testing.T) {
	limits := DefaultLimits()
	gateway, err := New(NewSnapshotMetadata(), failingStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		signal := testStatusSignal("traffic_delta")
		signal.DeviceID = fmt.Sprintf("device-cardinality-%d", i)
		signal.SessionID = fmt.Sprintf("session-cardinality-%d", i)
		signal.EndpointID = fmt.Sprintf("endpoint-cardinality-%d", i)
		gateway.emitStatus(context.Background(), signal)
	}
	waitFor(t, time.Second, func() bool {
		_, _, _, failures := gateway.status.snapshot()
		return failures > 0
	})

	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := recorder.Body.String()
	for _, forbidden := range []string{"device-cardinality-", "session-cardinality-", "endpoint-cardinality-"} {
		if strings.Contains(metrics, forbidden) {
			t.Fatalf("status metrics exposed high-cardinality identifier %q: %s", forbidden, metrics)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gateway.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayWriterPrioritizesControlAndPreservesSingleWriter(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	var mu sync.Mutex
	written := make([]contractv1.Frame, 0, 3)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32

	sess := newGatewayWriterTestSession(func(ctx context.Context, encoded []byte) error {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			maximum := maxActive.Load()
			if current <= maximum || maxActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		frame, err := contractv1.DecodeFrame(encoded)
		if err != nil {
			return err
		}
		mu.Lock()
		written = append(written, frame)
		mu.Unlock()
		if calls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	defer sess.close(1000, "test complete")

	errs := make(chan error, 3)
	go func() { errs <- sess.sendFrame(context.Background(), contractv1.KindData, 1, []byte("data-1")) }()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first data write did not start")
	}
	go func() { errs <- sess.sendFrame(context.Background(), contractv1.KindData, 1, []byte("data-2")) }()
	waitFor(t, time.Second, func() bool { return len(sess.dataWrites) == 1 })
	go func() {
		errs <- sess.sendFrame(context.Background(), contractv1.KindControl, 0, []byte(`{"message_type":"pong"}`))
	}()
	waitFor(t, time.Second, func() bool { return len(sess.controlWrites) == 1 })
	close(releaseFirst)
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if maxActive.Load() != 1 {
		t.Fatalf("WebSocket writer concurrency=%d want=1", maxActive.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(written) != 3 {
		t.Fatalf("written frame count=%d", len(written))
	}
	if written[0].Kind != contractv1.KindData || written[1].Kind != contractv1.KindControl || written[2].Kind != contractv1.KindData {
		t.Fatalf("writer order=%v,%v,%v want data,control,data", written[0].Kind, written[1].Kind, written[2].Kind)
	}
	for i, frame := range written {
		if want := uint64(i + 3); frame.Sequence != want {
			t.Fatalf("sequence[%d]=%d want=%d", i, frame.Sequence, want)
		}
	}
}

func newGatewayWriterTestSession(write func(context.Context, []byte) error) *session {
	gateway := &Gateway{limits: DefaultLimits()}
	sess := &session{
		gateway:       gateway,
		streams:       make(map[uint32]*stream),
		done:          make(chan struct{}),
		controlWrites: make(chan sessionWriteRequest, 32),
		dataWrites:    make(chan sessionWriteRequest, 2),
		writeMessage:  write,
	}
	sess.outbound.Store(2)
	go sess.writeLoop()
	return sess
}

func testStatusSignal(kind string) contractv1.GatewayStatusSignal {
	return contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         "status-r8-test",
		ObservedAt:      time.Now().UTC().Format(time.RFC3339),
		Kind:            kind,
	}
}
