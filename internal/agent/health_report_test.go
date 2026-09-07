package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func quietAgentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestAgentHealthReportContentAndValidation proves the periodic health_report
// control message is contract-valid, carries bounded counters, and remains
// session-scoped telemetry on the shared control writer.
func TestAgentHealthReportContentAndValidation(t *testing.T) {
	sess := &agentSession{
		limits:        DefaultLimits(),
		logger:        quietAgentLogger(),
		streams:       make(map[uint32]*agentStream),
		queueBudget:   newAgentByteBudget(8 << 20),
		closed:        make(chan struct{}),
		controlWrites: make(chan agentWriteRequest, 32),
		dataWrites:    make(chan agentWriteRequest, 2),
	}
	sess.writeMessage = func(context.Context, []byte) error { return nil }
	sess.outbound.Store(2)
	go sess.writeLoop()
	defer sess.shutdown()

	// Register one live stream with one queued frame so counters are non-zero.
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	stream := &agentStream{
		id:            7,
		incoming:      make(chan agentQueuedPayload, 4),
		space:         make(chan struct{}, 1),
		ctx:           streamCtx,
		cancel:        streamCancel,
		streamBudget:  newAgentByteBudget(2 << 20),
		sessionBudget: sess.queueBudget,
	}
	if !stream.enqueue(context.Background(), []byte("queued-frame"), time.Millisecond) {
		t.Fatal("test stream enqueue failed")
	}
	sess.mu.Lock()
	sess.streams[7] = stream
	sess.mu.Unlock()

	sess.observeReconnect()
	sess.observeReconnect()

	// Capture frames through the real single-writer path: writeLoop encodes
	// and calls writeMessage, so we intercept there without racing the
	// control queue.
	written := make(chan []byte, 1)
	sess.writeMessage = func(_ context.Context, encoded []byte) error {
		select {
		case written <- append([]byte(nil), encoded...):
		default:
		}
		return nil
	}

	if err := sess.sendHealthReport(context.Background(), "report-test-001", "v9.9.9-test"); err != nil {
		t.Fatalf("sendHealthReport: %v", err)
	}
	var encoded []byte
	select {
	case encoded = <-written:
	case <-time.After(time.Second):
		t.Fatal("health report did not reach the control writer")
	}
	frame, err := contractv1.DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("decode written frame: %v", err)
	}
	if frame.Kind != contractv1.KindControl || frame.StreamID != 0 {
		t.Fatalf("health report frame kind=%v stream=%d", frame.Kind, frame.StreamID)
	}

	var report contractv1.HealthReport
	if err := json.Unmarshal(frame.Payload, &report); err != nil {
		t.Fatalf("health report payload was not JSON: %v", err)
	}
	if report.MessageType != "health_report" || report.ContractVersion != contractv1.ProtocolVersion {
		t.Fatalf("health report envelope=%+v", report)
	}
	if report.ReportID != "report-test-001" {
		t.Fatalf("health report id=%q", report.ReportID)
	}
	if report.ActiveStreams != 1 {
		t.Fatalf("health report active_streams=%d want 1", report.ActiveStreams)
	}
	if report.QueuedFrames != 1 {
		t.Fatalf("health report queued_frames=%d want 1", report.QueuedFrames)
	}
	if report.ReconnectCount != 2 {
		t.Fatalf("health report reconnect_count=%d want 2", report.ReconnectCount)
	}
	if report.LastReconnectAt == "" {
		t.Fatal("health report missing last_reconnect_at after observed reconnects")
	}
	if report.AgentVersion != "v9.9.9-test" {
		t.Fatalf("health report agent_version=%q", report.AgentVersion)
	}

	// The produced payload must satisfy the strict v1 contract validator.
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := contractv1.ValidateControlPayload(payload, 0, time.Now().UTC()); err != nil {
		t.Fatalf("health report violates contract: %v", err)
	}
}

// TestAgentHealthReportLoopStopsOnClose proves the periodic loop terminates
// when the session closes instead of leaking a goroutine.
func TestAgentHealthReportLoopStopsOnClose(t *testing.T) {
	sess := &agentSession{
		limits:  DefaultLimits(),
		logger:  quietAgentLogger(),
		streams: make(map[uint32]*agentStream),
		closed:  make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		sess.healthReportLoop(context.Background(), 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	sess.shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("health report loop did not stop after session close")
	}
}

// TestAgentHealthReportLoopStopsOnWriterFailure proves a failed report write
// ends the loop instead of spinning on a broken session.
func TestAgentHealthReportLoopStopsOnWriterFailure(t *testing.T) {
	sess := &agentSession{
		limits:        DefaultLimits(),
		logger:        quietAgentLogger(),
		streams:       make(map[uint32]*agentStream),
		closed:        make(chan struct{}),
		controlWrites: make(chan agentWriteRequest, 32),
		dataWrites:    make(chan agentWriteRequest, 2),
	}
	sess.writeMessage = func(context.Context, []byte) error { return nil }
	sess.outbound.Store(2)
	go sess.writeLoop()
	defer sess.shutdown()

	// Close the session writer path first; the loop's report write must fail
	// with errAgentWriterClosed and terminate the loop.
	sess.closeOnce.Do(func() { close(sess.closed) })

	done := make(chan struct{})
	go func() {
		sess.healthReportLoop(context.Background(), 5*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("health report loop survived writer closure")
	}
}
