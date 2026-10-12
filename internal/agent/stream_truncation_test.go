package agent

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestStreamSendFailureIsReportedAsTruncated pins the terminal frame a stream
// must emit when the tunnel write fails while the local target still has bytes:
// a stream_error, never stream_close "completed". Reporting "completed" for a
// truncated response lets the Gateway serve a short body as a complete one.
// serveUDPStream already recorded the send error; this test holds the TCP and
// HTTP-relay paths to the same rule.
func TestStreamSendFailureIsReportedAsTruncated(t *testing.T) {
	for _, mode := range []string{"", "tcp"} {
		t.Run("mode="+ifEmpty(mode, "http-relay"), func(t *testing.T) {
			target := startPartialWriteTarget(t)
			sess, stream, controls := truncationHarness(t, target, mode)
			go sess.serveStream(stream)

			got := awaitTerminalFrame(t, controls)
			if got.MessageType != "stream_error" {
				t.Fatalf("truncated stream reported %q (%+v); want stream_error", got.MessageType, got)
			}
			if got.Code != "internal_error" {
				t.Fatalf("truncation code %q; want internal_error, a contract enum value", got.Code)
			}
			if got.Retryable {
				t.Error("a partially delivered body must not be marked retryable")
			}
			select {
			case extra := <-controls:
				t.Fatalf("stream emitted a second terminal frame after the error: %+v", extra)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}

type terminalFrame struct {
	MessageType string `json:"message_type"`
	Code        string `json:"code"`
	ReasonCode  string `json:"reason_code"`
	Retryable   bool   `json:"retryable"`
}

func ifEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// startPartialWriteTarget accepts one connection and writes a chunk without
// ever closing it, so the relay fails on its outbound tunnel write rather than
// on a local end of file.
func startPartialWriteTarget(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("partial-response"))
		time.Sleep(5 * time.Second)
	}()
	return listener.Addr().String()
}

// truncationHarness builds a session whose data queue is never drained, so a
// mid-response tunnel write times out while the session and its control queue
// stay healthy. That is the realistic truncation: the relay must report the
// short response instead of claiming completion.
func truncationHarness(t *testing.T, target, mode string) (*agentSession, *agentStream, chan terminalFrame) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	limits := DefaultLimits()
	limits.IdleTimeout = 2 * time.Second
	limits.WriteTimeout = 200 * time.Millisecond
	controls := make(chan terminalFrame, 4)
	sess := &agentSession{
		limits: limits, logger: quietAgentLogger(), streams: make(map[uint32]*agentStream),
		closed: make(chan struct{}), controlWrites: make(chan agentWriteRequest, 8), dataWrites: make(chan agentWriteRequest, 1),
	}
	// Control traffic is served, data traffic is not: a stalled tunnel write
	// must not be confused with a dead session.
	go func() {
		for request := range sess.controlWrites {
			var message terminalFrame
			err := json.Unmarshal(request.payload, &message)
			if err == nil {
				controls <- message
			}
			request.result <- err
		}
	}()
	t.Cleanup(sess.shutdown)
	stream := &agentStream{
		id: 3, endpoint: Endpoint{ID: "ep-1", Target: target, Protocol: "tcp"}, mode: mode,
		incoming: make(chan agentQueuedPayload, 4), space: make(chan struct{}, 1), peerHalfClose: make(chan struct{}),
		ctx: ctx, cancel: cancel, streamBudget: newAgentByteBudget(4096), sessionBudget: newAgentByteBudget(4096),
		logger: quietAgentLogger(),
	}
	sess.streams[stream.id] = stream
	return sess, stream, controls
}

func awaitTerminalFrame(t *testing.T, controls chan terminalFrame) terminalFrame {
	t.Helper()
	select {
	case frame := <-controls:
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never emitted a terminal frame")
	}
	return terminalFrame{}
}
