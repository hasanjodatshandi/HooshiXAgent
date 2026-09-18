package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestGracefulShutdownDrainsTunnelsAfterInflightRequestConsumesHTTPWindow
// proves a slow in-flight public request cannot turn a correct drain into a
// process failure. http.Server.Shutdown spends the whole bounded window waiting
// for in-flight requests, while the Gateway's tunnel drain only starts after it
// returns and is what fails the active streams (which is also what releases
// those in-flight ingress requests). Sharing one window means the tunnel drain
// is handed an already-expired context, reports "gateway drain incomplete:
// context deadline exceeded" and exits 1 even though every stream and port was
// released — supervisors with restart-on-failure then treat a correct drain as
// a crash.
func TestGracefulShutdownDrainsTunnelsAfterInflightRequestConsumesHTTPWindow(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var startOnce sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		startOnce.Do(func() { close(requestStarted) })
		<-releaseRequest
		w.WriteHeader(http.StatusOK)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()

	go func() {
		response, err := http.Get("http://" + listener.Addr().String() + "/inflight")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}()
	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight public request never reached the handler")
	}

	const timeout = 250 * time.Millisecond
	var drainWindowErr error
	var drainDeadline time.Time
	drainTunnels := func(ctx context.Context) error {
		// The real Gateway fails every active stream here, which is what
		// unblocks the in-flight ingress request above.
		drainWindowErr = ctx.Err()
		drainDeadline, _ = ctx.Deadline()
		close(releaseRequest)
		time.Sleep(20 * time.Millisecond)
		return ctx.Err()
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	result := gracefulShutdown(server, nil, drainTunnels, timeout, logger)

	if drainWindowErr != nil {
		t.Fatalf("tunnel drain was handed a context that was already %v (lifetime of the shared shutdown window): the drain must run in its own bounded window", drainWindowErr)
	}
	if drainDeadline.IsZero() {
		t.Fatal("tunnel drain received an unbounded context")
	}
	if remaining := time.Until(drainDeadline); remaining <= 0 || remaining > timeout {
		t.Fatalf("tunnel drain window remaining=%s want a fresh bounded window of at most %s", remaining, timeout)
	}
	if result != nil {
		t.Fatalf("graceful shutdown with one in-flight public request returned %v want nil (exit 0)", result)
	}
	// Documented drain behaviour (O2): the listener is closed before the drain
	// finishes, so a request arriving on a brand-new connection is never
	// answered at all — the client observes a refused connection, not a 503.
	// Only a request reusing an already-established keep-alive connection can
	// be answered with 503 by the handler.
	if connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		connection.Close()
		t.Fatal("listener still accepted a new connection after shutdown")
	}
}

// TestGracefulShutdownReportsTunnelDrainFailure proves the tunnel drain window
// is still bounded and that a genuine drain failure keeps its non-zero exit.
func TestGracefulShutdownReportsTunnelDrainFailure(t *testing.T) {
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()

	blocked := make(chan struct{})
	defer close(blocked)
	const timeout = 100 * time.Millisecond
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	result := gracefulShutdown(server, nil, func(ctx context.Context) error {
		select {
		case <-blocked:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, timeout, logger)
	if result == nil {
		t.Fatal("a tunnel drain that never completes was reported as a successful exit")
	}
	if !errors.Is(result, context.DeadlineExceeded) {
		t.Fatalf("tunnel drain failure %v does not report the bounded window expiry", result)
	}
}

// TestShutdownResultTreatsBoundedShutdownTimeoutAsSuccess proves a bounded
// http.Server.Shutdown timeout is not a process failure when the Gateway's own
// bounded drain completed: Shutdown only ever reports context expiry, and the
// pre-change behaviour exited 1 after a clean drain.
func TestShutdownResultTreatsBoundedShutdownTimeoutAsSuccess(t *testing.T) {
	if err := shutdownResult(context.DeadlineExceeded, nil, nil); err != nil {
		t.Fatalf("completed drain with bounded HTTP shutdown timeout returned %v want nil", err)
	}
	if err := shutdownResult(context.DeadlineExceeded, context.DeadlineExceeded, nil); err != nil {
		t.Fatalf("ops shutdown timeout returned %v want nil", err)
	}
	if err := shutdownResult(nil, nil, nil); err != nil {
		t.Fatalf("clean shutdown returned %v", err)
	}
}

// TestShutdownResultReportsGatewayDrainFailure proves a failed Gateway drain
// is still reported, so a real drain failure cannot be silently downgraded to
// a successful exit.
func TestShutdownResultReportsGatewayDrainFailure(t *testing.T) {
	drainErr := context.DeadlineExceeded
	err := shutdownResult(nil, nil, drainErr)
	if err == nil {
		t.Fatal("gateway drain failure was reported as success")
	}
	if !errors.Is(err, drainErr) {
		t.Fatalf("drain failure %v does not wrap the drain error", err)
	}
}

// TestGatewayLogLevelMapping keeps the documented -log-level values stable.
func TestGatewayLogLevelMapping(t *testing.T) {
	if got := gatewayLogLevel("debug"); got.String() != "DEBUG" {
		t.Fatalf("debug level=%s", got)
	}
	if got := gatewayLogLevel("info"); got.String() != "INFO" {
		t.Fatalf("info level=%s", got)
	}
	if got := gatewayLogLevel("anything-else"); got.String() != "INFO" {
		t.Fatalf("unknown level=%s want INFO", got)
	}
}
