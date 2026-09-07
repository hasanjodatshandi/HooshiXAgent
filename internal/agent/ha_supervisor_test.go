package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunSpawnsPinnedWorkersForAliases proves the Phase-3 HA supervisor: a
// configuration with a primary plus alias gateways runs one pinned worker per
// candidate (bounded by MaxTunnels), and both the primary failover worker and
// the pinned standby worker run their own bounded loops.
func TestRunSpawnsPinnedWorkersForAliases(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	dir := t.TempDir()
	config := DefaultConfig()
	config.GatewayURL = "wss://primary.example/agent/v1/connect"
	config.GatewayAliases = []string{"wss://secondary.example/agent/v1/connect"}
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(dir, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	primaryAttempts := atomic.Int32{}
	standbyAttempts := atomic.Int32{}
	runner.attempt = func(context.Context) error {
		primaryAttempts.Add(1)
		return errors.New("synthetic primary outage")
	}
	runner.pinnedAttempt = func(ctx context.Context, index int) error {
		standbyAttempts.Add(1)
		if index == 1 {
			<-ctx.Done()
			return nil
		}
		return errors.New("synthetic pinned outage")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("supervisor returned %v", err)
	}

	if primaryAttempts.Load() == 0 {
		t.Fatal("primary worker never ran")
	}
	if standbyAttempts.Load() == 0 {
		t.Fatal("standby worker never ran")
	}
}

// TestRunSingleWorkerWithoutAliases proves the single-tunnel path is used
// when only the primary gateway is configured.
func TestRunSingleWorkerWithoutAliases(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	dir := t.TempDir()
	config := DefaultConfig()
	config.GatewayURL = "wss://primary.example/agent/v1/connect"
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(dir, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	pinnedCalls := atomic.Int32{}
	runner.pinnedAttempt = func(context.Context, int) error {
		pinnedCalls.Add(1)
		return errors.New("unexpected pinned call")
	}

	attempts := atomic.Int32{}
	runner.attempt = func(context.Context) error {
		attempts.Add(1)
		return errors.New("synthetic outage")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = runner.Run(ctx)

	if attempts.Load() == 0 {
		t.Fatal("single-tunnel worker never ran")
	}
	if pinnedCalls.Load() != 0 {
		t.Fatal("pinned worker spawned without alias candidates")
	}
}

// TestSupervisorStopsOnTerminalWorkerError proves a terminal failure from any
// worker (revocation or permanent failure) stops the whole supervisor.
func TestSupervisorStopsOnTerminalWorkerError(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	dir := t.TempDir()
	config := DefaultConfig()
	config.GatewayURL = "wss://primary.example/agent/v1/connect"
	config.GatewayAliases = []string{"wss://secondary.example/agent/v1/connect"}
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(dir, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	runner.attempt = func(ctx context.Context) error {
		<-ctx.Done() // park the primary worker until the supervisor stops
		return nil
	}
	runner.pinnedAttempt = func(context.Context, int) error {
		return ErrSessionRevoked
	}

	result := make(chan error, 1)
	go func() { result <- runner.Run(context.Background()) }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("supervisor error=%v want ErrSessionRevoked", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not stop on the worker's terminal error")
	}
}

// TestRunPinnedAttemptBoundsIndices proves out-of-range worker indices fail
// closed as permanent errors instead of panicking or dialing the primary.
func TestRunPinnedAttemptBoundsIndices(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	dir := t.TempDir()
	config := DefaultConfig()
	config.GatewayURL = "wss://primary.example/agent/v1/connect"
	config.GatewayAliases = []string{"wss://secondary.example/agent/v1/connect"}
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(dir, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = runner.runPinnedAttempt(ctx, 2)
	if err == nil || !errors.Is(err, ErrPermanentAgentFailure) {
		t.Fatalf("out-of-range pinned worker error=%v want permanent failure", err)
	}
}

// TestSupervisorBoundsWorkersByMaxTunnels proves the worker count is bounded
// by MaxTunnels even when more alias candidates are configured.
func TestSupervisorBoundsWorkersByMaxTunnels(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTunnels = 2
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	dir := t.TempDir()
	config := DefaultConfig()
	config.GatewayURL = "wss://primary.example/agent/v1/connect"
	config.GatewayAliases = []string{
		"wss://second.example/agent/v1/connect",
		"wss://third.example/agent/v1/connect",
		"wss://fourth.example/agent/v1/connect",
	}
	if err := SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(dir, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.Map
	primaryRan := atomic.Bool{}
	runner.attempt = func(context.Context) error {
		primaryRan.Store(true)
		return errors.New("synthetic outage")
	}
	runner.pinnedAttempt = func(ctx context.Context, index int) error {
		workers.Store(index, struct{}{})
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = runner.Run(ctx)

	workerCount := 0
	workers.Range(func(any, any) bool {
		workerCount++
		return true
	})
	// Worker 0 is the primary failover worker; pinned workers are 1..MaxTunnels-1.
	if workerCount > limits.MaxTunnels-1 {
		t.Fatalf("pinned worker count=%d exceeds MaxTunnels-1=%d", workerCount, limits.MaxTunnels-1)
	}
	if !primaryRan.Load() {
		t.Fatal("primary worker missing under the bounded schedule")
	}
}
