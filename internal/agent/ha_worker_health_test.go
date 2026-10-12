package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/tunnelstates"
)

// TestPinnedWorkerExitLeavesNoLiveHealthCredit pins the lifecycle rule that
// makes the HA aggregate's Attach-without-Detach design safe: whichever way a
// pinned worker returns, its health machine ends in a terminal state. A dead
// worker left in Connecting, Degraded or Reconnecting would keep being
// credited as live tunnel capacity by Aggregate.State, and a lost Revoked state
// would hide a device-wide revocation.
func TestPinnedWorkerExitLeavesNoLiveHealthCredit(t *testing.T) {
	// The aggregate also holds the primary machine, which never dialled in these
	// tests, so a Shutdown standby is deliberately shadowed by Init: Aggregate
	// keeps "not dialled yet" distinct from "stopped" (a fresh Runner must not
	// publish a terminal snapshot to the tray). A Revoked standby, in contrast,
	// always wins, which is what keeps a device-wide revocation visible.
	cases := []struct {
		name     string
		wantEnd  tunnelstates.State
		wantName string
	}{
		{name: "cancelled-before-start", wantEnd: tunnelstates.Shutdown, wantName: "init"},
		{name: "revoked", wantEnd: tunnelstates.Revoked, wantName: "revoked"},
		{name: "permanent", wantEnd: tunnelstates.Shutdown, wantName: "init"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, err := NewRunner(t.TempDir(), DefaultLimits(), quietAgentLogger())
			if err != nil {
				t.Fatal(err)
			}
			health := tunnelstates.New()
			runner.aggregate.Attach(health)
			switch tc.name {
			case "cancelled-before-start":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := runner.runPinnedWorker(ctx, 1, health); err != nil {
					t.Fatalf("cancelled worker returned %v", err)
				}
			case "revoked":
				runner.pinnedAttempt = func(context.Context, int, *tunnelstates.Machine) error { return ErrSessionRevoked }
				if err := runner.runPinnedWorker(context.Background(), 1, health); !errors.Is(err, ErrSessionRevoked) {
					t.Fatalf("worker error %v, want revocation to surface", err)
				}
			case "permanent":
				runner.pinnedAttempt = func(context.Context, int, *tunnelstates.Machine) error { return ErrPermanentAgentFailure }
				if err := runner.runPinnedWorker(context.Background(), 1, health); !errors.Is(err, ErrPermanentAgentFailure) {
					t.Fatalf("worker error %v, want permanent failure to surface", err)
				}
			}
			if current := health.Current(); !current.Terminal() {
				t.Fatalf("worker ended with machine in %q: a dead worker must not stay live in the aggregate", current)
			} else if current != tc.wantEnd {
				t.Fatalf("machine ended in %q, want %q", current, tc.wantEnd)
			}
			if state, _, healthy := runner.aggregate.Observability(); healthy {
				t.Fatalf("aggregate reports a dead worker as healthy (state=%q)", state)
			} else if state != tc.wantName {
				t.Fatalf("aggregate state=%q, want %q", state, tc.wantName)
			}
		})
	}
}

// TestPinnedWorkerBackoffExitAlsoTerminates covers the fourth exit path: an
// ordinary session error parks the worker in Reconnecting, and cancellation
// during that wait must still leave a terminal machine behind.
func TestPinnedWorkerBackoffExitAlsoTerminates(t *testing.T) {
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), quietAgentLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.limits.ReconnectMin = 5 * time.Second
	runner.limits.ReconnectMax = 5 * time.Second
	health := tunnelstates.New()
	runner.aggregate.Attach(health)
	// Signalled from the worker goroutine, read by the test: a shared counter
	// here would be a data race, and the race detector would rightly fail it.
	attempted := make(chan struct{}, 1)
	runner.pinnedAttempt = func(context.Context, int, *tunnelstates.Machine) error {
		select {
		case attempted <- struct{}{}:
		default:
		}
		return errors.New("tunnel session ended")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.runPinnedWorker(ctx, 1, health) }()
	select {
	case <-attempted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker never attempted a session")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled worker returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not leave its backoff wait")
	}
	if current := health.Current(); !current.Terminal() {
		t.Fatalf("worker ended in the non-terminal state %q", current)
	}
	if state, _, healthy := runner.aggregate.Observability(); healthy || state != "init" {
		// "init", not "shutdown": the never-dialled primary still shadows the
		// ended standby, but the standby is no longer credited as live capacity.
		t.Fatalf("aggregate after a cancelled worker: state=%q healthy=%v", state, healthy)
	}
}
