package tunnelstates

import "testing"

func TestAggregatePrefersBestAvailableState(t *testing.T) {
	t.Parallel()

	connected := New()
	connected.MustTransition(Connecting)
	connected.MustTransition(Connected)

	reconnecting := New()
	reconnecting.MustTransition(Connecting)
	reconnecting.MustTransition(Reconnecting)

	aggregate := NewAggregate(connected, reconnecting)
	if aggregate.State() != Connected {
		t.Fatalf("aggregate=%v want connected when any tunnel is connected", aggregate.State())
	}
	if !aggregate.Healthy() {
		t.Fatal("aggregate must be healthy with one connected tunnel")
	}
}

func TestAggregateDegradedWithoutConnected(t *testing.T) {
	t.Parallel()

	degraded := New()
	degraded.MustTransition(Connecting)
	degraded.MustTransition(Connected)
	degraded.MustTransition(Degraded)

	reconnecting := New()
	reconnecting.MustTransition(Connecting)
	reconnecting.MustTransition(Reconnecting)

	aggregate := NewAggregate(degraded, reconnecting)
	if aggregate.State() != Degraded {
		t.Fatalf("aggregate=%v want degraded", aggregate.State())
	}
	if !aggregate.Healthy() {
		t.Fatal("degraded aggregate is still serving and must be healthy")
	}
}

func TestAggregateReconnectingWhenAllRetrying(t *testing.T) {
	t.Parallel()

	one := New()
	one.MustTransition(Connecting)
	one.MustTransition(Reconnecting)

	two := New()
	two.MustTransition(Connecting)
	two.MustTransition(Reconnecting)

	aggregate := NewAggregate(one, two)
	if aggregate.State() != Reconnecting {
		t.Fatalf("aggregate=%v want reconnecting", aggregate.State())
	}
	if aggregate.Healthy() {
		t.Fatal("all-reconnecting aggregate must not be healthy")
	}
}

func TestAggregateTerminalViews(t *testing.T) {
	t.Parallel()

	revoked := New()
	revoked.MustTransition(Connecting)
	revoked.MustTransition(Revoked)

	shutdown := New()
	shutdown.MustTransition(Shutdown)

	if aggregate := NewAggregate(revoked); aggregate.State() != Revoked {
		t.Fatalf("single revoked aggregate=%v", aggregate.State())
	}
	if aggregate := NewAggregate(shutdown); aggregate.State() != Shutdown {
		t.Fatalf("single shutdown aggregate=%v", aggregate.State())
	}
	if aggregate := NewAggregate(revoked, shutdown); aggregate.State() != Revoked {
		t.Fatalf("mixed terminal aggregate=%v want revoked to win", aggregate.State())
	}
}

func TestAggregateEmptyIsInit(t *testing.T) {
	t.Parallel()

	aggregate := NewAggregate()
	if aggregate.State() != Init {
		t.Fatalf("empty aggregate=%v want init", aggregate.State())
	}
}

func TestSelfTransitionIsIdempotent(t *testing.T) {
	t.Parallel()

	machine := New()
	machine.MustTransition(Connecting)
	machine.MustTransition(Connected)
	for i := 0; i < 3; i++ {
		if err := machine.Transition(Connected); err != nil {
			t.Fatalf("idempotent self-transition rejected: %v", err)
		}
	}
	if machine.Current() != Connected {
		t.Fatalf("self-transition changed state: %v", machine.Current())
	}
	// Terminal self-transitions are still illegal.
	terminal := New()
	terminal.MustTransition(Shutdown)
	if err := terminal.Transition(Shutdown); err == nil {
		t.Fatal("terminal state accepted a self-transition")
	}
}
