package tunnelstates

import "testing"

func TestLegalLifecycleTransitions(t *testing.T) {
	t.Parallel()

	machine := New()
	if machine.Current() != Init {
		t.Fatalf("initial state=%v want init", machine.Current())
	}
	for _, to := range []State{Connecting, Connected, Degraded, Connected, Reconnecting, Connecting, Connected} {
		if err := machine.Transition(to); err != nil {
			t.Fatalf("legal transition to %v rejected: %v", to, err)
		}
	}
	if machine.Current() != Connected {
		t.Fatalf("final state=%v want connected", machine.Current())
	}
}

func TestTerminalStatesStopTransitions(t *testing.T) {
	t.Parallel()

	for _, terminal := range []State{Revoked, Shutdown} {
		machine := New()
		machine.MustTransition(Connecting)
		machine.MustTransition(terminal)
		if !machine.Current().Terminal() {
			t.Fatalf("%v must be terminal", terminal)
		}
		if err := machine.Transition(Connected); err != ErrIllegalTransition {
			t.Fatalf("terminal state accepted transition: err=%v", err)
		}
		if machine.Current() != terminal {
			t.Fatalf("terminal transition changed state to %v", machine.Current())
		}
	}
}

func TestIllegalTransitionsFailClosed(t *testing.T) {
	t.Parallel()

	illegal := []struct {
		path []State
		bad  State
	}{
		{path: []State{Connecting}, bad: Init},
		{path: []State{Connecting, Connected}, bad: Init},
		{path: []State{Connecting}, bad: Degraded},
		{path: []State{Connecting, Reconnecting}, bad: Degraded},
		{path: []State{Connecting, Reconnecting}, bad: Init},
		{path: []State{}, bad: Connected},
		{path: []State{}, bad: Revoked},
		{path: []State{}, bad: Reconnecting},
	}
	for _, test := range illegal {
		machine := New()
		for _, step := range test.path {
			if err := machine.Transition(step); err != nil {
				t.Fatalf("setup transition %v: %v", step, err)
			}
		}
		before := machine.Current()
		if err := machine.Transition(test.bad); err == nil {
			t.Fatalf("illegal transition path=%v to %v accepted", test.path, test.bad)
		}
		if machine.Current() != before {
			t.Fatalf("illegal transition changed state: %v -> %v", before, machine.Current())
		}
	}
}

func TestObservabilityNamesAreStableAndBounded(t *testing.T) {
	t.Parallel()

	states := []State{Init, Connecting, Connected, Degraded, Reconnecting, Revoked, Shutdown}
	seen := make(map[string]bool)
	for _, state := range states {
		name, terminal := (&Machine{state: state}).Observability()
		if name == "" || name == "unknown" || len(name) > 16 {
			t.Fatalf("state %d observability name=%q", state, name)
		}
		if seen[name] {
			t.Fatalf("duplicate observability name %q", name)
		}
		seen[name] = true
		if terminal != (state == Revoked || state == Shutdown) {
			t.Fatalf("state %v terminal flag=%t", state, terminal)
		}
	}
}
