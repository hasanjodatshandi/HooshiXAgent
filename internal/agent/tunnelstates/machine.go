// Package tunnelstates defines the Edge Agent connection health state
// machine required by the tunnel implementation plan.
//
// It is pure domain logic: no network, filesystem, or OS dependencies, so
// legal/illegal transition behavior is fully unit-testable without sockets.
package tunnelstates

import "errors"

// State is one Agent tunnel connection health state.
type State int

const (
	// Init is the state before any connection attempt has been made.
	Init State = iota
	// Connecting covers dial and authenticated-handshake progress.
	Connecting
	// Connected is a fully authenticated session serving streams.
	Connected
	// Degraded means the session is authenticated but an operational signal
	// (heartbeat deadline miss or repeated failure) suggests instability.
	Degraded
	// Reconnecting follows an ended session while a bounded retry is pending.
	Reconnecting
	// Revoked is a terminal state after an authoritative session_revoked.
	Revoked
	// Shutdown is the terminal state after context cancellation or explicit
	// operator stop.
	Shutdown
)

var stateNames = map[State]string{
	Init:         "init",
	Connecting:   "connecting",
	Connected:    "connected",
	Degraded:     "degraded",
	Reconnecting: "reconnecting",
	Revoked:      "revoked",
	Shutdown:     "shutdown",
}

// String returns the stable lowercase name used by logs and diagnostics.
func (state State) String() string {
	if name, ok := stateNames[state]; ok {
		return name
	}
	return "unknown"
}

// Terminal reports whether the state accepts no further transitions.
func (state State) Terminal() bool {
	switch state {
	case Revoked, Shutdown:
		return true
	default:
		return false
	}
}

// ErrIllegalTransition is returned when a transition is not permitted.
var ErrIllegalTransition = errors.New("illegal tunnel state transition")

// legalTransitions is the authoritative transition table.
var legalTransitions = map[State][]State{
	Init:         {Connecting, Shutdown},
	Connecting:   {Connected, Reconnecting, Revoked, Shutdown},
	Connected:    {Degraded, Reconnecting, Revoked, Shutdown},
	Degraded:     {Connected, Reconnecting, Revoked, Shutdown},
	Reconnecting: {Connecting, Connected, Revoked, Shutdown},
	Revoked:      {},
	Shutdown:     {},
}

func canTransition(from, to State) bool {
	for _, candidate := range legalTransitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// Machine is the connection health state machine for one Agent tunnel
// lifecycle (per transport) or for the aggregate multi-tunnel view. It is
// not the stream/session protocol state; it is the operational health view
// required by the reliability and high-availability phases of the tunnel
// implementation plan.
type Machine struct {
	state State
}

// New returns a machine in the Init state.
func New() *Machine {
	return &Machine{state: Init}
}

// Current returns the current state.
func (machine *Machine) Current() State {
	return machine.state
}

// Transition applies a state change. Re-entering the current state is an
// idempotent success so composite views can re-assert an unchanged health
// level. All other illegal transitions return ErrIllegalTransition and leave
// the machine unchanged, mirroring the fail-closed policy used across the
// runtime.
func (machine *Machine) Transition(to State) error {
	if machine.state.Terminal() {
		return ErrIllegalTransition
	}
	if machine.state == to {
		return nil
	}
	if !canTransition(machine.state, to) {
		return ErrIllegalTransition
	}
	machine.state = to
	return nil
}

// MustTransition is the test-only helper that panics on illegal transitions.
// Production code must use Transition and handle the error.
func (machine *Machine) MustTransition(to State) {
	if err := machine.Transition(to); err != nil {
		panic(err)
	}
}

// Observability returns a short bounded status descriptor suitable for
// structured logs or health reporting. It exposes no identifiers.
func (machine *Machine) Observability() (state string, terminal bool) {
	return machine.state.String(), machine.state.Terminal()
}
