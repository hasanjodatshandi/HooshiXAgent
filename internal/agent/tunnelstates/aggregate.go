package tunnelstates

import "sync"

// Aggregate derives the combined health of several concurrently maintained
// tunnels. It is pure domain logic for the high-availability phase: the
// aggregate is healthy whenever any transport is Connected/Degraded, and
// only Reconnecting/terminal states degrade it.
type Aggregate struct {
	mu       sync.Mutex
	machines []*Machine
}

// NewAggregate returns an aggregate view over zero or more per-transport
// machines.
func NewAggregate(machines ...*Machine) *Aggregate {
	return &Aggregate{machines: append([]*Machine(nil), machines...)}
}

// State returns the best available aggregate state:
//
//   - Connected when any transport is Connected;
//   - Degraded when any transport is Degraded but none Connected;
//   - Reconnecting when every transport is in Reconnecting;
//   - Revoked when all transports are Revoked;
//   - Shutdown when all transports are terminal without any Revoked;
//   - Connecting while any transport is Connecting and none of the above.
func (aggregate *Aggregate) State() State {
	aggregate.mu.Lock()
	defer aggregate.mu.Unlock()

	if len(aggregate.machines) == 0 {
		return Init
	}
	var sawConnecting, sawConnected, sawDegraded, sawReconnecting, sawRevoked bool
	for _, machine := range aggregate.machines {
		switch machine.Current() {
		case Connected:
			sawConnected = true
		case Degraded:
			sawDegraded = true
		case Connecting:
			sawConnecting = true
		case Reconnecting:
			sawReconnecting = true
		case Revoked:
			sawRevoked = true
		case Shutdown, Init:
		}
	}
	switch {
	case sawConnected:
		return Connected
	case sawDegraded:
		return Degraded
	case sawConnecting:
		return Connecting
	case sawReconnecting:
		return Reconnecting
	case sawRevoked:
		return Revoked
	default:
		return Shutdown
	}
}

// Healthy reports whether at least one tunnel is currently serving.
func (aggregate *Aggregate) Healthy() bool {
	switch aggregate.State() {
	case Connected, Degraded:
		return true
	default:
		return false
	}
}

// Observability returns the bounded aggregate descriptor for logs and
// diagnostics. It exposes no identifiers.
func (aggregate *Aggregate) Observability() (state string, terminal bool, healthy bool) {
	stateValue := aggregate.State()
	return stateValue.String(), stateValue.Terminal(), aggregate.Healthy()
}
