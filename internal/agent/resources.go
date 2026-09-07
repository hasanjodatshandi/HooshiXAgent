package agent

import "github.com/hasanjodatshandi/HooshiXAgent/internal/agent/agentbudget"

// agentByteBudget aliases the pure-domain bounded byte budget so existing
// Agent session/stream code keeps its names while the policy lives in the
// ADR-0013 domain layer.
type agentByteBudget = agentbudget.ByteBudget

func newAgentByteBudget(limit int64) *agentByteBudget {
	return agentbudget.New(limit)
}

type agentQueuedPayload = agentbudget.QueuedPayload
