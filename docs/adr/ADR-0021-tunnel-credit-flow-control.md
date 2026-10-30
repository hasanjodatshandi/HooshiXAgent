# ADR-0021: Credit-based flow control for tunnel streams (protocol v2)

Status: Accepted
Date: 2026-10-29
Implementation status: not yet shipped. v1 remains the wire protocol until the
v2 rollout completes; the increments below are tracked as separate changes.

## Context

ADR-0005/ADR-0007 multiplex many streams over one tunnel and bound memory with
per-stream and per-session byte budgets plus bounded queues. That keeps the
receiver safe but gives the sender no pacing signal: when the Agent's local
consumer is slow and a stream queue reaches its budget, `handleData` answers
`resource_limit` and closes the stream (`internal/agent/session.go:402-433`).
The Gateway is never told to slow down, so large uploads and interactive
sessions to a slow local target are reset instead of throttled. Queue slots are
deliberately sized so the byte budget, not the slot count, binds
(`internal/agent/resources.go:50-60`), which makes the abort threshold
predictable but does not remove it. The E2E
`TestAgentGatewayLargeRequestStreaming` timeout on 2026-10-28 (green on rerun)
is consistent with this failure mode, though not proof of it.

## Decision

- Negotiate a second tunnel subprotocol, `hooshix-tunnel.v2`, in the existing
  client_hello/session_ready exchange. Peers that do not advertise v2 keep v1
  behavior unchanged; mixed deployments interoperate.
- Add one control message, `stream_window_update`, carrying `stream_id`
  (uint32) and `credit_bytes` (uint32). Credits are additive and capped by the
  configured stream window.
- A stream starts with an initial credit equal to its configured window, which
  must not exceed `MaxStreamQueueBytes`. The sender MUST NOT keep more than the
  granted credit of payload bytes in flight on that stream.
- The receiver returns credit only after a payload leaves its queue for the
  local target (write completed) or is discarded when the stream finishes.
  Releases are idempotent. Over-release, credit above the window or credit for
  an unknown/closed stream is a `protocol_error` that closes only that stream.
- Credit paces the sender; the existing byte and frame budgets remain the hard
  memory bound. A zero-credit stream pauses its sender without blocking other
  streams, heartbeats or control traffic.
- Window updates are coalesced (at least 25% of the window or 100 ms) and sent
  on the ordered control writer.
- Resume/reconnect creates a new session: every window resets to the initial
  credit and no credit is transferred across sessions.
- A stream that holds zero credit and makes no progress for `IdleTimeout` is
  closed through the existing resource-limit path.

## Alternatives

- Raise the byte budgets: defers the reset, raises per-stream memory, and still
  fails by abort rather than pacing. Rejected.
- Block the Agent reader when one queue is full: one slow stream would stall
  every stream and the heartbeat on the session. Rejected.
- Userspace adaptive pacing without protocol support: more complexity with no
  end-to-end guarantee. Rejected.

## Consequences

Slow consumers throttle their own producers; throughput converges to the
slowest hop while memory bounds stay unchanged. Each stream gains a small
credit state machine and periodic control frames. RDP and large uploads become
reliable under backpressure. v1 remains available until the v2 rollout is
complete; nothing in the Panel, metadata projection or contract v1 changes.

## Security impact

Credit accounting is bounded and validated. Overflow, over-release and
cross-stream credit are protocol errors scoped to one stream. No new trust
boundary and no new credential are introduced.

## Reliability/performance impact

Removes reset-on-backpressure for progressing transfers at the cost of extra
control traffic and per-stream state. Coalescing keeps overhead below one frame
per 100 ms per active stream. Zero-window waits and `resource_limit` closures
must be exported as metrics during rollout.

## Compatibility/migration impact

Subprotocol negotiation only; Agents and Gateways upgrade independently and a
v2 peer paired with a v1 peer stays on v1. No durable state, database or
metadata changes.

## Verification / fitness functions

- Contract tests for window arithmetic: initialization, additive updates, zero
  window, over-release, overflow and update coalescing.
- E2E with an intentionally slow local consumer: an upload pauses at zero
  credit and resumes without a reset; the 7 MiB large-request test completes;
  an RDP soak stays connected.
- Negotiation tests for v2↔v2, v1↔v2 and v2↔v1; resume resets windows.
- Race and fuzz tests for the control payload and stream shutdown at zero
  credit (no goroutine leaks).

## Rollback/supersession

Rebuild Agent and Gateway without advertising v2 and both sides fall back to v1
immediately; no data migration is required. A later protocol revision that
supersedes this decision needs its own ADR.

Related ADRs: ADR-0005, ADR-0007, ADR-0008, ADR-0013, ADR-0015.
